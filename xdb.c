/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

#include "xdb.h"
#include "ctypes.h"
#include "kv.h"
#include "wh.h"
#include "sst.h"
#include "blkio.h"

// defs {{{
#define XDB_COMP_CONC ((4)) // maximum compaction threads
#define XDB_REJECT_SIZE_SHIFT ((3)) // reject up to 12.5%
#define WAL_BLKSZ ((PGSZ << 6)) // 256KB
// }}} defs

// struct {{{
struct mt_pair {
  union {
    void * wmt;
    struct wormhole * wmt_wh;
  };
  union {
    void * imt;
    struct wormhole * imt_wh;
  };
  struct mt_pair * next; // next version
};

struct wal {
  int fd;
  struct wring * wring;
  u8 * buf; // wring_acquire()-ed
  u64 bufoff; // in bytes <= bufsz
  u64 headblk; // 1,2,3...
  u64 nblks; // file size
  u64 write_user;
  u64 write_nblks;
};

// map
struct xdb {
  // 1st line
  struct mt_pair * volatile version;
  u64 padding1[7];

  struct qsbr * qsbr;
  u64 mtsz; // memtable size
  u64 max_mtsz;
  struct msstz * z;
  u64 max_rejsz;
  u32 nr_workers;
  u32 co_per_worker;
  volatile bool running;
  pthread_t comp_pid;
  struct wal wal;

  void * mt1;
  void * mt2;
  struct mt_pair mt_views[4];
  u64 padding2[7];
  mutex lock;
};

struct xdb_ref {
  struct xdb * xdb;
  struct msstv * v;
  struct msstv_ref * vref;

  union {
    void * imt_ref;
    struct wormhole * imt_ref_raw;
  };
  union {
    void * wmt_ref;
    struct wormref * wmt_ref_wh;
  };
  union {
    struct mt_pair * version;
    struct qsbr_ref qref;
  };
};

struct xdb_iter {
  struct xdb_ref * db_ref;
  struct mt_pair * version; // the version used to create the miter
  struct miter * miter;
};

struct xdb_mt_merge_ctx {
  struct kv * new_kv;
  struct xdb * xdb;
  struct mt_pair * version;
  bool success;
};
// }}} struct

// misc {{{
static const struct kvmap_api * wmt_api = &kvmap_api_wormhole;
static const struct kvmap_api * imt_api = &kvmap_api_whunsafe;

  static inline void
xdb_lock(struct xdb * const xdb)
{
  mutex_lock(&xdb->lock);
}

  static inline void
xdb_unlock(struct xdb * const xdb)
{
  mutex_unlock(&xdb->lock);
}
// }}} misc

// wal {{{
// call with lock, see below
  static void
wal_flush_buf(struct wal * const wal)
{
  wring_write(wal->wring, wal->headblk * WAL_BLKSZ, wal->buf);
  wal->buf = wring_acquire(wal->wring);
  debug_assert(wal->buf);
  wal->bufoff = 0;
  wal->headblk++;
  wal->write_nblks++;

  // fsync is not necessary when using direct-io + io_uring
#if 0
#define XDB_SYNC_SIZE ((1lu<<25)) // 32MB
#define XDB_SYNC_NBLKS_MASK (((XDB_SYNC_SIZE / WAL_BLKSZ) - 1))
  if ((wal->headblk & XDB_SYNC_NBLKS_MASK) == 0)
    wring_fsync(wal->wring);
#endif
}

// must call with xdb->lock locked
  static void
wal_append(struct wal * const wal, const struct kv * const kv)
{
  debug_assert(kv);
  const size_t estsz = sst_kv_vi128_estimate(kv);
  if ((estsz + wal->bufoff) > WAL_BLKSZ)
    wal_flush_buf(wal);

  debug_assert(wal->buf);
  sst_kv_vi128_encode(wal->buf + wal->bufoff, kv);
  wal->bufoff += estsz;
  debug_assert(wal->bufoff <= WAL_BLKSZ);
}

  static bool
wal_init(struct wal * const wal, const char * const path, const size_t walsz)
{
  char * const fn = malloc(strlen(path) + 10);
  sprintf(fn, "%s/wal", path);
#if !defined(O_DIRECT)
#define O_DIRECT 0
#endif
  int fd = open(fn, O_RDWR|O_CREAT|O_DIRECT, 00644);
  if (fd < 0)
    fd = open(fn, O_RDWR|O_CREAT, 00644);
  free(fn);
  if (fd < 0)
    return false;

  wal->fd = fd;
  wal->wring = wring_create(fd, WAL_BLKSZ, 32);
  wal->buf = wring_acquire(wal->wring);
  wal->nblks = walsz / WAL_BLKSZ;
  return true;
}

  static void
wal_close(struct wal * const wal)
{
  wring_write(wal->wring, wal->headblk * WAL_BLKSZ, wal->buf);
  wal->buf = NULL;
  wring_destroy(wal->wring);
  fdatasync(wal->fd);
  close(wal->fd);
}
// }}} wal

// kv {{{
// allocate one extra byte for refcnt
  static struct kv *
xdb_new_ts(const struct kref * const kref)
{
  const size_t sz = sizeof(struct kv) + kref->len; // no value
  struct kv * const new = malloc(sz);
  debug_assert(new);
  new->klen = kref->len;
  new->vlen = SST_VLEN_TS;
  memcpy(new->kv, kref->ptr, kref->len);
  new->hash = kv_crc32c_extend(kref->hash32); // why fix this?
  return new;
}

  static struct kv *
xdb_dup_kv(const struct kv * const kv)
{
  const size_t sz = sst_kv_size(kv);
  struct kv * const new = malloc(sz);
  debug_assert(new);
  memcpy(new, kv, sz);
  return new;
}
// }}} kv

// xdb_ref {{{
  static inline void
xdb_ref_enter(struct xdb_ref * const ref)
{
  if (ref->wmt_ref)
    wmt_api->resume(ref->wmt_ref);
}

  static inline void
xdb_ref_leave(struct xdb_ref * const ref)
{
  if (ref->wmt_ref)
    wmt_api->park(ref->wmt_ref);
}

  static void
xdb_unref_all(struct xdb_ref * const ref)
{
  if (ref->v) {
    msstv_unref(ref->vref);
    msstz_putv(ref->xdb->z, ref->v);
    ref->v = NULL;
    ref->vref = NULL;
  }

  if (ref->imt_ref) {
    kvmap_unref(imt_api, ref->imt_ref);
    ref->imt_ref = NULL;
  }

  if (ref->wmt_ref) {
    kvmap_unref(wmt_api, ref->wmt_ref);
    ref->wmt_ref = NULL;
  }
  cpu_cfence();
  ref->version = NULL;
  // don't need to clear memory
}

// must already released everything when calling this function
  static void
xdb_ref_all(struct xdb_ref * const ref)
{
  ref->version = ref->xdb->version;
  ref->v = msstz_getv(ref->xdb->z);
  ref->vref = msstv_ref(ref->v);

  ref->wmt_ref = kvmap_ref(wmt_api, ref->version->wmt);
  debug_assert(ref->wmt_ref);

  if (ref->version->imt) {
    ref->imt_ref = kvmap_ref(imt_api, ref->version->imt);
    debug_assert(ref->imt_ref);
  }
  xdb_ref_leave(ref);
}

  static void
xdb_ref_update_version(struct xdb_ref * const ref)
{
  if (ref->xdb->version != ref->version) {
    xdb_unref_all(ref);
    xdb_ref_all(ref);
  }
}

  struct xdb_ref *
xdb_ref(struct xdb * const xdb)
{
  struct xdb_ref * ref = calloc(1, sizeof(*ref));
  ref->xdb = xdb;
  qsbr_register(xdb->qsbr, &ref->qref);
  xdb_ref_all(ref);
  return ref;
}

  struct xdb *
xdb_unref(struct xdb_ref * const ref)
{
  struct xdb * xdb = ref->xdb;
  xdb_unref_all(ref);
  qsbr_unregister(xdb->qsbr, &ref->qref);
  free(ref);
  return xdb;
}
// }}} xdb_ref

// comp {{{
// insert-only; don't overwrite
  static struct kv *
xdb_mt_reinsert_func(struct kv * const kv0, void * const priv)
{
  struct xdb_mt_merge_ctx * const ctx = priv;
  ctx->success = kv0 == NULL;
  return kv0 ? kv0 : ctx->new_kv;
}

// insert rejected keys from imt into wmt; vlen == 1 marks a rejected partition
  static void
xdb_reinsert_rejected(struct xdb * const xdb, void * const wmt_map, void * const imt_map, struct kv ** const anchors)
{
  void * const wmt_ref = kvmap_ref(wmt_api, wmt_map);
  void * const rej_ref = kvmap_ref(imt_api, imt_map);
  void * const rej_iter = imt_api->iter_create(rej_ref);
  struct xdb_mt_merge_ctx ctx = {}; // only use new_kv and success

#define REINSERT_BUF_MAX ((4096))
  struct kv ** const buf = malloc(sizeof(buf[0]) * REINSERT_BUF_MAX);
  u32 bufnr = 0;
  for (u32 i = 0; anchors[i]; i++) {
    if (anchors[i]->vlen == 0) // skip accepted partitions
      continue;
    // find the end of current partition
    if (anchors[i+1]) {
      struct kv * const kz = anchors[i+1];
      struct kref krefz = {.ptr = kz->kv, .len = kz->klen, .hash32 = kv_crc32c(kz->kv, kz->klen)};
      imt_api->iter_seek(rej_iter, &krefz);
    }
    // peek and next does not make any copies; see mm_mt.out
    struct kv * const end = anchors[i+1] ? imt_api->iter_peek(rej_iter, NULL) : NULL;
    struct kv * const k0 = anchors[i];
    struct kref kref0 = {.ptr = k0->kv, .len = k0->klen, .hash32 = kv_crc32c(k0->kv, k0->klen)};
    imt_api->iter_seek(rej_iter, &kref0);
    while (imt_api->iter_valid(rej_iter)) {
      struct kv * const curr = imt_api->iter_next(rej_iter, NULL);
      if (curr == end)
        break;

      ctx.new_kv = xdb_dup_kv(curr);
      if (!ctx.new_kv)
        debug_die();
      bool s = kvmap_kv_merge(wmt_api, wmt_ref, curr, xdb_mt_reinsert_func, &ctx);
      if (!s)
        debug_die();
      if (ctx.success) { // should rewrite in the log
        buf[bufnr] = curr;
        bufnr++;
        // enqueue for batch rewrite
        if (bufnr == REINSERT_BUF_MAX) {
          xdb_lock(xdb);
          for (u32 j = 0; j < REINSERT_BUF_MAX; j++) {
            xdb->mtsz += sst_kv_size(buf[i]);
            wal_append(&xdb->wal, buf[i]);
          }
          xdb_unlock(xdb);
          bufnr = 0;
        }
      }
    }
  }
  // the last batch
  xdb_lock(xdb);
  for (u32 i = 0; i < bufnr; i++) {
    xdb->mtsz += sst_kv_size(buf[i]);
    wal_append(&xdb->wal, buf[i]);
  }
  xdb_unlock(xdb);
  free(buf);

  imt_api->iter_destroy(rej_iter);
  kvmap_unref(imt_api, rej_ref);
  kvmap_unref(wmt_api, wmt_ref);
#undef REINSERT_BUF_MAX
}

  static inline bool
xdb_mt_wal_full(struct xdb * const xdb)
{
  // mt is full OR wal is full
  // when this is true: writers must wait; compaction should start
  return (xdb->mtsz >= xdb->max_mtsz) || (xdb->wal.headblk >= xdb->wal.nblks);
}

// compaction steps:
//   lock(wal)
//       - switch memtable mode from wmt-only to wmt+imt (very quick)
//       - flush and switch the log (TODO: use two independent log files)
//   unlock(wal)
//   - qsbr_wait for users to leave the now imt
//   - save an old version until the new version is ready for access
//   - call msstz_comp
//   - release the data in wal
//   lock(wal)
//       - rewrite rejected keys to the wal (TODO: eliminate locking with a separate rejected log file)
//   unlock(wal)
//   - reinsert rejected keys into wmt; skip those already updated
//   - release the old version (was using its anchors for rejected partitions)
//   - switch to the normal mode (wmt only) because keys in the imt are either in wmt or partitions
//   - qsbr_wait for users to leave the imt
//   - clean the imt (will be used as the new wmt in the next compaction
//   - done
  static void
xdb_do_comp(struct xdb * const xdb, const u64 max_rejsz)
{
  const double t0 = time_sec();
  xdb_lock(xdb);

  // switch version
  struct mt_pair * const v_comp = xdb->version->next;
  xdb->version = v_comp; // wmt => wmt+imt

  // cut the log
  wal_flush_buf(&xdb->wal);
  const u64 mtsz = xdb->mtsz;
  const u64 walsz = xdb->wal.headblk * WAL_BLKSZ;
  xdb->mtsz = 0; // reset mtsz while holding the lock
  xdb->wal.headblk = 0; // TODO: open a new wal file

  xdb_unlock(xdb);

  void * wmt_map = v_comp->wmt;
  void * imt_map = v_comp->imt;
  // unlocked
  qsbr_wait(xdb->qsbr, (u64)v_comp);

  struct msstv * const oldv = msstz_getv(xdb->z); // keep oldv alive
  const double t_prep = time_sec();

  // compaction
  msstz_comp(xdb->z, imt_api, imt_map, xdb->nr_workers, xdb->co_per_worker, max_rejsz);
  const double t_comp = time_sec();

  struct kv ** const anchors = msstv_anchors(oldv);
  xdb_reinsert_rejected(xdb, wmt_map, imt_map, anchors);
  const double t_reinsert = time_sec();

  free(anchors);
  msstz_putv(xdb->z, oldv);
  struct mt_pair * const v_normal = xdb->version->next;
  xdb->version = v_normal;

  // unlocked
  qsbr_wait(xdb->qsbr, (u64)v_normal);
  const double t_wait2 = time_sec();

  imt_api->clean(imt_map);
  const double t_clean = time_sec();

  // print report
  // writes
  const size_t usr_write = xdb->wal.write_user;
  const size_t wal_write = xdb->wal.write_nblks * WAL_BLKSZ;
  const size_t sst_write = msstz_stat_writes(xdb->z);
  const size_t sst_read = msstz_stat_reads(xdb->z);
  // WA, RA
  const double sys_wa = (double)(wal_write + sst_write) / (double)usr_write;
  const double comp_ra = (double)sst_read / (double)usr_write;

  const u64 mb = 1lu<<20;
  msstz_log(xdb->z, "%s mtsz %lu walsz %lu write-mb usr %lu wal %lu sst %lu WA %.4lf comp-read-mb %lu RA %.4lf\n",
       __func__, mtsz, walsz, usr_write/mb, wal_write/mb, sst_write/mb, sys_wa, sst_read/mb, comp_ra);
  msstz_log(xdb->z, "%s times-ms total %.3lf prep %.3lf comp %.3lf reinsert %.3lf wait2 %.3lf clean %.3lf\n",
      __func__, t_clean-t0, t_prep-t0, t_comp-t_prep, t_reinsert-t_comp, t_wait2-t_reinsert, t_clean-t_wait2);
}

  static void *
xdb_compaction_worker(void * const ptr)
{
  struct xdb * xdb = (typeof(xdb))ptr;
  // pin on cpus
  char * env = getenv("XDB_CPU_LIST");
  u32 cpus[XDB_COMP_CONC];
  u32 nr = 0;
  if (env) { // explicit cpu list
    char ** const tokens = string_tokens(env, ",");
    while ((nr < XDB_COMP_CONC) && tokens[nr]) {
      cpus[nr] = a2u32(tokens[nr]);
      nr++;
    }
    free(tokens);
    msstz_log(xdb->z, "%s cpus %s\n", __func__, env);
  } else { // auto detection; use the last a few cpus
    u32 cores[64];
    const u32 ncores = process_getaffinity_list(64, cores);
    nr = (ncores < XDB_COMP_CONC) ? ncores : XDB_COMP_CONC;
    for (u32 i = 0; i < nr; i++)
      cpus[i] = cores[ncores - nr + i];

    if (nr == 0) {
      nr = 1;
      cpus[0] = 0;
    }
    msstz_log(xdb->z, "%s cpus %u first %u (auto)\n", __func__, nr, cpus[0]);
  }
  thread_setaffinity_list(nr, cpus);
  thread_set_name(pthread_self(), "xdb_comp");

  while (true) {
    // while running and does not need compaction
    const u64 t0 = time_nsec();
    // wait until (1) the mt is full or (2) the log file is full
    while (xdb->running && !xdb_mt_wal_full(xdb))
      usleep(10); // 1ms

    if (!xdb->running)
      break;

    const u64 dt = time_diff_nsec(t0);
    msstz_log(xdb->z, "%s compaction worker wait-ms %lu\n", __func__, dt / 1000000);
    xdb_do_comp(xdb, xdb->max_rejsz);
  }
  xdb_do_comp(xdb, 0); // flush log; leave nothing in the memtable; TODO: just save the keys in the log

  pthread_exit(NULL);
}
// }}} comp

// open close {{{
  struct xdb *
xdb_open(const char * const dir, const size_t cache_size_mb, const size_t mt_size_mb, const size_t wal_size_mb,
    const u32 nr_workers, const u32 co_per_worker, const bool ckeys)
{
  mkdir(dir, 0777);
  struct xdb * xdb = yalloc(sizeof(*xdb));
  memset(xdb, 0, sizeof(*xdb));

  const struct kvmap_mm mm_mt = { .in = kvmap_mm_in_noop, .out = kvmap_mm_out_noop, .free = kvmap_mm_free_free};

  xdb->mt1 = wormhole_create(&mm_mt);
  xdb->mt2 = wormhole_create(&mm_mt);

  // normal: one mt
  xdb->mt_views[0] = (struct mt_pair){.wmt = xdb->mt1, .next = &xdb->mt_views[1]};
  xdb->mt_views[1] = (struct mt_pair){.wmt = xdb->mt2, .imt = xdb->mt1, .next = &xdb->mt_views[2]};

  xdb->mt_views[2] = (struct mt_pair){.wmt = xdb->mt2, .next = &xdb->mt_views[3]};
  xdb->mt_views[3] = (struct mt_pair){.wmt = xdb->mt1, .imt = xdb->mt2, .next = &xdb->mt_views[0]};
  xdb->version = xdb->mt_views; // [0]

  xdb->qsbr = qsbr_create();

  // just a warning
  if ((mt_size_mb * 2) > wal_size_mb)
    fprintf(stderr, "%s wal_size < mt_size*2\n", __func__);

  // sz
  xdb->max_mtsz = mt_size_mb << 20;
  xdb->max_rejsz = xdb->max_mtsz >> XDB_REJECT_SIZE_SHIFT;
  wal_init(&xdb->wal, dir, wal_size_mb << 20);

  // z
  struct msstz * z = msstz_open(dir, cache_size_mb, ckeys);
  debug_assert(z);
  xdb->z = z;

  mutex_init(&xdb->lock);
  xdb->nr_workers = nr_workers; // internal parallelism
  xdb->co_per_worker = co_per_worker;
  xdb->running = true;
  pthread_create(&xdb->comp_pid, NULL, xdb_compaction_worker, xdb);
  return xdb;
}

// destroy
  void
xdb_close(struct xdb * xdb)
{
  xdb->running = false;
  pthread_join(xdb->comp_pid, NULL);

  mutex_deinit(&xdb->lock);
  // assume all users have left
  qsbr_destroy(xdb->qsbr);

  msstz_destroy(xdb->z);
  wal_close(&xdb->wal);
  wmt_api->destroy(xdb->mt1);
  wmt_api->destroy(xdb->mt2);
  free(xdb);
}
// }}} open close

// get probe {{{
struct xdb_get_info {
  struct kv * out;
  struct kv * ret;
};

  static void
xdb_inp_get(struct kv * const kv, void * const priv)
{
  // copy when looking at this key
  // to avoid consistency problems after get returns
  struct xdb_get_info * const info = (typeof(info))priv;
  if (kv && kv->vlen != SST_VLEN_TS) {
    info->ret = kvmap_mm_out_ts(kv, info->out);
  } else {
    info->ret = NULL;
  }
}

  struct kv *
xdb_get(struct xdb_ref * const ref, const struct kref * const kref, struct kv * const out)
{
  xdb_ref_update_version(ref);
  xdb_ref_enter(ref);

  // wmt
  struct xdb_get_info info = {out, NULL};
  if (wmt_api->inpr(ref->wmt_ref, kref, &xdb_inp_get, &info)) {
    xdb_ref_leave(ref);
    return info.ret;
  }
  xdb_ref_leave(ref);

  // imt
  if (ref->imt_ref) {
    if (imt_api->inpr(ref->imt_ref, kref, &xdb_inp_get, &info))
      return info.ret;
  }
  // not in log, maybe in ssts
  return msstv_get_ts(ref->vref, kref, out);
}

  static void
xdb_inp_probe(struct kv * const kv, void * const priv)
{
  // copy when looking at this key
  // to avoid consistency problems after get returns
  *(bool *)priv = kv && (kv->vlen != SST_VLEN_TS);
}

  bool
xdb_probe(struct xdb_ref * const ref, const struct kref * const kref)
{
  xdb_ref_update_version(ref);
  xdb_ref_enter(ref);

  bool is_valid;
  if (wmt_api->inpr(ref->wmt_ref, kref, &xdb_inp_probe, &is_valid)) {
    xdb_ref_leave(ref);
    return is_valid;
  }
  xdb_ref_leave(ref);

  if (ref->imt_ref) {
    if (imt_api->inpr(ref->imt_ref, kref, &xdb_inp_probe, &is_valid))
      return is_valid;
  }
  return msstv_probe_ts(ref->vref, kref);
}
// }}} get probe

// set del {{{
// this is so long
  static void
xdb_write_enter(struct xdb_ref * const ref)
{
  struct xdb * xdb = ref->xdb;
  while (xdb_mt_wal_full(xdb)) {
    xdb_ref_update_version(ref);
    usleep(10);
  }
}

// call with lock
  static struct kv *
xdb_mt_update_func(struct kv * const kv0, void * const priv)
{
  struct xdb_mt_merge_ctx * const ctx = priv;
  struct xdb * const xdb = ctx->xdb;
  const size_t newsz = sst_kv_size(ctx->new_kv);
  const size_t oldsz = kv0 ? sst_kv_size(kv0) : 0;
  const size_t diffsz = newsz - oldsz;
  debug_assert(xdb->mtsz >= oldsz);

  xdb_lock(xdb);
  if (xdb->version != ctx->version) {
    // abort
    xdb_unlock(xdb);
    return kv0;
  }

  xdb->mtsz += diffsz;
  xdb->wal.write_user += newsz;
  wal_append(&xdb->wal, ctx->new_kv);

  xdb_unlock(xdb);
  ctx->success = true;
  return ctx->new_kv;
}

  static bool
xdb_update(struct xdb_ref * const ref, const struct kref * const kref, struct kv * const newkv)
{
  debug_assert(kref && newkv);
  xdb_write_enter(ref);

  struct xdb_mt_merge_ctx ctx = {newkv, ref->xdb, NULL, false};
  bool s;
  do {
    xdb_ref_update_version(ref);
    xdb_ref_enter(ref);
    ctx.version = ref->version;
    s = wmt_api->merge(ref->wmt_ref, kref, xdb_mt_update_func, &ctx);
    xdb_ref_leave(ref);
  } while (!ctx.success);
  return s;
}

  bool
xdb_set(struct xdb_ref * const ref, const struct kv * const kv)
{
  struct kv * const new_kv = xdb_dup_kv(kv);
  if (!new_kv)
    return false;

  struct kref kref;
  kref_ref_kv(&kref, kv);
  return xdb_update(ref, &kref, new_kv);
}

  bool
xdb_del(struct xdb_ref * const ref, const struct kref * const kref)
{
  struct kv * const ts_kv = xdb_new_ts(kref);
  if (!ts_kv)
    return false;

  return xdb_update(ref, kref, ts_kv);
}
// }}} set del

// iter {{{
  static void
xdb_iter_miter_ref(struct xdb_iter * const iter)
{
  struct xdb_ref * ref = iter->db_ref;
  struct mt_pair * version = ref->version;
  iter->version = version; // remember version used by miter

  miter_add(iter->miter, &kvmap_api_msstv_ts, ref->v);

  if (version->imt)
    miter_add(iter->miter, imt_api, version->imt);

  miter_add(iter->miter, wmt_api, version->wmt);
}

  static void
xdb_iter_update_version(struct xdb_iter * const iter)
{
  struct xdb_ref * ref = iter->db_ref;
  if (ref->version == ref->xdb->version && iter->version == ref->version)
    return;

  miter_clean(iter->miter);
  xdb_ref_update_version(ref);
  xdb_iter_miter_ref(iter);
  // acquire new
}

  struct xdb_iter *
xdb_iter_create(struct xdb_ref * const ref)
{
  struct xdb_iter * iter = calloc(1, sizeof(*iter));
  iter->miter = miter_create();
  iter->db_ref = ref;

  xdb_ref_update_version(ref);
  xdb_iter_miter_ref(iter);
  xdb_iter_park(iter);
  return iter;
}

  static void
xdb_iter_skip_ts(struct xdb_iter * const iter)
{
  struct kvref kvref;
  do {
    if (miter_kvref(iter->miter, &kvref) == false)
      return;
    if (kvref.hdr.vlen != SST_VLEN_TS)
      break;
    miter_skip_unique(iter->miter);
  } while (true);
}

  void
xdb_iter_park(struct xdb_iter * const iter)
{
  miter_park(iter->miter);
}

  void
xdb_iter_seek(struct xdb_iter * const iter, const struct kref * const key)
{
  xdb_iter_update_version(iter);
  miter_seek(iter->miter, key);
  xdb_iter_skip_ts(iter);
}

  bool
xdb_iter_valid(struct xdb_iter * const iter)
{
  return miter_valid(iter->miter);
}

// assume valid is called before peek
  struct kv *
xdb_iter_peek(struct xdb_iter * const iter, struct kv * const out)
{
  struct kvref kvref;
  if (!miter_kvref(iter->miter, &kvref))
    return NULL;

  // should never see TS here
  debug_assert(kvref.hdr.vlen != SST_VLEN_TS);
  return sst_kvref_dup2_kv(&kvref, out);
}

  bool
xdb_iter_kref(struct xdb_iter * const iter, struct kref * const kref)
{
  return miter_kref(iter->miter, kref);
}

  bool
xdb_iter_kvref(struct xdb_iter * const iter, struct kvref * const kvref)
{
  return miter_kvref(iter->miter, kvref);
}

  void
xdb_iter_skip(struct xdb_iter * const iter, const u32 n)
{
  for (u32 i = 0; i < n; i++) {
    miter_skip_unique(iter->miter);
    xdb_iter_skip_ts(iter);
  }
}

  struct kv *
xdb_iter_next(struct xdb_iter * const iter, struct kv * const out)
{
  struct kv * kv = xdb_iter_peek(iter, out);
  xdb_iter_skip(iter, 1);
  return kv;
}

  void
xdb_iter_destroy(struct xdb_iter * const iter)
{
  miter_destroy(iter->miter);
  free(iter);
}
// }}} iter

// api {{{
const struct kvmap_api kvmap_api_xdb = {
  .ordered = true,
  .threadsafe = true,
  .unique = true,
  .get = (void*)xdb_get,
  .probe = (void*)xdb_probe,
  .set = (void*)xdb_set,
  .del = (void*)xdb_del,
  .ref = (void*)xdb_ref,
  .unref = (void*)xdb_unref,
  .destroy = (void*)xdb_close,

  .iter_create = (void*)xdb_iter_create,
  .iter_seek = (void*)xdb_iter_seek,
  .iter_valid = (void*)xdb_iter_valid,
  .iter_peek = (void*)xdb_iter_peek,
  .iter_kref = (void*)xdb_iter_kref,
  .iter_kvref = (void*)xdb_iter_kvref,
  .iter_skip = (void*)xdb_iter_skip,
  .iter_next = (void*)xdb_iter_next,
  .iter_park = (void*)xdb_iter_park,
  .iter_destroy = (void*)xdb_iter_destroy,
};

  static void *
xdb_kvmap_api_create(const char * const name, const struct kvmap_mm * const mm, char ** const args)
{
  (void)mm;
  if (!strcmp(name, "xdbx")) {
    return xdb_open(args[0], a2u64(args[1]), a2u64(args[2]), a2u64(args[3]), a2u32(args[4]), a2u32(args[5]), args[6][0] != '0');
  } else if (!strcmp(name, "xdb")) {
    return xdb_open(args[0], a2u64(args[1]), 4096, 8192, 4, 1, true); // 4 threads by default
    //return xdb_open(args[0], a2u64(args[1]), 4096, 8192, 4, 4, false); // x4 co-per-thr if not using ckeys
  } else {
    return NULL;
  }
}

__attribute__((constructor))
  static void
xdb_kvmap_api_init(void)
{
  kvmap_api_register(2, "xdb", "<path> <cache-size-mb>", xdb_kvmap_api_create, &kvmap_api_xdb);
  kvmap_api_register(7, "xdbx", "<path> <cache-size-mb> <mt-size-mb> <wal-size-mb> <nr-workers> <co-per-worker> <copy-keys(0/1)>",
      xdb_kvmap_api_create, &kvmap_api_xdb);
}
// }}}

// remixdb {{{
// The default
  struct xdb *
remixdb_open(const char * const dir, const size_t cache_size_mb, const size_t mt_size_mb)
{
  return xdb_open(dir, cache_size_mb, mt_size_mb, mt_size_mb << 1, 4, 1, true);
}

// This mode provides SLIGHTLY lower WA and lower disk usage;
// However, compaction can be slower if your workload exhibit poor write locality
// You should use this mode only when the disk space is REALLY limited
  struct xdb *
remixdb_open_compact(const char * const dir, const size_t cache_size_mb, const size_t mt_size_mb)
{
  return xdb_open(dir, cache_size_mb, mt_size_mb, mt_size_mb << 1, 4, 4, false);
}

  struct xdb_ref *
remixdb_ref(struct xdb * const xdb)
{
  return xdb_ref(xdb);
}

  void
remixdb_unref(struct xdb_ref * const ref)
{
  (void)xdb_unref(ref);
}

  void
remixdb_close(struct xdb * const xdb)
{
  xdb_close(xdb);
}

  bool
remixdb_set(struct xdb_ref * const ref, const void * const kbuf, const u32 klen,
    const void * const vbuf, const u32 vlen)
{
  // TODO: huge kvs should be stored in separate fileswith indirections inserted in xdb
  if ((klen + vlen) > 65500)
    return false;

  struct kv * const new_kv = kv_create(kbuf, klen, vbuf, vlen);
  if (!new_kv)
    return false;

  struct kref kref;
  kref_ref_kv(&kref, new_kv);
  return xdb_update(ref, &kref, new_kv);
}

  bool
remixdb_del(struct xdb_ref * const ref, const void * const kbuf, const u32 klen)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);

  struct kv * const ts_kv = xdb_new_ts(&kref);
  if (!ts_kv)
    return false;

  return xdb_update(ref, &kref, ts_kv);
}

// test if the key exist in Wormhole
  bool
remixdb_probe(struct xdb_ref * const ref, const void * const kbuf, const u32 klen)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);
  return xdb_probe(ref, &kref);
}

struct remixdb_get_info { void * vbuf_out; u32 * vlen_out; };

  static void
remixdb_inp_get(struct kv * kv, void * priv)
{
  // copy when looking at this key
  // to avoid consistency problems after get returns
  if (kv) {
    struct remixdb_get_info * const info = (typeof(info))priv;
    *info->vlen_out = kv->vlen; // copy the raw vlen
    if (kv->vlen != SST_VLEN_TS)
      memcpy(info->vbuf_out, kv_vptr_c(kv), kv->vlen & SST_VLEN_MASK);
  }
}

  bool
remixdb_get(struct xdb_ref * const ref, const void * const kbuf, const u32 klen,
    void * const vbuf_out, u32 * const vlen_out)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);

  xdb_ref_update_version(ref);
  xdb_ref_enter(ref);

  // wmt
  struct remixdb_get_info info = {vbuf_out, vlen_out};
  if (wmt_api->inpr(ref->wmt_ref, &kref, &remixdb_inp_get, &info)) {
    xdb_ref_leave(ref);
    return (*vlen_out) != SST_VLEN_TS;
  }
  xdb_ref_leave(ref);

  // imt
  if (ref->imt_ref) {
    if (imt_api->inpr(ref->imt_ref, &kref, &remixdb_inp_get, &info))
      return (*vlen_out) != SST_VLEN_TS;
  }
  // not in log, maybe in ssts
  return msstv_get_value_ts(ref->vref, &kref, vbuf_out, vlen_out);
}

  struct xdb_iter *
remixdb_iter_create(struct xdb_ref * const ref)
{
  return xdb_iter_create(ref);
}

  void
remixdb_iter_seek(struct xdb_iter * const iter, const void * const kbuf, const u32 klen)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);
  xdb_iter_seek(iter, &kref);
}

  bool
remixdb_iter_valid(struct xdb_iter * const iter)
{
  return xdb_iter_valid(iter);
}

  bool
remixdb_iter_peek(struct xdb_iter * const iter,
    void * const kbuf_out, u32 * const klen_out,
    void * const vbuf_out, u32 * const vlen_out)
{
  struct kvref kvref;
  if (!miter_kvref(iter->miter, &kvref))
    return false;

  // should never see TS here
  debug_assert(kvref.hdr.vlen != SST_VLEN_TS);
  if (kbuf_out) {
    const u32 klen = kvref.hdr.klen;
    memcpy(kbuf_out, kvref.kptr, klen);
    *klen_out = klen;
  }

  if (vbuf_out) {
    const u32 vlen = kvref.hdr.vlen & SST_VLEN_MASK;
    memcpy(vbuf_out, kvref.vptr, vlen);
    *vlen_out = vlen;
  }

  return true;
}

  void
remixdb_iter_skip(struct xdb_iter * const iter, const u32 nr)
{
  xdb_iter_skip(iter, nr);
}

  void
remixdb_iter_park(struct xdb_iter * const iter)
{
  xdb_iter_park(iter);
}

  void
remixdb_iter_destroy(struct xdb_iter * const iter)
{
  xdb_iter_destroy(iter);
}
// }}} remixdb

// fdm: marker
