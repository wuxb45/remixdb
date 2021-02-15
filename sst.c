/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

// headers {{{
#include "lib.h"
#include "ctypes.h"
#include "kv.h"
#include <assert.h> // static_assert
#include <dirent.h> // dirfd
#include <stdarg.h> // va_start
#include <sys/uio.h> // writev
#include "sst.h"

// }}} headers

// define {{{
#define SST_MAX_BLKPGNR ((16)) // 16 pages
#define SST_MAX_BLKSZ ((PGSZ * SST_MAX_BLKPGNR)) // 64kB
#define SST_MAX_KVSZ  ((SST_MAX_BLKSZ - (sizeof(u16) * 2)))
#define SST_MAX_BLKID ((UINT16_MAX - SST_MAX_BLKPGNR))
#define MSST_NWAY ((16)) // 16 levels

#define SSTY_STALE     ((0x80u))
#define SSTY_TOMBSTONE ((0x40u))
#define SSTY_RANK      ((0x3fu))
#define SSTY_INVALID   ((0xffu))

// 4 for 16; 5 for 32; TODO: 6 for 64
#define SSTY_DBITS ((5))
#define SSTY_DIST ((1u << SSTY_DBITS))
static_assert(SSTY_DBITS >= 4 && SSTY_DBITS <= 5, "Supported SSTY_DBITS: 4 and 5; TODO: 6");

#if defined(__linux__)
#define SSTY_MMAP_FLAGS ((MAP_PRIVATE|MAP_POPULATE))
#else
#define SSTY_MMAP_FLAGS ((MAP_PRIVATE))
#endif

// turn on IO-optimized binary search by default
#define MSSTY_SEEK_BISECT_OPT

#define MSSTZ_DIST ((32))
#define MSSTZ_NBLKS ((20400)) // slightly smaller than 20480
// approx. table size must be smaller
#define MSSTZ_TSZ ((MSSTZ_NBLKS * PGSZ))
#define MSSTZ_MINSZ ((MSSTZ_TSZ >> 2)) // 1/4 of the maximum table size
#define MSSTZ_ETSZ ((MSSTZ_NBLKS * ((PGSZ - 256))))
#define MSSTZ_NWAY_MINOR ((8))
#define MSSTZ_NWAY_MAJOR ((2))
#define MSSTZ_NWAY_SAFE ((12))
static_assert(MSSTZ_NWAY_MINOR <= MSST_NWAY, "nway");
static_assert(MSSTZ_NBLKS <= SST_MAX_BLKID, "nblks");
// }}} define

// kv {{{
  inline size_t
sst_kv_vi128_estimate(const struct kv * const kv)
{
  return vi128_estimate_u32(kv->klen) + vi128_estimate_u32(kv->vlen) + kv->klen + (kv->vlen & SST_VLEN_MASK);
}

  u8 *
sst_kv_vi128_encode(u8 * ptr, const struct kv * const kv)
{
  ptr = vi128_encode_u32(ptr, kv->klen);
  ptr = vi128_encode_u32(ptr, kv->vlen);
  const u32 kvlen = kv->klen + (kv->vlen & SST_VLEN_MASK);
  memcpy(ptr, kv->kv, kvlen);
  return ptr + kvlen;
}

  inline size_t
sst_kv_size(const struct kv * const kv)
{
  return sizeof(*kv) + kv->klen + (kv->vlen & SST_VLEN_MASK);
}

// estimate the size of kvs in a range
  u64
sst_kvmap_estimate(const struct kvmap_api * const api, void * const map,
    const struct kref * const k0, const struct kref * const kz)
{
  void * const ref = kvmap_ref(api, map);
  void * const iter = api->iter_create(ref);
  u64 est = 0;
  struct kv * kz_inp = NULL;
  if (kz) {
    api->iter_seek(iter, kz);
    api->iter_inp(iter, kvmap_inp_steal_kv, &kz_inp);
  }

  api->iter_seek(iter, k0);
  while (api->iter_valid(iter)) {
    struct kv * kv_inp = NULL;
    api->iter_inp(iter, kvmap_inp_steal_kv, &kv_inp);
    if (kv_inp == kz_inp)
      break;
    est += sst_kv_vi128_estimate(kv_inp);
    est += sizeof(u16);
    api->iter_skip(iter, 1);
  }

  api->iter_destroy(iter);
  kvmap_unref(api, ref);
  return est;
}

  struct kv *
sst_kvref_dup2_kv(struct kvref * const kvref, struct kv * const out)
{
  const size_t sz = sst_kv_size(&kvref->hdr);
  struct kv * const new = out ? out : malloc(sz);
  if (new) {
    *new = kvref->hdr;
    memcpy(new->kv, kvref->kptr, new->klen);
    memcpy(new->kv + new->klen, kvref->vptr, new->vlen & SST_VLEN_MASK);
  }
  return new;
}
// }}} kv

// mm {{{
  struct kv *
kvmap_mm_in_ts(struct kv * const kv, void * const priv)
{
  (void)priv;
  if (kv == NULL)
    return NULL;

  const size_t sz = sst_kv_size(kv);
  struct kv * const new = malloc(sz);
  if (new)
    memcpy(new, kv, sz);
  return new;
}

  struct kv *
kvmap_mm_out_ts(struct kv * const kv, struct kv * const out)
{
  if (kv == NULL)
    return NULL;
  const size_t sz = sst_kv_size(kv);
  struct kv * const new = out ? out : malloc(sz);
  if (new)
    memcpy(new, kv, sz);
  return new;
}

// for memtable
const struct kvmap_mm kvmap_mm_ts = {
  .in = kvmap_mm_in_ts,
  .out = kvmap_mm_out_ts,
  .free = kvmap_mm_free_free,
  .priv = NULL,
};
// }}} mm

// sst {{{
struct sst_blkmeta { // the first two bytes in each block
  u8 nkeys; // number of keys
  u8 nblks; // number of 4K pages
};

struct sst_meta {
  u32 inr; // == 0 for empty sst in the place of bms[0]
  u32 nblks;
  u64 seq; // <= the file's seq after linking
  u32 way; // this should be always valid after linking
  u32 totkv;
  u32 bmsoff;
  u32 ioffsoff;
  u32 ckeysoff;
  u32 ckeyssz;
};

struct sst {
  const struct sst_blkmeta * bms; // block metadata (2-byte each)
  u32 inr; // number of index keys in ioffs
  u32 nblks; // number of 4kB data blocks
  int fd;
  u32 refcnt; // not atomic; only msstz can change it; should close/unmap only when == 1
  struct rcache * rc;
  const u32 * ioffs; // offsets of the index keys
  u8 * mem; // pointer to the mmap area
  u32 fsize;
  u32 totkv;
};

  static bool
sst_init_at(const int dirfd, const u64 seq, const u32 way, struct sst * const sst)
{
  char fn[24];
  const u64 magic = seq * 100lu + way;
  sprintf(fn, "%03lu.sstx", magic);
  const int fd = openat(dirfd, fn, O_RDONLY);
  if (fd < 0)
    return false;

  const size_t fsize = fdsize(fd);
  if (fsize == 0 || fsize >= UINT32_MAX) {
    close(fd);
    return false;
  }

  // Hugepages make replacement hard; some file systems don't support hugepages
  //MAP_HUGETLB|MAP_HUGE_2MB
  u8 * const mem = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
  if (mem == MAP_FAILED)
    return false;

  sst->mem = mem;
  sst->fsize = (u32)fsize;
  const struct sst_meta * const meta = sst_meta(sst);
  debug_assert((meta->seq < seq) || ((meta->seq == seq) && (meta->way == way)));
  sst->bms = (typeof(sst->bms))(mem + meta->bmsoff);
  sst->inr = meta->inr;
  sst->nblks = meta->nblks;
  sst->fd = fd; // keep fd open
  sst->refcnt = 1;
  sst->rc = NULL;
  sst->ioffs = (typeof(sst->ioffs))(mem + meta->ioffsoff);
  sst->totkv = meta->totkv;
  //const u32 datasz = PGSZ * sst->nblks;
  //madvise(mem, datasz, MADV_RANDOM);
  //pages_lock(mem + datasz, fsize - datasz); // mlock the metadata area; not necessary with ssty
  pages_lock((void *)sst->bms, sizeof(sst->bms[0]) * meta->nblks); // mlock the bms
  return true;
}

  const struct sst_meta *
sst_meta(struct sst * const sst)
{
  const struct sst_meta * const meta = (typeof(meta))(sst->mem + sst->fsize - sizeof(*meta));
  return meta;
}

  inline void
sst_rcache(struct sst * const sst, struct rcache * const rc)
{
  sst->rc = rc;
}

  static struct sst *
sst_open_at(const int dirfd, const u64 seq, const u32 way)
{
  struct sst * const sst = yalloc(sizeof(*sst));
  if (sst == NULL)
    return NULL;
  if (sst_init_at(dirfd, seq, way, sst)) {
    return sst;
  } else {
    free(sst);
    return NULL;
  }
}

  struct sst *
sst_open(const char * const dirname, const u64 seq, const u32 way)
{
  const int dirfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dirfd < 0)
    return NULL;
  struct sst * const sst = sst_open_at(dirfd, seq, way);
  close(dirfd);
  return sst;
}

  static inline u32
k128_search_le(const u8 * const base, const u32 * const ioffs,
    const struct kref * const key, const size_t headersize, u32 l, u32 r)
{
  while ((l + 1) < r) {
    const u32 m = (l + r) >> 1;
    const int cmp = kref_k128_compare(key, base + headersize + ioffs[m]);
    if (cmp < 0) // search-key < [m]
      r = m;
    else if (cmp > 0) // search-key > [m]
      l = m;
    else
      return m;
  }
  return l;
}

  static u16
sst_search_blkid(struct sst * const map, const struct kref * const key)
{
  const u32 ikeyid = k128_search_le(map->mem, map->ioffs, key, sizeof(u16), 0, map->inr);
  const u16 blkid = *(const u16 *)(map->mem + map->ioffs[ikeyid]);
  return blkid;
}

// access data blocks from here
  static inline const u8 *
sst_blk_acquire(struct sst * const map, const u16 blkid)
{
  if (map->rc && (map->bms[blkid].nblks == 1)) {
    const u8 * const ptr = rcache_acquire(map->rc, map->fd, blkid);
    return ptr;
  }
  return map->mem + (PGSZ * blkid);
}

  static inline u64
sst_blk_retain(struct rcache * const rc, const u8 * blk)
{
  debug_assert(blk && (((u64)blk) & 0xffflu) == 0);
  if (rc && (blk[1] == 1))
    rcache_retain(rc, blk);
  return (u64)blk;
}

  static inline void
sst_blk_release(struct rcache * const rc, const u8 * blk)
{
  debug_assert(blk && (((u64)blk) & 0xffflu) == 0);
  if (rc && (blk[1] == 1))
    rcache_release(rc, blk);
}

// the highest bit is set if there is a match
// return 0 to nkeys (low bits)
  static u32
sst_search_block_ge(const u8 * const blk, const struct kref * const key)
{
  const u16 * const offs = (typeof(offs))(blk+sizeof(u16));
  u32 l = 0;
  u32 r = ((struct sst_blkmeta *)blk)->nkeys; // blkmeta.nkeys
  while (l < r) {
    const u32 m = (l + r) >> 1;
    const int cmp = kref_kv128_compare(key, blk + offs[m]);
    if (cmp < 0)
      r = m;
    else if (cmp > 0)
      l = m + 1;
    else
      return m | (1u << 31); // match
  }
  return l;
}

  static inline const u8 *
sst_blk_get_kvptr(const u8 * const blk, const u32 id)
{
  debug_assert(id < blk[0]);
  const u16 * const offs = (typeof(offs))(blk + sizeof(u8) + sizeof(u8));
  return blk + offs[id];
}

  struct kv *
sst_get(struct sst * const map, const struct kref * const key, struct kv * const out)
{
  const u16 blkid = sst_search_blkid(map, key);

  // search in the block
  const u8 * const blk = sst_blk_acquire(map, blkid);
  debug_assert(blk);
  const u32 r = sst_search_block_ge(blk, key);
  if ((r >> 31) == 0) { // not found
    sst_blk_release(map->rc, blk);
    return NULL;
  }

  // found
  const u8 * ptr = sst_blk_get_kvptr(blk, r & 0xffffu);
  u32 klen, vlen;
  ptr = vi128_decode_u32(ptr, &klen);
  ptr = vi128_decode_u32(ptr, &vlen);

  const u32 vlen1 = vlen & SST_VLEN_MASK;
  const u32 kvlen = klen + vlen1;
  struct kv * const ret = out ? out : malloc(sizeof(*ret) + kvlen);
  ret->klen = klen;
  ret->vlen = vlen;
  memcpy(ret->kv, ptr, kvlen);
  sst_blk_release(map->rc, blk);
  return ret;
}

  bool
sst_probe(struct sst * const map, const struct kref * const key)
{
  const u16 blkid = sst_search_blkid(map, key);

  // search in the block
  const u8 * const blk = sst_blk_acquire(map, blkid);
  debug_assert(blk);
  const u32 r = sst_search_block_ge(blk, key);
  sst_blk_release(map->rc, blk);
  return (r >> 31);
}

  struct kv *
sst_first_key(struct sst * const map, struct kv * const out)
{
  if (map->nblks == 0)
    return NULL;

  const u8 * const blk = sst_blk_acquire(map, 0);
  const u8 * ptr = sst_blk_get_kvptr(blk, 0);
  u32 klen, vlen;
  ptr = vi128_decode_u32(ptr, &klen);
  ptr = vi128_decode_u32(ptr, &vlen);
  struct kv * const ret = out ? out : malloc(sizeof(*ret) + klen);
  ret->klen = klen;
  ret->vlen = 0;
  memcpy(ret->kv, ptr, klen);
  sst_blk_release(map->rc, blk);
  return ret;
}

  struct kv *
sst_last_key(struct sst * const map, struct kv * const out)
{
  if (map->nblks == 0)
    return NULL;

  u32 bmsi = map->nblks-1;
  while (map->bms[bmsi].nblks == 0)
    bmsi--;
  debug_assert(bmsi < map->nblks);

  const u8 * const blk = sst_blk_acquire(map, bmsi);
  const u8 * ptr = sst_blk_get_kvptr(blk, map->bms[bmsi].nkeys-1);
  u32 klen, vlen;
  ptr = vi128_decode_u32(ptr, &klen);
  ptr = vi128_decode_u32(ptr, &vlen);
  struct kv * const ret = out ? out : malloc(sizeof(*ret) + klen);
  ret->klen = klen;
  ret->vlen = 0;
  memcpy(ret->kv, ptr, klen);
  sst_blk_release(map->rc, blk);
  return ret;
}

  static void
sst_deinit(struct sst * const map)
{
  if (map->refcnt == 1) {
    debug_assert(map->mem);
    munmap((void *)map->mem, map->fsize);
    if (map->rc)
      rcache_close(map->rc, map->fd);
    else
      close(map->fd);
  } else {
    map->refcnt--;
  }
}

  static void
sst_deinit_lazy(struct sst * const map)
{
  if (map->refcnt == 1) {
    debug_assert(map->mem);
    munmap((void *)map->mem, map->fsize);
    if (map->rc)
      rcache_close_lazy(map->rc, map->fd);
    else
      close(map->fd);
  } else {
    map->refcnt--;
  }
}

  void
sst_destroy(struct sst * const map)
{
  sst_deinit(map);
  free(map);
}

  void
sst_fprint(struct sst * const map, FILE * const out)
{
  fprintf(out, "%s totkv %u inr %u nblks %u filesz %u\n",
      __func__, map->totkv, map->inr, map->nblks, map->fsize);
}
// }}} sst

// kvenc {{{
// 2MB * 63 = 126 MB
#define KVENC_BUFSZ ((1u << 21))
#define KVENC_BUFNR ((63))
struct kvenc {
  u32 idx;
  u32 off;
  u8 * bufs[KVENC_BUFNR];
};

  static struct kvenc *
kvenc_create(void)
{
  return calloc(1, sizeof(struct kvenc));
}

  static void
kvenc_append_raw(struct kvenc * const enc, const void * const data, const u32 size)
{
  u32 off = 0;
  u32 rem = size;
  while (rem) {
    const u32 bufidx = enc->idx;
    debug_assert(bufidx < KVENC_BUFNR);
    if (enc->bufs[bufidx] == NULL)
      enc->bufs[bufidx] = malloc(KVENC_BUFSZ);

    const u32 cpsz = (rem <= (KVENC_BUFSZ - enc->off)) ? rem : (KVENC_BUFSZ - enc->off);
    if (data)
      memcpy(enc->bufs[bufidx] + enc->off, ((u8 *)data) + off, cpsz);
    else
      memset(enc->bufs[bufidx] + enc->off, 0, cpsz);

    rem -= cpsz;
    off += cpsz;
    enc->off += cpsz;
    if (enc->off == KVENC_BUFSZ) {
      enc->idx = bufidx + 1;
      enc->off = 0;
    }
  }
}

  static void
kvenc_append_bool(struct kvenc * const enc, const bool v)
{
  kvenc_append_raw(enc, &v, sizeof(bool));
}

  static inline void
kvenc_append_u32(struct kvenc * const enc, const u32 val)
{
  kvenc_append_raw(enc, &val, sizeof(val));
}

  static inline u32 *
kvenc_append_u32_backref(struct kvenc * const enc)
{
  const u32 idx = enc->idx;
  const u32 off = enc->off;
  debug_assert((off + sizeof(u32)) <= KVENC_BUFSZ);
  debug_assert((off % sizeof(u32)) == 0);
  kvenc_append_raw(enc, NULL, sizeof(u32));
  return (u32 *)(enc->bufs[idx] + off);
}

  static inline void
kvenc_append_u16(struct kvenc * const enc, const u16 val)
{
  kvenc_append_raw(enc, &val, sizeof(val));
}

  static inline void
kvenc_append_vi128(struct kvenc * const enc, const u32 val)
{
  u8 buf[8];
  u8 * const end = vi128_encode_u32(buf, val);
  kvenc_append_raw(enc, buf, (u32)(end - buf));
}

  static inline void
kvenc_append_padding(struct kvenc * const enc, const u32 power)
{
  debug_assert(power <= 12);
  const u32 p2 = 1u << power;
  const u32 off = enc->off & (p2 - 1);
  if (off)
    kvenc_append_raw(enc, NULL, p2 - off);
}

  static u32
kvenc_size(struct kvenc * const enc)
{
  return KVENC_BUFSZ * enc->idx + enc->off;
}

  static ssize_t
kvenc_write(struct kvenc * const enc, const int fd)
{
  struct iovec vec[KVENC_BUFNR+1];
  const u32 nr = enc->idx;
  for (u32 i = 0; i < nr; i++) {
    vec[i].iov_base = enc->bufs[i];
    vec[i].iov_len = KVENC_BUFSZ;
  }
  vec[nr].iov_base = enc->bufs[nr];
  vec[nr].iov_len = enc->off;
  return writev(fd, vec, enc->off ? (nr + 1) : nr);
}

  static void
kvenc_reset(struct kvenc * const enc)
{
  for (u32 i = 0; i < KVENC_BUFNR; i++) {
    if (enc->bufs[i])
      free(enc->bufs[i]);
    else
      break;
  }
  memset(enc, 0, sizeof(*enc));
}

  static void
kvenc_destroy(struct kvenc * const enc)
{
  const u32 nr = enc->idx;
  for (u32 i = 0; i < nr; i++)
    free(enc->bufs[i]);
  if (enc->off)
    free(enc->bufs[nr]);
  free(enc);
}
// }}} kvenc

// sst_build {{{
#define SST_BUILD_METASZ ((sizeof(u16) * 256 * 2))
#define SST_BUILD_BUFSZ ((SST_BUILD_METASZ + SST_MAX_BLKSZ))
#define SST_BUILD_NVEC ((16))

// from k0 (inclusive) to kz (exclusive)
// warning: all iters in miter must handle the tombstone (vlen >= SST_VLEN_TS)
// return the output file size (in bytes)
  static u64
sst_build_at(const int dirfd, struct miter * const miter,
    const u64 seq, const u32 way, const u32 maxblks, const bool del, const bool ckeys,
    const struct kv * const k0, const struct kv * const kz)
{
  char fn[24];
  const u64 magic = seq * 100lu + way;
  sprintf(fn, "%03lu.sstx", magic);
  const int fdout = openat(dirfd, fn, O_WRONLY|O_CREAT|O_TRUNC, 00644);
  if (fdout < 0)
    return 0;

  struct kv * const tmp0 = malloc(SST_MAX_BLKSZ);
  kv_refill(tmp0, "", 0, "", 0);
  struct kv * const tmp1 = malloc(SST_MAX_BLKSZ);

  // kv encoding buffers
  struct iovec vecs[SST_BUILD_NVEC];
  u8 * const databufs = malloc(SST_BUILD_BUFSZ * SST_BUILD_NVEC); // kv blocks
  u16 * mbuf = (u16 *)databufs;
  u8 * kvbuf = ((u8 *)mbuf) + SST_BUILD_METASZ;
  u8 * kvcsr = kvbuf;
  u32 vi = 0;

  // max number of 4kB data blocks
  debug_assert(maxblks && (maxblks <= SST_MAX_BLKID));
  struct sst_blkmeta * const bms = calloc(1, sizeof(bms[0]) * (maxblks + SST_MAX_BLKPGNR));
  u32 keyid = 0; // number of keys in current block
  u32 blkid = 0;
  u32 totkv = 0;
  // at most 65536 ikeys
  u32 * const ioffs = malloc(sizeof(ioffs[0]) * (1lu << 16)); // offsets of ikeys

  struct kvenc * const aenc = kvenc_create();
  struct kvenc * const kenc = kvenc_create();
  u32 inr = 0;

  if (k0)
    miter_kv_seek(miter, k0);

  do {
    // key in tmp1
    struct kv * curr = miter_peek(miter, tmp1);

    // skip tombstone; need tests!
    if (del) {
      while (curr && (curr->vlen == SST_VLEN_TS)) {
        miter_skip_unique(miter);
        curr = miter_peek(miter, tmp1);
      }
    }

    // check for termination
    if (curr && kz && (kv_compare(curr, kz) >= 0))
      curr = NULL;

    const size_t est1 = curr ? ((u32)sst_kv_vi128_estimate(curr) + sizeof(u16)) : 0;
    if (est1 > SST_MAX_KVSZ) {
      fprintf(stderr, "WARNING: skip very long kv: size=%zu\n", est1);
      miter_skip_unique(miter);
      continue;
    }
    // estimate the sizes if curr is added to the current block
    const u32 metasz = sizeof(u16) * (keyid + 1);
    const u32 datasz = (u32)(kvcsr - kvbuf);
    const u32 totsz = metasz + datasz;
    const u32 esttot = totsz + (u32)est1;
    // close and write current block if:
    //     no more new data: curr == NULL
    // or: the new keys is not the first key AND total size is more than one page
    // or: current block has too many keys (254)
    // NOTE: a huge key (need 2+ pages) exclusively ocuppy a multi-page block
    if (curr == NULL || (keyid && (esttot > PGSZ)) || (keyid == 254)) {
      if (keyid == 0)
        break;

      // blksize: whole pages
      const u32 blksize = (u32)bits_round_up(metasz + datasz, 12);
      const u8 blknr = (u8)(blksize >> 12); // 1 to 16
      debug_assert(blknr && (blknr <= SST_MAX_BLKPGNR));
      // encode the metadata right before the kvbuf
      u16 * const mbuf1 = (u16 *)(kvbuf - metasz);
      for (u32 i = 0; i < keyid; i++)
        mbuf1[i+1] = mbuf[i] + metasz;

      // write all metadata: metasz bytes
      // save in the buffer
      struct sst_blkmeta * const pblkmeta = &(bms[blkid]);
      pblkmeta->nkeys = keyid; // 1 byte # of keys
      pblkmeta->nblks = blknr; // 1byte # of 4kB blocks
      mbuf1[0] = *(u16 *)pblkmeta;
      memset(kvcsr, 0, blksize - metasz - datasz); // zero-padding

      struct iovec * const vec = &vecs[vi];
      vec->iov_base = mbuf1;
      vec->iov_len = blksize;
      vi++;
      if (vi == SST_BUILD_NVEC) {
        writev(fdout, vecs, vi); // ignore I/O errors
        vi = 0;
      }
      mbuf = (u16 *)(databufs + (SST_BUILD_BUFSZ * vi));
      kvbuf = ((u8 *)mbuf) + SST_BUILD_METASZ;
      kvcsr = kvbuf;
      keyid = 0;
      blkid += blknr;
      // stop processing the next block; break the do-while loop
      if ((curr == NULL) || (blkid >= maxblks))
        break;
    }
    // the beginning of a block: build anchor key for every head key of block
    if (keyid == 0) {
      ioffs[inr] = kvenc_size(aenc);
      // block id
      debug_assert(blkid <= SST_MAX_BLKID);
      kvenc_append_u16(aenc, (u16)blkid);
      // anchor key
      const u32 alen = tmp0->klen ? (kv_key_lcp(tmp0, curr)+1) : 0;
      debug_assert(alen <= curr->klen);
      // encode index key
      kvenc_append_vi128(aenc, alen);
      kvenc_append_raw(aenc, curr->kv, alen);
      inr++;
    }

    // append kv to data block
    mbuf[keyid++] = (u16)(kvcsr - kvbuf);
    kvcsr = sst_kv_vi128_encode(kvcsr, curr);
    totkv++;
    // copy keys for faster remix building
    if (ckeys) {
      const u32 lcp = kv_key_lcp(curr, tmp0);
      const u32 slen = curr->klen - lcp;
      kvenc_append_vi128(kenc, lcp); // prefix length
      kvenc_append_vi128(kenc, slen); // suffix length
      kvenc_append_bool(kenc, curr->vlen == SST_VLEN_TS);
      kvenc_append_raw(kenc, curr->kv + lcp, slen);
    }
    // remember last key in tmp0
    kv_dup2_key(curr, tmp0);
    miter_skip_unique(miter);
  } while (true);

  if (vi)
    writev(fdout, vecs, vi); // ignore I/O errors

  debug_assert(inr < UINT16_MAX);
  // place bms immediately after data blocks
  const u32 bmsoff = PGSZ * blkid;
  const u32 bmssz = sizeof(bms[0]) * blkid;
  // now all data blocks have been written; write one big index block
  // calculate index-key offsets
  const u32 ikeysoff = bmsoff + bmssz; // index keys
  for (u64 i = 0; i < inr; i++)
    ioffs[i] += ikeysoff;
  // write: index keys; all index-key offsets; # of index-keys
  kvenc_append_padding(aenc, 4);
  kvenc_append_padding(kenc, 4);
  const u32 ikeyssz = kvenc_size(aenc);
  const u32 ioffsoff = ikeysoff + ikeyssz;
  const u32 ioffssz = sizeof(ioffs[0]) * inr;
  const u32 ckeysoff = ioffsoff + ioffssz;
  const u32 ckeyssz = kvenc_size(kenc);

  // metadata
  struct sst_meta endmeta = {.inr = inr, .nblks = blkid, .seq = seq, .way = way, .totkv = totkv,
    .bmsoff = bmsoff, .ioffsoff = ioffsoff, .ckeysoff = ckeysoff, .ckeyssz = ckeyssz, };
  const u32 endsz = sizeof(endmeta);
  const u64 totsz = ckeysoff + ckeyssz + endsz;

  // sst file layout:
  // 0: data blocks 4kB x blkid      +bmsoff==blkssz
  // bmsoff: blockmetas (bms)        +bmssz[0]
  // ikeysoff: index keys (ikeys)    +ikeyssz[1]
  // ioffsoff: index offsets (ioffs) +ioffssz[2]
  // ?:      endmeta                 +endsz[3]
  // totsz is file size

  const ssize_t nwbms = write(fdout, bms, bmssz);
  const ssize_t nwanc = kvenc_write(aenc, fdout);
  const ssize_t nwiof = write(fdout, ioffs, ioffssz);
  const ssize_t nwcpy = kvenc_write(kenc, fdout);
  const ssize_t nwmeta = write(fdout, &endmeta, endsz);
  const bool wok = (bmssz + ikeyssz + ioffssz + ckeyssz + endsz) == (nwbms + nwanc + nwiof + nwcpy + nwmeta);

  // done
  fsync(fdout);
  close(fdout);
  free(tmp0);
  free(tmp1);
  free(databufs);
  free(bms);
  free(ioffs);
  kvenc_destroy(aenc);
  kvenc_destroy(kenc);
  return wok ? totsz : 0;
}

  u64
sst_build(const char * const dirname, struct miter * const miter,
    const u64 seq, const u32 way, const u32 maxblks, const bool del, const bool ckeys,
    const struct kv * const k0, const struct kv * const kz)
{
  const int dirfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dirfd < 0)
    return 0;
  const u64 ret = sst_build_at(dirfd, miter, seq, way, maxblks, del, ckeys, k0, kz);
  close(dirfd);
  return ret;
}
// }}} sst_build

// sst_iter {{{
struct sst_ptr {
  u16 blkid; // xth 4kb-block in the table
  u16 keyid; // xth key in the block // MAX == invalid
};

struct sst_iter { // 32 bytes
  struct sst * sst;
  u32 rank; // pure rank value < nway
  struct sst_ptr ptr;
  u32 klen;
  u32 vlen;
  const u8 * kvdata;
};

  static int
sst_iter_compare(struct sst_iter * const i1, struct sst_iter * const i2)
{
  debug_assert(i1->ptr.keyid != UINT16_MAX);
  debug_assert(i2->ptr.keyid != UINT16_MAX);
  const u32 len = i1->klen < i2->klen ? i1->klen : i2->klen;
  const int cmp = memcmp(i1->kvdata, i2->kvdata, len);
  return cmp ? cmp : (((int)i1->klen) - ((int)i2->klen));
}

// i1 must be valid
// key can be NULL
  static int
sst_iter_compare_kref(struct sst_iter * const iter, const struct kref * const key)
{
  debug_assert(iter->ptr.keyid != UINT16_MAX);
  debug_assert(key);
  const u32 len = (iter->klen < key->len) ? iter->klen : key->len;
  const int cmp = memcmp(iter->kvdata, key->ptr, len);
  if (cmp != 0) {
    return cmp;
  } else {
    return ((int)iter->klen) - ((int)key->len);
  }
}

  static inline bool
sst_iter_match_kref(const struct sst_iter * const i1, const struct kref * const key)
{
  debug_assert(i1->ptr.keyid != UINT16_MAX);
  return (i1->klen == key->len) && (!memcmp(i1->kvdata, key->ptr, i1->klen));
}

  static inline const u8 *
sst_iter_blk_addr(struct sst_iter * const iter)
{
  debug_assert(iter->kvdata);
  const u64 addr = ((u64)iter->kvdata) >> 12 << 12;
  return (const u8 *)addr;
}

  static inline void
sst_iter_blk_release(struct sst_iter * const iter)
{
  if (iter->kvdata) {
    // get page address
    const u8 * const blk = sst_iter_blk_addr(iter);
    sst_blk_release(iter->sst->rc, blk);
    iter->kvdata = NULL;
  }
}

// sst only
// call this function when iter has been moved
  static void
sst_iter_fix_ptr(struct sst_iter * const iter)
{
  const struct sst_blkmeta blkmeta = iter->sst->bms[iter->ptr.blkid];
  sst_iter_blk_release(iter);

  // will fix kvdata in peek()
  if (iter->ptr.keyid >= blkmeta.nkeys) { // beyond the current block
    iter->ptr.blkid += blkmeta.nblks;
    if (iter->ptr.blkid >= iter->sst->nblks) {
      iter->ptr.keyid = UINT16_MAX; // invalid
      return;
    }
    iter->ptr.keyid = 0;
  }
}

  static void
sst_iter_fix_kv_reuse(struct sst_iter * const iter)
{
  // reuse the kvdata and keyid
  debug_assert(iter->kvdata);
  const u8 * const blk = sst_iter_blk_addr(iter);
  const u8 * ptr = sst_blk_get_kvptr(blk, iter->ptr.keyid);
  ptr = vi128_decode_u32(ptr, &iter->klen);
  iter->kvdata = vi128_decode_u32(ptr, &iter->vlen);
}

// make kvdata current with the iter; acquire blk
// also used by mssty
  static void
sst_iter_fix_kv(struct sst_iter * const iter)
{
  // don't fix if invalid or already has the ->kvdata
  if ((!sst_iter_valid(iter)) || iter->kvdata)
    return;

  const u8 * blk = sst_blk_acquire(iter->sst, iter->ptr.blkid);
  const u8 * ptr = sst_blk_get_kvptr(blk, iter->ptr.keyid);
  ptr = vi128_decode_u32(ptr, &iter->klen);
  iter->kvdata = vi128_decode_u32(ptr, &iter->vlen);
}

// points to the first key; invalid for empty sst
  static inline void
sst_iter_init(struct sst_iter * const iter, struct sst * const sst, const u32 rank)
{
  debug_assert(rank < MSST_NWAY);
  iter->sst = sst;
  iter->rank = rank;
  iter->ptr.blkid = sst->nblks;
  iter->ptr.keyid = UINT16_MAX;
  // klen, vlen are ignored
  iter->kvdata = NULL;
}

  struct sst_iter *
sst_iter_create(struct sst * const sst)
{
  struct sst_iter * const iter = calloc(1, sizeof(*iter));
  if (iter == NULL)
    return NULL;
  sst_iter_init(iter, sst, 0);
  return iter;
}

  void
sst_iter_seek(struct sst_iter * const iter, const struct kref * const key)
{
  // first, find the block
  iter->ptr.blkid = sst_search_blkid(iter->sst, key);
  if (iter->ptr.blkid < iter->sst->nblks) {
    // second, find search in the block
    const u8 * const blk = sst_blk_acquire(iter->sst, iter->ptr.blkid);
    iter->ptr.keyid = (u16)sst_search_block_ge(blk, key); // ignoring the high bits
    sst_blk_release(iter->sst->rc, blk);
    sst_iter_fix_ptr(iter);
  } else {
    debug_assert(iter->ptr.keyid == UINT16_MAX);
  }
}

  inline void
sst_iter_seek_null(struct sst_iter * const iter)
{
  iter->ptr.blkid = 0;
  if (iter->sst->nblks) {
    iter->ptr.keyid = 0;
    sst_iter_fix_ptr(iter);
    debug_assert(iter->ptr.keyid != UINT16_MAX);
  } else {
    iter->ptr.keyid = UINT16_MAX;
  }
}

  inline bool
sst_iter_valid(struct sst_iter * const iter)
{
  return iter->ptr.keyid != UINT16_MAX;
}

// test if iter points to a tombstone
  inline bool
sst_iter_ts(struct sst_iter * const iter)
{
  sst_iter_fix_kv(iter);
  return iter->vlen == SST_VLEN_TS;
}

  struct kv *
sst_iter_peek(struct sst_iter * const iter, struct kv * const out)
{
  if (!sst_iter_valid(iter))
    return NULL;

  sst_iter_fix_kv(iter);

  const u32 vlen1 = iter->vlen & SST_VLEN_MASK;
  const u32 kvlen = iter->klen + vlen1;
  struct kv * const ret = out ? out : malloc(sizeof(*ret) + kvlen);
  ret->klen = iter->klen;
  ret->vlen = iter->vlen;
  memcpy(ret->kv, iter->kvdata, kvlen);
  return ret;
}

  bool
sst_iter_kref(struct sst_iter * const iter, struct kref * const kref)
{
  if (!sst_iter_valid(iter))
    return false;

  sst_iter_fix_kv(iter);
  kref_ref_raw(kref, iter->kvdata, iter->klen); // no hash32
  return true;
}

  bool
sst_iter_kvref(struct sst_iter * const iter, struct kvref * const kvref)
{
  if (!sst_iter_valid(iter))
    return false;

  sst_iter_fix_kv(iter);
  kvref->hdr.klen = iter->klen;
  kvref->hdr.vlen = iter->vlen;
  kvref->hdr.hash = 0;
  kvref->kptr = iter->kvdata;
  kvref->vptr = iter->kvdata + iter->klen;
  return true;
}

  inline u64
sst_iter_retain(struct sst_iter * const iter)
{
  return sst_blk_retain(iter->sst->rc, sst_iter_blk_addr(iter));
}

  inline void
sst_iter_release(struct sst_iter * const iter, const u64 opaque)
{
  sst_blk_release(iter->sst->rc, (const u8 *)opaque);
}

// skip using the given blkmeta[]
  void
sst_iter_skip(struct sst_iter * const iter, const u32 nr)
{
  if (!sst_iter_valid(iter))
    return;

  const struct sst_blkmeta * const bms = iter->sst->bms;
  struct sst_ptr * const pptr = &iter->ptr;
  u32 todo = nr;
  do {
    const u32 ncap = bms[pptr->blkid].nkeys - pptr->keyid;
    if (todo < ncap) {
      pptr->keyid += todo;
      if (iter->kvdata)
        sst_iter_fix_kv_reuse(iter);
      return; // done
    }
    sst_iter_park(iter); // discard iter->kvdata
    pptr->blkid += bms[pptr->blkid].nblks;
    if (pptr->blkid >= iter->sst->nblks) {
      pptr->keyid = UINT16_MAX;
      return; // invalid
    }
    pptr->keyid = 0;
    todo -= ncap;
  } while (todo);
}

  struct kv *
sst_iter_next(struct sst_iter * const iter, struct kv * const out)
{
  struct kv * const ret = sst_iter_peek(iter, out);
  sst_iter_skip(iter, 1);
  return ret;
}

  void
sst_iter_park(struct sst_iter * const iter)
{
  sst_iter_blk_release(iter);
}

  void
sst_iter_destroy(struct sst_iter * const iter)
{
  sst_iter_park(iter);
  free(iter);
}

  void
sst_dump(struct sst * const sst, const char * const fn)
{
  const int fd = open(fn, O_WRONLY|O_CREAT|O_TRUNC, 00644);
  debug_assert(fd >= 0);
  struct sst_iter iter;
  sst_iter_init(&iter, sst, 0);
  sst_iter_seek_null(&iter);
  struct kvref kvref;
  u32 n = 0;
  dprintf(fd, "nblks %u totkv %u\n", sst->nblks, sst->totkv);
  while (sst_iter_kvref(&iter, &kvref)) {
    dprintf(fd, "%6u b %6u k %6u %.*s (%u,%u)\n",
        n, iter.ptr.blkid, iter.ptr.keyid, iter.klen, iter.kvdata, iter.klen, iter.vlen);
    sst_iter_skip(&iter, 1);
    n++;
  }
  fsync(fd);
  close(fd);
}
// }}} sst_iter

// msstx {{{
struct msst {
  u64 seq;
  u32 nway;
  au32 refcnt;
  struct ssty * ssty; // ssty makes it mssty
  struct rcache * rc;
  struct sst ssts[MSST_NWAY];
};

struct msstx_iter {
  struct msst * msst;
  u32 nway;
  // minheap
  struct sst_iter * mh[MSST_NWAY+1];
  struct sst_iter iters[MSST_NWAY];
};

  static struct msst *
msstx_open_at_reuse(const int dirfd, const u64 seq, const u32 nway, struct msst * const msst0, const u32 nway0)
{
  if (nway > MSST_NWAY)
    return NULL;
  struct msst * const msst = calloc(1, sizeof(*msst));
  if (msst == NULL)
    return NULL;

  debug_assert(nway0 <= nway);
  for (u32 i = 0; i < nway0; i++) {
    debug_assert(msst0->ssts[i].refcnt == 1);
    msst->ssts[i] = msst0->ssts[i];
    // only increment the old's refcnt
    msst0->ssts[i].refcnt++;
  }

  for (u32 i = nway0; i < nway; i++) {
    if (!sst_init_at(dirfd, seq, i, &(msst->ssts[i])))
      goto fail_sst;
  }
  msst->seq = seq;
  msst->nway = nway;
  return msst;

fail_sst:
  for (u64 i = 0; i < nway; i++)
    if (msst->ssts[i].mem)
      sst_deinit(&(msst->ssts[i]));

  free(msst);
  return NULL;
}

  static struct msst *
msstx_open_at(const int dirfd, const u64 seq, const u32 nway)
{
  return msstx_open_at_reuse(dirfd, seq, nway, NULL, 0);
}

  inline struct msst *
msstx_open(const char * const dirname, const u64 seq, const u32 nway)
{
  const int dirfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dirfd < 0)
    return NULL;
  struct msst * const msst = msstx_open_at_reuse(dirfd, seq, nway, NULL, 0);
  close(dirfd);
  return msst;
}

  inline void
msst_rcache(struct msst * const msst, struct rcache * const rc)
{
  msst->rc = rc;
  for (u32 i = 0; i < msst->nway; i++)
    sst_rcache(&(msst->ssts[i]), rc);
}

  void
msstx_destroy(struct msst * const msst)
{
  debug_assert(msst->ssty == NULL);
  for (u32 i = 0; i < msst->nway; i++)
    sst_deinit(&(msst->ssts[i]));
  free(msst);
}

  struct msstx_iter *
msstx_iter_create(struct msst * const msst)
{
  struct msstx_iter * const iter = calloc(1, sizeof(*iter));
  if (iter == NULL)
    return NULL;

  iter->msst = msst;
  iter->nway = msst->nway;
  for (u32 i = 0; i < msst->nway; i++) {
    sst_iter_init(&(iter->iters[i]), &(msst->ssts[i]), i);
    iter->mh[i+1] = &(iter->iters[i]);
  }
  return iter;
}

  struct kv *
msstx_get(struct msst * const msst, const struct kref * const key, struct kv * const out)
{
  for (u32 i = msst->nway-1; i < msst->nway; i--) {
    struct kv * const ret = sst_get(&(msst->ssts[i]), key, out);
    if (ret)
      return ret;
  }
  return NULL;
}

  bool
msstx_probe(struct msst * const msst, const struct kref * const key)
{
  for (u32 i = msst->nway-1; i < msst->nway; i--)
    if (sst_probe(&(msst->ssts[i]), key))
      return true;
  return false;
}

// mh {{{
  static void
msstx_mh_swap(struct msstx_iter * const iter, const u32 cidx)
{
  debug_assert(cidx > 1);
  struct sst_iter * const tmp = iter->mh[cidx];
  iter->mh[cidx] = iter->mh[cidx>>1];
  iter->mh[cidx>>1] = tmp;
}

  static bool
msstx_mh_should_swap(struct sst_iter * const sp, struct sst_iter * const sc)
{
  debug_assert(sp != sc);
  debug_assert(sp->rank != sc->rank);
  if (!sst_iter_valid(sp))
    return true;
  if (!sst_iter_valid(sc))
    return false;

  const int c = sst_iter_compare(sp, sc);
  if (c > 0)
    return true;
  else if (c < 0)
    return false;
  return sp->rank < sc->rank; // high rank == high priority
}

  static void
msstx_mh_uphead(struct msstx_iter * const iter, u32 idx)
{
  while (idx > 1) {
    struct sst_iter * const sp = iter->mh[idx >> 1];
    struct sst_iter * const sc = iter->mh[idx];
    if (!sst_iter_valid(sc))
      return;
    if (msstx_mh_should_swap(sp, sc))
      msstx_mh_swap(iter, idx);
    else
      return;
    idx >>= 1;
  }
}

  static void
msstx_mh_downheap(struct msstx_iter * const iter, u32 idx)
{
  const u32 nway = iter->nway;
  while ((idx<<1) <= nway) {
    struct sst_iter * sl = iter->mh[idx<<1];
    u32 idxs = idx << 1;
    if ((idx<<1) < nway) { // has sr
      struct sst_iter * sr = iter->mh[(idx<<1) + 1];
      if (msstx_mh_should_swap(sl, sr))
        idxs++;
    }

    if (msstx_mh_should_swap(iter->mh[idx], iter->mh[idxs]))
      msstx_mh_swap(iter, idxs);
    else
      return;
    idx = idxs;
  }
}
// }}} mh

  bool
msstx_iter_valid(struct msstx_iter * const iter)
{
  return iter->nway && sst_iter_valid(iter->mh[1]);
}

  static inline bool
msstx_iter_valid_1(struct msstx_iter * const iter)
{
  return iter->nway != 0;
}

  void
msstx_iter_seek(struct msstx_iter * const iter, const struct kref * const key)
{
  const u32 nway = iter->nway;
  for (u32 i = 1; i <= nway; i++) {
    struct sst_iter * const iter1 = iter->mh[i];
    sst_iter_seek(iter1, key);
    if (sst_iter_valid(iter1))
      sst_iter_fix_kv(iter1);
  }
  for (u32 i = 2; i <= nway; i++)
    msstx_mh_uphead(iter, i);
}

  void
msstx_iter_seek_null(struct msstx_iter * const iter)
{
  const u32 nway = iter->nway;
  for (u32 i = 1; i <= nway; i++) {
    struct sst_iter * const iter1 = iter->mh[i];
    sst_iter_seek_null(iter1);
    if (sst_iter_valid(iter1))
      sst_iter_fix_kv(iter1);
  }
  for (u32 i = 2; i <= nway; i++)
    msstx_mh_uphead(iter, i);
}

  struct kv *
msstx_iter_peek(struct msstx_iter * const iter, struct kv * const out)
{
  if (!msstx_iter_valid_1(iter))
    return NULL;
  return sst_iter_peek(iter->mh[1], out);
}

  bool
msstx_iter_kref(struct msstx_iter * const iter, struct kref * const kref)
{
  if (!msstx_iter_valid_1(iter))
    return false;

  return sst_iter_kref(iter->mh[1], kref);
}

  bool
msstx_iter_kvref(struct msstx_iter * const iter, struct kvref * const kvref)
{
  if (!msstx_iter_valid_1(iter))
    return false;

  return sst_iter_kvref(iter->mh[1], kvref);
}

  inline u64
msstx_iter_retain(struct msstx_iter * const iter)
{
  return sst_iter_retain(iter->mh[1]);
}

  inline void
msstx_iter_release(struct msstx_iter * const iter, const u64 opaque)
{
  // all should use the same rcache
  sst_blk_release(iter->msst->rc, (const u8 *)opaque);
}

  void
msstx_iter_skip(struct msstx_iter * const iter, const u32 nr)
{
  for (u32 i = 0; i < nr; i++) {
    if (!msstx_iter_valid(iter))
      return;
    struct sst_iter * const iter1 = iter->mh[1];
    sst_iter_skip(iter1, 1);
    if (sst_iter_valid(iter1))
      sst_iter_fix_kv(iter1);
    msstx_mh_downheap(iter, 1);
  }
}

  struct kv *
msstx_iter_next(struct msstx_iter * const iter, struct kv * const out)
{
  struct kv * const ret = msstx_iter_peek(iter, out);
  msstx_iter_skip(iter, 1);
  return ret;
}

  void
msstx_iter_park(struct msstx_iter * const iter)
{
  const u32 nway = iter->nway;
  for (u32 i = 0; i < nway; i++)
    sst_iter_park(&(iter->iters[i]));
}

  void
msstx_iter_destroy(struct msstx_iter * const iter)
{
  msstx_iter_park(iter);
  free(iter);
}
// }}} msstx

// ssty {{{
struct ssty_meta {
  u32 nway;
  u32 nkidx;
  u32 padding;
  u32 ptroff;
  u32 inr1;
  u32 ioff1;
  u32 inr2;
  u32 ioff2;

  u32 totkv; // total number, including stale keys and tombstones
  u32 totsz; // sum of all sstx file's sizes (NOTE: totsz < 4GB)
  u32 valid; // number of valid keys (excluding stale keys and tombstones)
  u32 uniqx[MSST_NWAY+1];
  u64 magic;
};


struct ssty {
  union {
    u8 * mem; // and the array
    const u8 * ranks;
  };
  size_t size;
  u32 nway;
  u32 nkidx; // number of entries (including placeholders)
  u32 inr; // number of index entries
  u32 inr2;
  const struct sst_ptr * ptrs; // array of seek pointers
  const u32 * ioffs; // index offs
  const u32 * ioffs2;
  //u64 magic; // seq * 100 + nway
  const struct ssty_meta * meta;
  //const struct sst_blkmeta * bms[MSST_NWAY];
};

  static struct ssty *
ssty_open_at(const int dirfd, const u64 seq, const u32 nway)
{
  char fn[16];
  const u64 magic = seq * 100lu + nway;
  sprintf(fn, "%03lu.ssty", magic);
  const int fd = openat(dirfd, fn, O_RDONLY);
  if (fd < 0)
    return NULL;
  struct stat st;

  if (fstat(fd, &st))
    goto fail;

  const u64 fsize = (u64)st.st_size;
  debug_assert(fsize < UINT32_MAX);
  u8 * const mem = mmap(NULL, fsize, PROT_READ, SSTY_MMAP_FLAGS, fd, 0);
  if (mem == MAP_FAILED)
    goto fail;
  close(fd);
  struct ssty * const ssty = calloc(1, sizeof(*ssty));

  ssty->mem = mem;
  ssty->size = fsize;
  //pages_lock(mem, fsize);
  const struct ssty_meta * const meta = (typeof(meta))(mem + fsize - sizeof(*meta));
  ssty->nway = meta->nway;
  ssty->nkidx = meta->nkidx;
  ssty->ptrs = (struct sst_ptr *)(mem + meta->ptroff); // size1
  ssty->inr = meta->inr1; // nsecs
  ssty->ioffs = (const u32 *)(mem + meta->ioff1); // ioffsoff
  ssty->inr2 = meta->inr2; // ipages
  ssty->ioffs2 = (const u32 *)(mem + meta->ioff2); // ioffsoff2
  ssty->meta = meta;
  debug_assert(ssty->meta->magic == magic);
  return ssty;
fail:
  close(fd);
  return NULL;
}

  struct ssty *
ssty_open(const char * const dirname, const u64 seq, const u32 nway)
{
  const int dirfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dirfd < 0)
    return NULL;
  struct ssty * const ssty = ssty_open_at(dirfd, seq, nway);
  close(dirfd);
  return ssty;
}

  void
ssty_destroy(struct ssty * const ssty)
{
  debug_assert(ssty);
  munmap((void *)ssty->mem, ssty->size);
  free(ssty);
}

  void
ssty_fprint(struct ssty * const ssty, FILE * const fout)
{
  fprintf(fout, "%s magic %lu nway %u nkidx %u inr %u %u filesz %zu\n",
      __func__, ssty->meta->magic, ssty->nway, ssty->nkidx,
      ssty->inr, ssty->inr2, ssty->size);
}

  static u32
ssty_ranks_mask(const u8 * const ranks, const u8 rank)
{
#if defined(__x86_64__)
#if SSTY_DBITS == 5
#if defined(__AVX2__)
  const m256 maskv = _mm256_set1_epi8(SSTY_RANK);
  const m256 rankv = _mm256_set1_epi8(rank);
  const m256 tmpv = _mm256_and_si256(_mm256_load_si256((const void *)ranks), maskv);
  return (u32)_mm256_movemask_epi8(_mm256_cmpeq_epi8(tmpv, rankv));
#else
  const m128 maskv = _mm_set1_epi8(SSTY_RANK);
  const m128 rankv = _mm_set1_epi8(rank);
  const m128 tmpv0 = _mm_and_si128(_mm_load_si128((const void *)ranks), maskv);
  const m128 tmpv1 = _mm_and_si128(_mm_load_si128((const void *)(ranks+sizeof(m128))), maskv);
  const u32 bits0 = (u32)_mm_movemask_epi8(_mm_cmpeq_epi8(tmpv0, rankv));
  const u32 bits1 = (u32)_mm_movemask_epi8(_mm_cmpeq_epi8(tmpv1, rankv));
  return (bits1 << sizeof(m128)) | bits0;
#endif // __AVX2__
#elif SSTY_DBITS == 4
  const m128 maskv = _mm_set1_epi8(SSTY_RANK);
  const m128 rankv = _mm_set1_epi8(rank);
  const m128 tmpv = _mm_and_si128(_mm_load_si128((const void *)ranks), maskv);
  return (u32)_mm_movemask_epi8(_mm_cmpeq_epi8(tmpv, rankv));
#endif // SSTY_DBITS
#else // __x86_64__
  u32 bits = 0;
  for (u32 i = 0; i < SSTY_DIST; i++)
    if ((ranks[i] & SSTY_RANK) == rank)
      bits |= (1u << i);
  return bits;
#endif // __x86_64__
}

  static u32
ssty_ranks_count(const u8 * const ranks, const u32 nr, const u8 rank)
{
#if defined(__x86_64__)
  const u32 mask = ssty_ranks_mask(ranks, rank) & (((u32)(1lu << nr)) - 1u);
  return (u32)__builtin_popcount(mask);
#else
  // TODO: aarch64 SIMD
  u32 c = 0;
  for (u32 i = 0; i < nr; i++)
    if ((ranks[i] & SSTY_RANK) == rank)
      c++;
  return c;
#endif
}
// }}} ssty

// mssty {{{
struct mssty_iter {
  // ssty status
  u32 kidx; // invalid if >= ssty->nkidx
  u32 valid_bm;
  const struct sst_ptr * seek_ptrs;
  struct msst * msst;
  struct ssty * ssty;
  // iters
  struct sst_iter iters[MSST_NWAY];
};

  static bool
mssty_open_y_at(const int dirfd, struct msst * const msst)
{
  debug_assert(msst->ssty == NULL);
  struct ssty * const ssty = ssty_open_at(dirfd, msst->seq, msst->nway);
  msst->ssty = ssty;
  return ssty != NULL;
}

  bool
mssty_open_y(const char * const dirname, struct msst * const msst)
{
  debug_assert(msst->ssty == NULL);
  struct ssty * const ssty = ssty_open(dirname, msst->seq, msst->nway);
  msst->ssty = ssty;
  return ssty != NULL;
}

// naming convention example: seq=123, nway=8:
// dir/12300.sstx, dir/12301.sstx, ..., dir/12307.sstx, dir/12308.ssty
  static struct msst *
mssty_open_at(const int dirfd, const u64 seq, const u32 nway)
{
  struct msst * const msst = msstx_open_at(dirfd, seq, nway);
  if (msst == NULL)
    return NULL;

  if (!mssty_open_y_at(dirfd, msst)) {
    msstx_destroy(msst);
    return NULL;
  }

  return msst;
}

  struct msst *
mssty_open(const char * const dirname, const u64 seq, const u32 nway)
{
  const int dirfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dirfd < 0)
    return NULL;

  struct msst * const msst = mssty_open_at(dirfd, seq, nway);
  close(dirfd);
  return msst;
}

  static void
mssty_destroy_lazy(struct msst * const msst)
{
  ssty_destroy(msst->ssty);
  for (u32 i = 0; i < msst->nway; i++)
    sst_deinit_lazy(&(msst->ssts[i]));
  free(msst);
}

  void
mssty_destroy(struct msst * const msst)
{
  ssty_destroy(msst->ssty);
  msst->ssty = NULL;
  msstx_destroy(msst);
}

  void
mssty_fprint(struct msst * const msst, FILE * const fout)
{
  const u32 nway = msst->nway;
  fprintf(fout, "%s nway %u\n", __func__, nway);
  ssty_fprint(msst->ssty, fout);
  for (u32 i = 0; i < nway; i++)
    sst_fprint(&(msst->ssts[i]), fout);
}

  static void
mssty_iter_init(struct mssty_iter * const iter, struct msst * const msst)
{
  iter->msst = msst;
  iter->ssty = msst->ssty;
  iter->valid_bm = 0;
  const u32 nway = iter->ssty->nway;
  for (u32 i = 0; i < nway; i++)
    sst_iter_init(&(iter->iters[i]), &(msst->ssts[i]), i);
}

  void
mssty_iter_park(struct mssty_iter * const iter)
{
  u32 bits = iter->valid_bm;
  while (bits) {
    const u32 i = (u32)__builtin_ctz(bits);
    sst_iter_park(&(iter->iters[i]));
    bits ^= (1u << i);
  }
}

// internal: invalidate the iter and set a new ptr
  static inline void
mssty_iter_set_ptr(struct sst_iter * const iter, struct sst_ptr ptr)
{
  sst_iter_park(iter);
  iter->ptr = ptr;
}

  static void
mssty_iter_fix_rank(struct mssty_iter * const iter, const u8 rank)
{
  debug_assert(rank < MSST_NWAY);
  if (((1u << rank) & iter->valid_bm) == 0) {
    mssty_iter_set_ptr(&(iter->iters[rank]), iter->seek_ptrs[rank]);
    iter->valid_bm |= (1u << rank);
  }
}

  void
mssty_iter_seek_null(struct mssty_iter * const iter)
{
  mssty_iter_park(iter);
  iter->valid_bm = 0;
  iter->kidx = 0;
  struct ssty * const ssty = iter->ssty;
  iter->seek_ptrs = ssty->ptrs;
  if (ssty->nkidx)
    mssty_iter_fix_rank(iter, ssty->ranks[0] & SSTY_RANK);
}

  struct mssty_ref *
mssty_ref(struct msst * const msst)
{
  struct mssty_iter * const iter = malloc(sizeof(*iter));
  if (iter == NULL)
    return NULL;

  mssty_iter_init(iter, msst);
  mssty_iter_seek_null(iter);
  return (struct mssty_ref *)iter;
}

  struct msst *
mssty_unref(struct mssty_ref * const ref)
{
  struct mssty_iter * const iter = (typeof(iter))ref;
  struct msst * const msst = iter->msst;
  mssty_iter_destroy(iter);
  return msst;
}

  static struct sst_iter *
mssty_iter_iter(struct mssty_iter * const iter)
{
  const u8 rankenc = iter->ssty->ranks[iter->kidx];
  debug_assert((rankenc & SSTY_STALE) == 0);
  return &(iter->iters[rankenc & SSTY_RANK]);
}

// can return tombstone
  struct kv *
mssty_get(struct mssty_ref * const ref, const struct kref * const key, struct kv * const out)
{
  struct mssty_iter * const iter = (typeof(iter))ref;
  mssty_iter_seek(iter, key);
  if (!mssty_iter_valid(iter))
    return NULL;

  struct sst_iter * const iter1 = mssty_iter_iter(iter);
  sst_iter_fix_kv(iter1);
  struct kv * const ret = sst_iter_match_kref(iter1, key) ? sst_iter_peek(iter1, out) : NULL;
  sst_iter_park(iter1);
  return ret;
}

// can return tombstone
  bool
mssty_probe(struct mssty_ref * const ref, const struct kref * const key)
{
  struct mssty_iter * const iter = (typeof(iter))ref;
  mssty_iter_seek(iter, key);
  if (!mssty_iter_valid(iter))
    return false;

  struct sst_iter * const iter1 = mssty_iter_iter(iter);
  sst_iter_fix_kv(iter1);
  const bool r = sst_iter_match_kref(iter1, key);
  sst_iter_park(iter1);
  return r;
}

// return NULL for tomestone
  struct kv *
mssty_get_ts(struct mssty_ref * const ref, const struct kref * const key, struct kv * const out)
{
  struct mssty_iter * const iter = (typeof(iter))ref;
  mssty_iter_seek(iter, key);
  if ((!mssty_iter_valid(iter)) || mssty_iter_ts(iter))
    return NULL;

  struct sst_iter * const iter1 = mssty_iter_iter(iter);
  sst_iter_fix_kv(iter1);
  struct kv * const ret = sst_iter_match_kref(iter1, key) ? sst_iter_peek(iter1, out) : NULL;
  sst_iter_park(iter1); // seek can only acquire iter1
  return ret;
}

// return false for tomestone
  bool
mssty_probe_ts(struct mssty_ref * const ref, const struct kref * const key)
{
  struct mssty_iter * const iter = (typeof(iter))ref;
  mssty_iter_seek(iter, key);
  if ((!mssty_iter_valid(iter)) || mssty_iter_ts(iter))
    return false;

  struct sst_iter * const iter1 = mssty_iter_iter(iter);
  sst_iter_fix_kv(iter1);
  const bool r = sst_iter_match_kref(iter1, key);
  sst_iter_park(iter1); // seek can only acquire iter1
  return r;
}

// return false for tomestone
  bool
mssty_get_value_ts(struct mssty_ref * const ref, const struct kref * const key,
    void * const vbuf_out, u32 * const vlen_out)
{
  struct mssty_iter * const iter = (typeof(iter))ref;
  mssty_iter_seek(iter, key);
  if ((!mssty_iter_valid(iter)) || mssty_iter_ts(iter))
    return false;

  struct sst_iter * const iter1 = mssty_iter_iter(iter);
  sst_iter_fix_kv(iter1);
  const bool r = sst_iter_match_kref(iter1, key);
  if (r) {
    memcpy(vbuf_out, iter1->kvdata, iter1->vlen);
    *vlen_out = iter1->vlen;
  }
  sst_iter_park(iter1); // seek can only acquire iter1
  return r;
}

  struct mssty_iter *
mssty_iter_create(struct mssty_ref * const ref)
{
  struct mssty_iter * const iter0 = (typeof(iter0))ref;
  struct mssty_iter * const iter = malloc(sizeof(*iter));
  if (iter == NULL)
    return NULL;

  mssty_iter_init(iter, iter0->msst);
  iter->kidx = iter->ssty->nkidx;
  return iter;
}

  inline bool
mssty_iter_valid(struct mssty_iter * const iter)
{
  return iter->kidx < iter->ssty->nkidx;
}

// internal: skip the sst_iter at rank (< nway)
  static inline void
mssty_iter_skip_rank(struct mssty_iter * const iter, const u32 nr, const u8 rank)
{
  debug_assert(rank < MSST_NWAY);
  sst_iter_skip(&(iter->iters[rank]), nr);
}

  static inline u32
mssty_search_index(const struct ssty * const ssty, const struct kref * const key)
{
  // use two-level index
  // i2: the first 8 bytes are two u32 for [start, end) of i1 (plr)
  const u32 sidx2 = k128_search_le(ssty->mem, ssty->ioffs2, key, 8, 0, ssty->inr2);
  const u32 * const plr = (typeof(plr))(ssty->mem + ssty->ioffs2[sidx2]);
  const u32 sidx = k128_search_le(ssty->mem, ssty->ioffs, key, 0, plr[0], plr[1]);
  return sidx;
}

  static u32
mssty_iter_seek_bisect(struct mssty_iter * const iter, const struct kref * const key, const u32 aidx, u32 l, u32 r)
{
  // notes from ssty_build:
  // gaps are marked SSTY_INVALID; end of array is marked nway
  debug_assert(r <= SSTY_DIST);
  const u32 r0 = r;
  struct ssty * const ssty = iter->ssty;
  const u8 * const ranks = ssty->ranks + aidx;

  // l may point to a stale key when performing forward searching
  // search-key > key-at-l; it's safe to move forward
  while (ranks[l] & SSTY_STALE)
    l++;

  // skip stale slots and placeholders
  // no underflow because the first key of each group is not stale
  while (r && (ranks[r-1] & SSTY_STALE))
    r--;


  while (l < r) {
#ifdef MSSTY_SEEK_BISECT_OPT
    const u8 rankx = ranks[(l+r)>>1] & SSTY_RANK;
    struct sst_iter * const iterx = &(iter->iters[rankx]);
    mssty_iter_set_ptr(iterx, iter->seek_ptrs[rankx]);
    debug_assert(sst_iter_valid(iterx));
    // use 1lu << r to avoid undefined behavior of left-shift by 32
    u32 mask = ssty_ranks_mask(ranks, rankx) & (((u32)(1lu << r)) - 1u);
    debug_assert(l < SSTY_DIST);
    const u32 low = (1u << l) - 1u;
    const u32 nskip0 = __builtin_popcount(mask & low);
    if (nskip0)
      sst_iter_skip(iterx, nskip0);
    mask &= (~low); // clear the low bits
    debug_assert(mask); // have at least one bit
    do {
      sst_iter_fix_kv(iterx);
      const int cmp = sst_iter_compare_kref(iterx, key);
      const u32 m = __builtin_ctz(mask);
      debug_assert((ranks[m] & SSTY_RANK) == rankx);
      debug_assert(m < r);
      if (cmp < 0) { // shrink forward
        sst_iter_skip(iterx, 1);
        l = m + 1;
      } else if (cmp > 0) { // shrink backward
        r = m;
        break;
      } else { // match
        // must point to the non-stale version
        l = m;
        while (ranks[l] & SSTY_STALE)
          l--;
        r = m;
        break;
      }
      mask &= (mask - 1);
    } while (mask);
    sst_iter_park(iterx);
    // l may point to a stale key when performing forward searching
    // search-key > key-at-l; it's safe to move forward
    while ((l < r0) && (ranks[l] & SSTY_STALE))
      l++;
    // skip stale slots and placeholders
    // no underflow because the first key of each group is not stale
    while (r && (ranks[r-1] & SSTY_STALE))
      r--;
#else // MSSTY_SEEK_BISECT_OPT
    u32 m = (l + r) >> 1;
    // skip stale keys and move left; always compare with non-stale key
    while (ranks[m] & SSTY_STALE)
      m--;

    // compare
    debug_assert(l <= m && m < r);
    debug_assert((ranks[m] & SSTY_STALE) == 0);
    const u8 rankm = ranks[m] & SSTY_RANK;
    struct sst_iter * const iterm = &(iter->iters[rankm]);
    // set iter for random access [rankm]
    mssty_iter_set_ptr(iterm, iter->seek_ptrs[rankm]);
    const u32 nskip = ssty_ranks_count(ranks, m, rankm);
    sst_iter_skip(iterm, nskip);
    debug_assert(sst_iter_valid(iterm));
    sst_iter_fix_kv(iterm);
    const int cmp = sst_iter_compare_kref(iterm, key);
    sst_iter_park(iterm);

    if (cmp < 0) { // shrink forward
      l = m + 1;
      // skip stale keys
      while ((l < r0) && (ranks[l] & SSTY_STALE))
        l++;
    } else if (cmp > 0) { // shrink backward
      r = m;
    } else { // cmp == 0; done
      l = m;
      r = m;
    }
#endif // MSSTY_SEEK_BISECT_OPT
  }
  return l;
}

// perform seek in the group of kidx0 (group_id = kidx0 / dist)
// kidx0 may point to a stale key
// bisect between kidx0 and the last element
  static void
mssty_iter_seek_local(struct mssty_iter * const iter, const struct kref * const key, const u32 kidx0)
{
  debug_assert(iter->valid_bm == 0);
  // first key's index of the target group
  struct ssty * const ssty = iter->ssty;
  const u32 aidx = kidx0 >> SSTY_DBITS << SSTY_DBITS;
  // <= dist
  const u32 l0 = kidx0 - aidx;
  const u32 r0 = (aidx + SSTY_DIST) > ssty->nkidx ? (ssty->nkidx - aidx) : SSTY_DIST;
  const u32 goff = mssty_iter_seek_bisect(iter, key, aidx, l0, r0);

  debug_assert(iter->valid_bm == 0);
  // skip keys
  if (goff) {
    if (goff < SSTY_DIST) {
      const u8 * const ranks = ssty->ranks + aidx;
      for (u32 i = 0; i < ssty->nway; i++) {
        const u32 nskip = ssty_ranks_count(ranks, goff, i);
        if (nskip) {
          mssty_iter_fix_rank(iter, i);
          mssty_iter_skip_rank(iter, nskip, i);
        }
      }
    } else { // shortcut to the next group
      debug_assert(goff == SSTY_DIST);
      iter->seek_ptrs += ssty->nway;
    }
  } // else: goff == 0; do nothing
  iter->kidx = aidx + goff;
  // the current key must be the one unless >= nkidx
  if (unlikely(iter->kidx >= ssty->nkidx))
    return;

  const u8 rank = ssty->ranks[iter->kidx] & SSTY_RANK; // rank starts with 0
  debug_assert(rank < ssty->nway);
  mssty_iter_fix_rank(iter, rank);
}

  void
mssty_iter_seek(struct mssty_iter * const iter, const struct kref * const key)
{
  struct ssty * const ssty = iter->ssty;
  mssty_iter_park(iter);
  iter->valid_bm = 0;
  const u32 sidx = mssty_search_index(ssty, key);
  if (unlikely(sidx >= ssty->inr)) { // invalid
    iter->kidx = ssty->nkidx;
    return;
  }
  iter->seek_ptrs = &(ssty->ptrs[sidx * ssty->nway]);
  const u32 kidx0 = sidx << SSTY_DBITS;
  mssty_iter_seek_local(iter, key, kidx0);
}

  static u32
mssty_iter_seek_index_near(struct ssty * const ssty, const struct kref * const key, u32 l)
{
  while ((l < ssty->nkidx) && (ssty->ranks[l] & SSTY_STALE))
    l++;
  if (l == ssty->nkidx)
    return l;

  // linear scan
  u32 g = l >> SSTY_DBITS;
  u32 r = (g + 1) << SSTY_DBITS;
  while (r < ssty->nkidx) {
    const int cmp = kref_k128_compare(key, ssty->mem + ssty->ioffs[g + 1]);
    if (cmp < 0) {
      break;
    } else {
      g++;
      l = r;
      r += SSTY_DIST;
    }
  }
  debug_assert(l < ssty->nkidx);
  return l;
}

  static void
mssty_iter_seek_local_near(struct mssty_iter * const iter, const struct kref * const key, const u32 l)
{
  struct ssty * const ssty = iter->ssty;
  // now search in l's group; l must be a non-stale key
  const u32 g = l >> SSTY_DBITS;
  if (g == (iter->kidx >> SSTY_DBITS)) { // stay in the same group; reuse the valid iter
    while (iter->kidx < l)
      mssty_iter_skip(iter, 1);
    debug_assert(iter->kidx == l);
  } else { // switch group
    debug_assert((l & (SSTY_DIST-1)) == 0);
    mssty_iter_park(iter);
    iter->valid_bm = 0;
    iter->seek_ptrs = &(ssty->ptrs[(l >> SSTY_DBITS) * ssty->nway]);
    iter->kidx = l;
  }

  do {
    const u8 rank = ssty->ranks[iter->kidx] & SSTY_RANK; // rank starts with 0
    debug_assert(rank < ssty->nway);
    mssty_iter_fix_rank(iter, rank);
    struct sst_iter * const iter1 = &(iter->iters[rank]);
    sst_iter_fix_kv(iter1);
    if (sst_iter_compare_kref(iter1, key) >= 0)
      return;
    mssty_iter_skip(iter, 1);
  } while (mssty_iter_valid(iter));
}

// the target key must >= the current key under the iter
// the current iter can point to a stale key or deleted key
  void
mssty_iter_seek_near(struct mssty_iter * const iter, const struct kref * const key, const bool bsearch_keys)
{
  debug_assert(mssty_iter_valid(iter));
  struct ssty * const ssty = iter->ssty;

  // first test if key < iter
  const u8 * const ranks = ssty->ranks;
  const u8 rank0 = ranks[iter->kidx];
  struct sst_iter * const iter0 = &(iter->iters[rank0 & SSTY_RANK]);
  sst_iter_fix_kv(iter0);
  // return without any change
  if (sst_iter_compare_kref(iter0, key) >= 0)
    return;

  // seek_index does not affect the iter
  const u32 l = mssty_iter_seek_index_near(ssty, key, iter->kidx+1);
  if (l == ssty->nkidx) { // invalid
    mssty_iter_park(iter);
    iter->kidx = ssty->nkidx;
    return;
  }

  if (bsearch_keys) { // reset iter and use seek_local
    mssty_iter_park(iter);
    iter->valid_bm = 0;
    iter->seek_ptrs = &(ssty->ptrs[(l >> SSTY_DBITS) * ssty->nway]);
    mssty_iter_seek_local(iter, key, l);
  } else { // linear scan using the valid iter
    mssty_iter_seek_local_near(iter, key, l);
  }
}

// peek non-stale keys
  struct kv *
mssty_iter_peek(struct mssty_iter * const iter, struct kv * const out)
{
  if (!mssty_iter_valid(iter))
    return NULL;
  const u8 rank = iter->ssty->ranks[iter->kidx]; // rank starts with 0
  debug_assert((rank & SSTY_STALE) == 0);
  return sst_iter_peek(&(iter->iters[rank & SSTY_RANK]), out);
}

// kvref non-stale keys
  bool
mssty_iter_kref(struct mssty_iter * const iter, struct kref * const kref)
{
  if (!mssty_iter_valid(iter))
    return false;

  const u8 rank = iter->ssty->ranks[iter->kidx]; // rank starts with 0
  debug_assert((rank & SSTY_STALE) == 0);
  return sst_iter_kref(&(iter->iters[rank & SSTY_RANK]), kref);
}

// kvref non-stale keys
  bool
mssty_iter_kvref(struct mssty_iter * const iter, struct kvref * const kvref)
{
  if (!mssty_iter_valid(iter))
    return false;

  const u8 rank = iter->ssty->ranks[iter->kidx]; // rank starts with 0
  debug_assert((rank & SSTY_STALE) == 0);
  return sst_iter_kvref(&(iter->iters[rank & SSTY_RANK]), kvref);
}

  inline u64
mssty_iter_retain(struct mssty_iter * const iter)
{
  const u8 rank = iter->ssty->ranks[iter->kidx] & SSTY_RANK; // rank starts with 0
  return sst_iter_retain(&(iter->iters[rank]));
}

  inline void
mssty_iter_release(struct mssty_iter * const iter, const u64 opaque)
{
  sst_blk_release(iter->msst->rc, (const u8 *)opaque);
}

// non-stale keys
  void
mssty_iter_skip(struct mssty_iter * const iter, const u32 nr)
{
  if (!mssty_iter_valid(iter))
    return;
  struct ssty * const ssty = iter->ssty;
  u32 rank = ssty->ranks[iter->kidx] & SSTY_RANK;
  debug_assert(rank < ssty->nway);

  for (u32 i = 0; i < nr; i++) {
    mssty_iter_skip_rank(iter, 1, rank);
    iter->kidx++;

    // skip stale keys or gaps
    while (ssty->ranks[iter->kidx] & SSTY_STALE) { // stop when kidx >= nkidx
      rank = ssty->ranks[iter->kidx] & SSTY_RANK;
      iter->kidx++;
      if (rank < ssty->nway) { // not gap
        mssty_iter_fix_rank(iter, rank);
        mssty_iter_skip_rank(iter, 1, rank);
      }
    }
    if (!mssty_iter_valid(iter))
      return;
    // still valid
    rank = ssty->ranks[iter->kidx] & SSTY_RANK;
    debug_assert(rank < ssty->nway);
    mssty_iter_fix_rank(iter, rank);
  }
}

  struct kv *
mssty_iter_next(struct mssty_iter * const iter, struct kv * const out)
{
  struct kv * const ret = mssty_iter_peek(iter, out);
  mssty_iter_skip(iter, 1);
  return ret;
}

  void
mssty_iter_destroy(struct mssty_iter * const iter)
{
  mssty_iter_park(iter);
  free(iter);
}

// ts iter: ignore a key if its newest version is a tombstone
  bool
mssty_iter_ts(struct mssty_iter * const iter)
{
  return (iter->ssty->ranks[iter->kidx] & SSTY_TOMBSTONE) != 0;
}

// hide tomestones
  void
mssty_iter_seek_ts(struct mssty_iter * const iter, const struct kref * const key)
{
  mssty_iter_seek(iter, key);
  while (mssty_iter_valid(iter) && mssty_iter_ts(iter))
    mssty_iter_skip(iter, 1);
}

// skip nr valid keys (tomestones are transparent)
  void
mssty_iter_skip_ts(struct mssty_iter * const iter, const u32 nr)
{
  for (u32 i = 0; i < nr; i++) {
    if (!mssty_iter_valid(iter))
      return;
    mssty_iter_skip(iter, 1);
    while (mssty_iter_valid(iter) && mssty_iter_ts(iter))
      mssty_iter_skip(iter, 1);
  }
}

  struct kv *
mssty_iter_next_ts(struct mssty_iter * const iter, struct kv * const out)
{
  struct kv * const ret = mssty_iter_peek(iter, out);
  mssty_iter_skip_ts(iter, 1);
  return ret;
}
// end of ts iter

// dup iter: return all versions, including old keys and tombstones
  struct kv *
mssty_iter_peek_dup(struct mssty_iter * const iter, struct kv * const out)
{
  if (!mssty_iter_valid(iter))
    return NULL;
  const u8 rank = iter->ssty->ranks[iter->kidx] & SSTY_RANK; // rank starts with 0
  debug_assert(rank < iter->ssty->nway);
  return sst_iter_peek(&(iter->iters[rank]), out);
}

  void
mssty_iter_skip_dup(struct mssty_iter * const iter, const u32 nr)
{
  if (!mssty_iter_valid(iter))
    return;
  struct ssty * const ssty = iter->ssty;
  u32 rank = ssty->ranks[iter->kidx] & SSTY_RANK;
  debug_assert(rank < ssty->nway);

  for (u32 i = 0; i < nr; i++) {
    mssty_iter_skip_rank(iter, 1, rank);
    iter->kidx++;

    // skip gaps
    while (ssty->ranks[iter->kidx] == SSTY_INVALID)
      iter->kidx++;

    if (!mssty_iter_valid(iter))
      return;

    // still valid
    rank = ssty->ranks[iter->kidx] & SSTY_RANK;
    mssty_iter_fix_rank(iter, rank);
  }
}

  struct kv *
mssty_iter_next_dup(struct mssty_iter * const iter, struct kv * const out)
{
  struct kv * const ret = mssty_iter_peek_dup(iter, out);
  mssty_iter_skip_dup(iter, 1);
  return ret;
}

  bool
mssty_iter_kref_dup(struct mssty_iter * const iter, struct kref * const kref)
{
  if (!mssty_iter_valid(iter))
    return false;

  const u8 rank = iter->ssty->ranks[iter->kidx] & SSTY_RANK; // rank starts with 0
  return sst_iter_kref(&(iter->iters[rank]), kref);
}

  bool
mssty_iter_kvref_dup(struct mssty_iter * const iter, struct kvref * const kvref)
{
  if (!mssty_iter_valid(iter))
    return false;

  const u8 rank = iter->ssty->ranks[iter->kidx] & SSTY_RANK; // rank starts with 0
  return sst_iter_kvref(&(iter->iters[rank]), kvref);
}
// end of dup iter

  struct kv *
mssty_first(struct msst * const msst, struct kv * const out)
{
  if (msst->ssty->nkidx == 0)
    return NULL;
  struct sst_iter iter1;
  iter1.rank = msst->ssty->ranks[0] & SSTY_RANK;
  iter1.sst = &(msst->ssts[iter1.rank]);
  iter1.ptr.blkid = 0;
  iter1.ptr.keyid = 0;
  iter1.kvdata = NULL; // init to NULL
  struct kv * const ret = sst_iter_peek(&iter1, out);
  sst_iter_park(&iter1);
  return ret;
}

  struct kv *
mssty_last(struct msst * const msst, struct kv * const out)
{
  const u32 nkidx = msst->ssty->nkidx;
  if (nkidx == 0)
    return NULL;
  struct sst_iter iter1;
  const u8 rank = msst->ssty->ranks[nkidx-1] & SSTY_RANK;
  struct sst * const sst = &(msst->ssts[rank]);
  iter1.sst = sst;
  debug_assert(sst->nblks); // the sst at this rank must be non-empty
  u32 blkid = sst->nblks-1;
  // seek to the head if it's a jumbo block
  while (sst->bms[blkid].nblks == 0)
    blkid--;
  debug_assert((blkid + sst->bms[blkid].nblks) == sst->nblks);
  iter1.ptr.blkid = blkid;
  iter1.ptr.keyid = sst->bms[blkid].nkeys-1;
  iter1.kvdata = NULL; // init to NULL
  struct kv * const ret = sst_iter_peek(&iter1, out);
  sst_iter_park(&iter1);
  return ret;
}

  void
mssty_dump(struct msst * const msst, const char * const fn)
{
  const int fd = open(fn, O_WRONLY|O_CREAT|O_TRUNC, 00644);
  debug_assert(fd >= 0);
  void * const ref = mssty_ref(msst);
  struct mssty_iter * const iter = mssty_iter_create(ref);
  struct ssty * const ssty = msst->ssty;
  const struct ssty_meta * const meta = ssty->meta;
  dprintf(fd, "mssty seq%lu nway %u nkidx %u inr %u inr2 %u valid %u uniqx ",
      msst->seq, ssty->nway, ssty->nkidx, ssty->inr, ssty->inr2, meta->valid);
  for (u32 i = 0; i < ssty->nway; i++)
    dprintf(fd, "%u%c", meta->uniqx[i], (i == (ssty->nway-1)) ? '\n' : ' ');

  // print i2 keys
  const u32 n2 = ssty->inr2;
  for (u32 i = 0; i < n2; i++) {
    const u32 ioff2 = ssty->ioffs2[i];
    const u32 * const e2 = (typeof(e2))(ssty->mem + ioff2);
    const u8 * const a2 = (typeof(a2))(ssty->mem + ioff2 + sizeof(u32) + sizeof(u32));
    u32 klen = 0;
    const u8 * const keyptr = vi128_decode_u32(a2, &klen);
    dprintf(fd, "i2 %6u  %6u %6u %.*s (%u)\n", i, e2[0], e2[1], klen, keyptr, klen);
  }

  struct kvref kvref;
  u32 n = 0;
  mssty_iter_seek_null(iter);
  while (mssty_iter_kvref_dup(iter, &kvref)) { // dump all the keys
    const u8 rank = ssty->ranks[iter->kidx];
    const bool stale = (rank & SSTY_STALE) != 0;
    const bool ts = (rank & SSTY_TOMBSTONE) != 0; // first X: ssty says it's a TS
    const bool ts2 = (kvref.hdr.vlen & SST_VLEN_TS) != 0; // second X: the KV is really a TS
    debug_assert(ts == ts2);
    // count kidx(anchor) !DD rank key
    dprintf(fd, "%7u %7u%c %c%c%c%x %.*s (%u,%u)\n", n, iter->kidx, (iter->kidx % SSTY_DIST) ? ' ' : '*',
        stale ? '!' : ' ', ts ? 'X' : ' ', ts2 ? 'X' : ' ', rank & SSTY_RANK,
        kvref.hdr.klen, kvref.kptr, kvref.hdr.klen, kvref.hdr.vlen & SST_VLEN_MASK);
    mssty_iter_skip_dup(iter, 1);
    n++;
  }
  mssty_iter_destroy(iter);
  mssty_unref(ref);
  fsync(fd);
  close(fd);
}
// }}} mssty

// ssty_build {{{

// bi {{{
struct ssty_build_info {
  struct msst * x1; // input: target tables
  struct msst * y0; // input: the old mssty or NULL

  // allocated by the main function; filled by the sort function
  u8 * ranks; // output: run selectors
  struct sst_ptr * ptrs; // output: cursor positions
  struct kv ** anchors; // output: anchors

  int dirfd; // input
  u32 way0;  // input: number of ssts to reuse in y0
  u32 nkidx; // output: maximum key index
  u32 nsecs; // output: number of groups
  u32 valid; // output: number of valid keys
  u32 uniqx[MSST_NWAY]; // output: uniq non-stale keys at each level
};
// }}} bi

// sstc_iter {{{
struct sstc_iter {
  struct sst_iter iter;
  u8 * buffer;
  size_t bufsz;
  const u8 * cptr;
  const u8 * ckeysptr;
  size_t ckeyssz;
};

  static void
sstc_sync_kv(struct sstc_iter * const iter)
{
  const u8 * ptr = iter->cptr;
  u32 plen = 0, slen = 0;
  ptr = vi128_decode_u32(ptr, &plen);
  ptr = vi128_decode_u32(ptr, &slen);
  const bool ts = *ptr++;
  if ((plen + slen) > iter->bufsz) {
    iter->bufsz = bits_p2_up_u32(plen + slen + 256);
    iter->buffer = realloc(iter->buffer, iter->bufsz);
    debug_assert(iter->buffer);
  }
  memcpy(iter->buffer + plen, ptr, slen);

  iter->cptr = ptr + slen;

  struct sst_iter * const iter0 = &iter->iter;
  iter0->klen = plen + slen;
  iter0->vlen = ts ? SST_VLEN_TS : 0;
  iter0->kvdata = iter->buffer;
}

  static inline void
sstc_iter_init(struct sstc_iter * const iter, struct sst * const sst, const u32 rank)
{
  sst_iter_init(&iter->iter, sst, rank);
  const struct sst_meta * const meta = sst_meta(sst);

  if (sst->nblks && meta->ckeyssz) {
    iter->bufsz = 256; // buffer size
    iter->buffer = malloc(iter->bufsz);

    const u8 * const ckeys = sst->mem + meta->ckeysoff;
    iter->ckeysptr = ckeys;
    iter->ckeyssz = meta->ckeyssz;
    posix_madvise((void *)ckeys, meta->ckeyssz, POSIX_MADV_WILLNEED);
    iter->cptr = ckeys;

    struct sst_iter * const iter0 = &iter->iter;
    iter0->ptr.blkid = 0;
    iter0->ptr.keyid = 0;

    sstc_sync_kv(iter);
  }
}

  static struct sstc_iter *
sstc_iter_create(struct sst * const sst)
{
  struct sstc_iter * const iter = calloc(1, sizeof(*iter));
  if (iter == NULL)
    return NULL;
  sstc_iter_init(iter, sst, 0);
  return iter;
}

  static inline bool
sstc_iter_valid(struct sstc_iter * const iter)
{
  return sst_iter_valid(&iter->iter);
}

  static inline void
sstc_iter_seek(struct sstc_iter * const iter, const struct kref * const key)
{
  debug_assert(key == NULL || key == kref_null());
  (void)iter;
  (void)key;
}

  static inline void
sstc_iter_skip1(struct sstc_iter * const iter)
{
  struct sst_iter * const iter0 = &iter->iter;
  iter0->kvdata = NULL; // it points to the sstc buffer; just set to NULL
  sst_iter_skip(iter0, 1);
  if (sst_iter_valid(iter0))
    sstc_sync_kv(iter);
}

  static void
sstc_iter_skip(struct sstc_iter * const iter, const u32 nr)
{
  for (u32 i = 0; i < nr; i++)
    sstc_iter_skip1(iter);
}

  static bool
sstc_iter_kref(struct sstc_iter * const iter, struct kref * const kref)
{
  if (!sstc_iter_valid(iter))
    return false;

  kref_ref_raw(kref, iter->buffer, iter->iter.klen); // no hash32
  return true;
}

  static bool
sstc_iter_kvref(struct sstc_iter * const iter, struct kvref * const kvref)
{
  if (!sstc_iter_valid(iter))
    return false;

  struct sst_iter * const iter0 = &iter->iter;
  kvref->hdr.klen = iter0->klen;
  kvref->hdr.vlen = iter0->vlen;
  kvref->hdr.hash = 0;
  kvref->kptr = iter->buffer;
  kvref->vptr = NULL; // no value
  return true;
}

  static bool
sstc_iter_ts(struct sstc_iter * const iter)
{
  return sstc_iter_valid(iter) && (iter->iter.vlen == SST_VLEN_TS);
}

  static int
sstc_iter_compare(struct sstc_iter * const iter1, struct sstc_iter * const iter2)
{
  debug_assert(sstc_iter_valid(iter1) && sstc_iter_valid(iter2));
  // both are valid
  struct kref kref1, kref2;
  kref_ref_raw(&kref1, iter1->buffer, iter1->iter.klen); // no hash32
  kref_ref_raw(&kref2, iter2->buffer, iter2->iter.klen); // no hash32
  return kref_compare(&kref1, &kref2);
}

  static void
sstc_iter_destroy(struct sstc_iter * const iter)
{
  if (iter->ckeysptr && iter->ckeyssz)
    posix_madvise((void *)iter->ckeysptr, iter->ckeyssz, POSIX_MADV_DONTNEED);

  free(iter->buffer);
  free(iter);
}

static const struct kvmap_api kvmap_api_sstc = {
  .ordered = true,
  .readonly = true,
  .unique = true,
  .iter_create = (void *)sstc_iter_create,
  .iter_seek = (void *)sstc_iter_seek,
  .iter_valid = (void *)sstc_iter_valid,
  .iter_kref = (void *)sstc_iter_kref,
  .iter_kvref = (void *)sstc_iter_kvref,
  .iter_skip = (void *)sstc_iter_skip,
  .iter_destroy = (void *)sstc_iter_destroy,
};

  static bool
msstb_use_ckeys(struct msst * const x1)
{
  bool use_ckeys = true;
  for (u32 i = 0; i < x1->nway; i++) {
    const struct sst_meta * const meta = sst_meta(&(x1->ssts[i]));
    if ((meta->totkv != 0) && (meta->ckeyssz == 0)) {
      use_ckeys = false;
      break;
    }
  }
  return use_ckeys;
}
// }}} sstc_iter

// msstb {{{
struct msstb {
  u32 rankenc; // the current rank
  u32 idx; // index on the full sorted view
  u32 nway; // the target nway
  u32 way0; // <= y0->nway, the tables to reuse in the new ssty
  // iters[way1] is the current sst iter
  u32 way1; // not done as long as (way1 < nway)
  u32 nkidx; // a copy of y0->ssty->nkidx
  u32 kidx0; // index on ranks (of y0) for bc

  bool bsearch_anchors; // binary search anchors vs. linear scan anchors
  bool bsearch_keys; // binary search keys vs. linear scan keys in a group
  bool dup;   // the new key == old key; msstb2_sync1 can set dup to true
  bool stale;   // the old key should be set as stale

  const u8 * ranks; // shortcut to y0->ssty->ranks

  struct msst * x1; // the input msstx
  struct msst * y0; // the old mssty
  struct miter * miter;

  struct kv * tmp0; // for bc
  struct kv * tmp1; // for bc
  struct sst_iter older;
  struct sst_iter newer;

  // iterb will be moved ahead of iter0 (iterb >= iter0)
  // then iter0 will be used to encode the old kvs until they meet again
  struct mssty_iter iterb; // for binary search only
  struct mssty_iter iter0; // for linear iteration and encoding
  union {
    struct sst_iter * iters[MSST_NWAY]; // for new tables
    struct sstc_iter * citers[MSST_NWAY]; // for bc
  };
};

struct msstb_api {
  struct msstb * (*create)  (struct msst * const x1, struct msst * const y0, const u32 way0);
  void (*ptrs)              (struct msstb * const b, struct sst_ptr * const ptrs_out);
  struct kv * (*anchor)     (struct msstb * const b);
  void (*skip1)             (struct msstb * const b);
  void (*destroy)           (struct msstb * const b);
};

  static inline bool
msstb_valid(struct msstb * const b)
{
  return b->rankenc != UINT32_MAX;
}

  static inline u32
msstb_rankenc(struct msstb * const b)
{
  return (u8)b->rankenc;
}
// }}} msstb

// msstbm {{{
  static void
msstbm_sync_rank(struct msstb * const b)
{
  if (!miter_valid(b->miter)) {
    b->rankenc = UINT32_MAX;
    return;
  }

  const u32 rank = miter_rank(b->miter);
  debug_assert(rank < MSST_NWAY);
  struct kvref cref;
  miter_kvref(b->miter, &cref);
  const bool stale = (cref.hdr.klen == b->tmp1->klen) && (!memcmp(cref.kptr, b->tmp1->kv, b->tmp1->klen));
  const bool ts = cref.hdr.vlen == SST_VLEN_TS;
  b->rankenc = rank | (stale ? SSTY_STALE : 0u) | (ts ? SSTY_TOMBSTONE : 0u);

  if (!stale) {
    struct kv * const xchg = b->tmp0;
    b->tmp0 = b->tmp1;
    b->tmp1 = xchg;
    kvref_dup2_key(&cref, b->tmp1);
  }
}

  static struct kv *
msstbm_anchor(struct msstb * const b)
{
  const u32 alen = b->idx ? (kv_key_lcp(b->tmp0, b->tmp1)+1) : 0;
  debug_assert(alen <= b->tmp1->klen);
  struct kv * const anchor = kv_create(b->tmp1->kv, alen, NULL, 0); // key only
  return anchor;
}

  static void
msstbm_ptrs(struct msstb * const b, struct sst_ptr * const ptrs)
{
  for (u32 i = 0; i < b->nway; i++)
    ptrs[i] = b->iters[i]->ptr;
}

  static void
msstbm_skip1(struct msstb * const b)
{
  miter_skip(b->miter, 1);
  b->idx++;
  msstbm_sync_rank(b);
}

  static struct msstb *
msstbm_create(struct msst * const x1, struct msst * const y0, const u32 way0)
{
  (void)y0;
  (void)way0;
  struct msstb * const b = calloc(1, sizeof(*b));
  b->nway = x1->nway;
  b->idx = 0;
  b->tmp0 = malloc(sizeof(*b->tmp0) + SST_MAX_KVSZ);
  b->tmp1 = malloc(sizeof(*b->tmp1) + SST_MAX_KVSZ);
  const bool use_ckeys = msstb_use_ckeys(x1);
  const struct kvmap_api * const api_build = use_ckeys ? &kvmap_api_sstc : &kvmap_api_sst;
  struct miter * const miter = miter_create();
  b->miter = miter;
  for (u32 i = 0; i < b->nway; i++)
    b->iters[i] = miter_add(miter, api_build, &x1->ssts[i]);

  miter_seek(miter, kref_null());
  if (miter_valid(miter)) {
    struct kvref kvref;
    miter_kvref(miter, &kvref);
    kvref_dup2_key(&kvref, b->tmp1);
    b->tmp1->klen = !b->tmp1->klen; // let the first stale == false
  }
  msstbm_sync_rank(b);
  return b;
}

  static void
msstbm_destroy(struct msstb * const b)
{
  free(b->tmp0);
  free(b->tmp1);
  miter_destroy(b->miter);
  free(b);
}

static const struct msstb_api msstb_api_miter = {
  .create = msstbm_create,
  .ptrs = msstbm_ptrs,
  .anchor = msstbm_anchor,
  .skip1 = msstbm_skip1,
  .destroy = msstbm_destroy,
};
// }}} msstbm

// msstb2 {{{
  static void
msstb2_iter(struct msstb * const b, const u8 rank, struct sst_iter * const out)
{
  debug_assert(rank < b->nway);
  struct sst_iter * const iter = (rank < b->way0) ? &(b->iter0.iters[rank]) : b->iters[rank];
  debug_assert(iter->rank == rank);
  out->sst = iter->sst;
  out->rank = rank;
  out->ptr = iter->ptr;
  // klen and vlen are ignored
  out->kvdata = NULL;
}

  static void
msstb2_sync_rank(struct msstb * const b)
{
  const bool valid = (b->iter0.kidx < b->nkidx) || (b->way1 < b->nway);
  if (!valid) {
    b->rankenc = UINT32_MAX;
    return;
  }

  if (b->iter0.kidx < b->iterb.kidx) { // use the old
    b->rankenc = b->ranks[b->iter0.kidx] | (b->stale ? SSTY_STALE : 0);
  } else { // use the new
    debug_assert(b->iter0.kidx == b->iterb.kidx);
    const u8 ts = (b->iters[b->way1]->vlen == SST_VLEN_TS) ? SSTY_TOMBSTONE : 0;
    b->rankenc = b->way1 | ts;
  }

  if ((b->rankenc & SSTY_STALE) == 0) {
    b->older = b->newer;
    msstb2_iter(b, b->rankenc & SSTY_RANK, &b->newer);
  }
}

// update iterb to mark the merge point for the current sst_iter
  static void
msstb2_sync_mp(struct msstb * const b)
{
  struct mssty_iter * const iterb = &(b->iterb);
  do {
    if (b->way1 == b->nway) {
      mssty_iter_park(iterb); // no longer needed
      iterb->kidx = b->nkidx;
      return;
    } else if (sst_iter_valid(b->iters[b->way1])) {
      // use this way1 and iter1
      break;
    }
    b->way1++;
  } while (true);
  struct sst_iter * const iter1 = b->iters[b->way1];

  if (iterb->kidx == b->nkidx) { // !mssty_iter_valid(iterb)
    sst_iter_fix_kv(iter1); // msstb2_sync_rank needs the vlen
    return;
  }
  // seek on iterb; now iter1 is valid
  struct kref kref1;
  sst_iter_kref(iter1, &kref1);
  // let iterb point to the merge point
  mssty_iter_seek_near(iterb, &kref1, b->bsearch_keys);

  // skip placeholders and high-rank keys
  while ((iterb->kidx < b->nkidx) && ((b->ranks[iterb->kidx] & SSTY_RANK) >= b->way0))
    mssty_iter_skip_dup(iterb, 1);

  struct kref kref0; // the current
  if (mssty_iter_kref_dup(iterb, &kref0)) // mssty_iter is also valid
    b->dup = kref_match(&kref1, &kref0); // may find a dup
}

  static struct kv *
msstb2_anchor(struct msstb * const b)
{
  struct kref tmp0 = {};
  struct kref tmp1 = {};
  sst_iter_kref(&b->older, &tmp0);
  sst_iter_kref(&b->newer, &tmp1);
  const u32 alen = b->idx ? (kref_lcp(&tmp0, &tmp1)+1) : 0;
  debug_assert(alen <= tmp1.len);
  struct kv * const anchor = kv_create(tmp1.ptr, alen, NULL, 0); // key only
  sst_iter_park(&b->older);
  sst_iter_park(&b->newer);
  return anchor;
}

  static void
msstb2_ptrs(struct msstb * const b, struct sst_ptr * const ptrs)
{
  struct mssty_iter * const iter0 = &(b->iter0);
  for (u32 i = 0; i < b->way0; i++)
    ptrs[i] = iter0->iters[i].ptr;

  for (u32 i = b->way0; i < b->nway; i++)
    ptrs[i] = b->iters[i]->ptr;
}

  static void
msstb2_skip1(struct msstb * const b)
{
  b->idx++;
  if (b->iter0.kidx < b->iterb.kidx) { // skip an old key
    b->stale = false; // stale is one shot only
    do {
      mssty_iter_skip_dup(&(b->iter0), 1);
    } while ((b->iter0.kidx < b->nkidx) && ((b->ranks[b->iter0.kidx] & SSTY_RANK) >= b->way0));
    debug_assert(b->iter0.kidx <= b->iterb.kidx);
  } else { // skip a new key
    debug_assert(b->iter0.kidx == b->iterb.kidx);
    sst_iter_skip(b->iters[b->way1], 1);
    b->stale = b->dup; // force the next key to be stale
    b->dup = false; // dup is one shot only
    msstb2_sync_mp(b); // update iterb (and way1)
  }
  msstb2_sync_rank(b);
}

  static struct msstb *
msstb2_create_common(struct msst * const x1, struct msst * const y0, const u32 way0)
{
  debug_assert(x1);
  struct msstb * const b = calloc(1, sizeof(*b));
  if (!b)
    return NULL;

  b->x1 = x1;
  b->y0 = y0;
  b->way0 = way0;
  b->way1 = way0; // new tables start with way0
  b->nway = x1->nway; // the target nway
  b->newer.ptr.keyid = UINT16_MAX;

  if (way0) {
    debug_assert(y0);
    b->nkidx = y0->ssty->nkidx; // shortcut
    b->ranks = y0->ssty->ranks; // shortcut
  }
  return b;
}

  static struct msstb *
msstb2_create(struct msst * const x1, struct msst * const y0, const u32 way0)
{
  struct msstb * const b = msstb2_create_common(x1, y0, way0);
  if (way0) {
    mssty_iter_init(&(b->iterb), y0);
    mssty_iter_seek_null(&(b->iterb));
    mssty_iter_init(&(b->iter0), y0);
    mssty_iter_seek_null(&(b->iter0));
    for (u32 i = 0; i < way0; i++)
      mssty_iter_fix_rank(&(b->iter0), i);

    // skip the first a few stale keys
    while ((b->iter0.kidx < b->nkidx) && ((b->ranks[b->iter0.kidx] & SSTY_RANK) >= b->way0))
      mssty_iter_skip_dup(&(b->iter0), 1);
  }

  u32 newcnt = 0;
  for (u32 i = way0; i < b->nway; i++) {
    b->iters[i] = sst_iter_create(&(x1->ssts[i]));
    b->iters[i]->rank = i;
    sst_iter_seek_null(b->iters[i]);
    newcnt += x1->ssts[i].totkv;
  }

  // size ratio between the old and new sorted views; old:new, 1 <= ratio
  const u32 ratio = (newcnt && (newcnt < b->nkidx)) ? (b->nkidx / newcnt) : 1;
  // compensate the linear search for locality and efficiency
  b->bsearch_keys = ratio > (SSTY_DBITS + way0);

  msstb2_sync_mp(b);
  debug_assert(b->iter0.kidx <= b->iterb.kidx);
  msstb2_sync_rank(b);
  return b;
}

  static void
msstb2_destroy(struct msstb * const b)
{
  mssty_iter_park(&(b->iterb));
  mssty_iter_park(&(b->iter0));
  for (u32 i = b->way0; i < b->nway; i++)
    sst_iter_destroy(b->iters[i]);
  free(b);
}

static const struct msstb_api msstb_api_b2 = {
  .create = msstb2_create,
  .ptrs = msstb2_ptrs,
  .anchor = msstb2_anchor,
  .skip1 = msstb2_skip1,
  .destroy = msstb2_destroy,
};
// }}} msstb2

// msstbc {{{
  static struct kv *
msstbc_anchor(struct msstb * const b)
{
  const u32 alen = b->idx ? (kv_key_lcp(b->tmp0, b->tmp1)+1) : 0;
  debug_assert(alen <= b->tmp1->klen);
  struct kv * const anchor = kv_create(b->tmp1->kv, alen, NULL, 0); // key only
  return anchor;
}

  static void
msstbc_ptrs(struct msstb * const b, struct sst_ptr * const ptrs)
{
  for (u32 i = 0; i < b->nway; i++)
    ptrs[i] = b->citers[i]->iter.ptr;
}

  static void
msstbc_sync_lo(struct msstb * const b)
{
  while ((b->kidx0 < b->nkidx) && ((b->ranks[b->kidx0] & SSTY_RANK) >= b->way0))
    b->kidx0++;
}

  static void
msstbc_sync_hi(struct msstb * const b)
{
  while ((b->way1 < b->nway) && (!sstc_iter_valid(b->citers[b->way1])))
    b->way1++;
}

  static void
msstbc_sync_rank(struct msstb * const b)
{
  const bool validlo = b->kidx0 < b->nkidx;
  const bool validhi = b->way1 < b->nway;

  if (validlo) {
    const u8 loenc = b->ranks[b->kidx0];
    const u8 lorank = loenc & SSTY_RANK;
    debug_assert(lorank < b->way0);
    const int cmp = validhi ? sstc_iter_compare(b->citers[lorank], b->citers[b->way1]) : -1;
    if (cmp < 0) {
      b->rankenc = lorank;
      if (b->stale || (loenc & SSTY_STALE))
        b->rankenc |= SSTY_STALE;
    } else {
      b->rankenc = b->way1;
      debug_assert(b->stale == false);
    }
    b->stale = cmp == 0;
  } else { // validlo == false
    if (validhi) {
      b->rankenc = b->way1;
      //b->stale = false; // no need
    } else { // stop
      b->rankenc = UINT32_MAX;
      return;
    }
  }
  struct sstc_iter * const citer = b->citers[b->rankenc & SSTY_RANK];
  if (sstc_iter_ts(citer))
    b->rankenc |= SSTY_TOMBSTONE;

  if ((b->rankenc & SSTY_STALE) == 0) {
    struct kv * const xchg = b->tmp0;
    b->tmp0 = b->tmp1;
    b->tmp1 = xchg;
    struct kref cref;
    if (sstc_iter_kref(citer, &cref)) {
      b->tmp1->klen = cref.len;
      memcpy(b->tmp1->kv, cref.ptr, cref.len); // hash is ignored
    } else {
      debug_die();
    }
  }
}

  static void
msstbc_skip1(struct msstb * const b)
{
  const u8 rank = b->rankenc & SSTY_RANK;
  sstc_iter_skip1(b->citers[rank]);
  b->idx++;
  if (rank < b->way0) { // lo
    b->kidx0++;
    msstbc_sync_lo(b);
  } else {
    msstbc_sync_hi(b);
  }
  msstbc_sync_rank(b);
}

  static struct msstb *
msstbc_create(struct msst * const x1, struct msst * const y0, const u32 way0)
{
  struct msstb * const b = msstb2_create_common(x1, y0, way0);

  b->tmp0 = malloc(sizeof(*b->tmp0) + SST_MAX_KVSZ);
  b->tmp1 = malloc(sizeof(*b->tmp1) + SST_MAX_KVSZ);

  for (u32 i = 0; i < b->nway; i++) {
    b->citers[i] = sstc_iter_create(&(x1->ssts[i]));
    b->citers[i]->iter.rank = i;
  }
  msstbc_sync_lo(b);
  msstbc_sync_hi(b);
  msstbc_sync_rank(b);
  return b;
}

  static void
msstbc_destroy(struct msstb * const b)
{
  free(b->tmp0);
  free(b->tmp1);
  for (u32 i = 0; i < b->nway; i++)
    sstc_iter_destroy(b->citers[i]);
  free(b);
}

static const struct msstb_api msstb_api_bc = {
  .create = msstbc_create,
  .ptrs = msstbc_ptrs,
  .anchor = msstbc_anchor,
  .skip1 = msstbc_skip1,
  .destroy = msstbc_destroy,
};
// }}} msstbc

// sort {{{
// check if tables at way0 to nway overlap
  static const struct msstb_api *
ssty_build_api(struct msst * const x1, const u32 way0)
{
  const u32 nway = x1->nway;
  struct kv * const last = malloc(sizeof(*last) + SST_MAX_KVSZ);
  struct kv * const tmp = malloc(sizeof(*last) + SST_MAX_KVSZ);
  last->klen = UINT32_MAX;
  bool overlap = false;
  for (u32 i = way0; (i+1) < nway; i++) {
    if (x1->ssts[i].totkv == 0)
      continue;

    struct kv * const first = sst_first_key(&(x1->ssts[i]), tmp);
    if ((last->klen != UINT32_MAX) && (kv_compare(last, first) >= 0)) {
      overlap = true;
      break;
    }
    sst_last_key(&(x1->ssts[i]), last);
  }

  free(last);
  free(tmp);
  if (overlap) {
    return &msstb_api_miter;
  } else if (msstb_use_ckeys(x1)) {
    return &msstb_api_bc;
  } else {
    return &msstb_api_b2;
  }
}

  static void
ssty_build_sort_msstb(struct ssty_build_info * const bi)
{
  const struct msstb_api * const api = ssty_build_api(bi->x1, bi->way0);
  struct msstb * const b = api->create(bi->x1, bi->y0, bi->way0);
  if (!b)
    debug_die();

  const u32 nway = bi->x1->nway;
  u8 * const ranks = bi->ranks;

  struct sst_ptr * ptrs = bi->ptrs;

  u32 kidx0 = 0; // id of the first key of multiple identical keys (<= kidx1)
  u32 kidx1 = 0; // the current key
  u32 valid = 0; // number of unique and valid keys (unique_keys - tombstones)
  u32 aidx = 0; // the next anchor's index; generate anchor key when kidx0 == aidx

  while (msstb_valid(b)) {
    const u32 rankenc = msstb_rankenc(b);
    debug_assert(rankenc < SSTY_INVALID);
    debug_assert((rankenc & SSTY_RANK) < nway);

    if ((rankenc & SSTY_STALE) == 0) { // not a stale key
      api->ptrs(b, ptrs); // save ptrs of every newest version
      kidx0 = kidx1;
      bi->uniqx[rankenc & SSTY_RANK]++;
      if ((rankenc & SSTY_TOMBSTONE) == 0)
        valid++;
    } else if ((kidx0 ^ kidx1) >> SSTY_DBITS) { // crossing boundary
      const u32 gap = kidx1 - kidx0;
      memmove(&(ranks[kidx1]), &(ranks[kidx0]), gap); // move forward
      memset(&(ranks[kidx0]), SSTY_INVALID, gap); // fill with INVALID
      kidx0 += gap;
      kidx1 += gap;
    }

    if (kidx0 == aidx) { // generate anchors
      bi->anchors[aidx >> SSTY_DBITS] = api->anchor(b);
      aidx += SSTY_DIST;
      ptrs += nway; // ptrs accepted
    }
    ranks[kidx1] = (u8)rankenc;
    api->skip1(b);
    kidx1++;
  }
  api->destroy(b);

  // metadata
  bi->nkidx = kidx1;
  bi->nsecs = (kidx1 + SSTY_DIST - 1) >> SSTY_DBITS;
  bi->valid = valid;
}
// }}} sort

// main {{{
// y0 and way0 are optional
  static u32
ssty_build_at(const int dirfd, struct msst * const x1,
    const u64 seq, const u32 nway, struct msst * const y0, const u32 way0)
{
  // open ssty file for output
  debug_assert(nway == x1->nway);
  char fn[24];
  const u64 magic = seq * 100lu + nway;
  sprintf(fn, "%03lu.ssty", magic);
  const int fdout = openat(dirfd, fn, O_WRONLY|O_CREAT|O_TRUNC, 00644);
  if (fdout < 0)
    return 0;

  u32 totkv = 0;
  size_t totsz = 0;
  for (u32 i = 0; i < nway; i++) {
    totkv += x1->ssts[i].totkv;
    totsz += x1->ssts[i].fsize;
  }
  debug_assert(totsz <= UINT32_MAX);

  const u32 maxkidx = (totkv + SSTY_DIST) * 2; // large enough
  const u32 maxsecs = maxkidx >> SSTY_DBITS;
  u8 * const ranks = malloc(maxkidx + 128); // double size is enough
  struct sst_ptr * const ptrs = malloc(sizeof(*ptrs) * (maxsecs * nway + MSST_NWAY + 8));
  struct kv ** const anchors = malloc(sizeof(*anchors) * maxsecs);
  debug_assert(ranks && ptrs && anchors);

  struct ssty_build_info bi = {.x1 = x1, .y0 = y0, .dirfd = dirfd, .way0 = way0,
    .ranks = ranks, .ptrs = ptrs, .anchors = anchors};

  ssty_build_sort_msstb(&bi);
  debug_assert(bi.nkidx <= maxkidx);
  debug_assert(bi.nsecs <= maxsecs);
  const u32 nkidx = bi.nkidx;
  const u32 nsecs = bi.nsecs;
  // write ranks // x16 for simd in seek_local
  memset(&ranks[nkidx], (int)nway, sizeof(ranks[0]) * SSTY_DIST); // pad with nway (at least 1 byte, up to 16)
  const u32 size1 = (u32)bits_round_up(sizeof(u8) * nkidx + 1, SSTY_DBITS);
  write(fdout, bi.ranks, size1);
  free(bi.ranks);

  //write level indicators and seek ptrs
  const u32 size2 = sizeof(struct sst_ptr) * nsecs * nway;
  write(fdout, bi.ptrs, size2);
  free(bi.ptrs);

  // gen anchors
  const u32 baseoff = size1 + size2;
  u32 * const ioffs = malloc(sizeof(*ioffs) * nsecs);
  struct kvenc * const aenc = kvenc_create();
  for (u64 i = 0; i < nsecs; i++) {
    const u32 ioff = baseoff + kvenc_size(aenc);
    ioffs[i] = ioff;
    const u32 klen = anchors[i]->klen;
    const u32 est = vi128_estimate_u32(klen) + klen;
    const u32 rem = PGSZ - (ioff % PGSZ);
    if (est > rem) {
      kvenc_append_raw(aenc, NULL, rem);
      ioffs[i] += rem;
      debug_assert((ioffs[i] % PGSZ) == 0);
    }
    kvenc_append_vi128(aenc, klen);
    kvenc_append_raw(aenc, anchors[i]->kv, klen);
  }
  kvenc_append_padding(aenc, 2);
  const u32 size3 = kvenc_size(aenc);
  kvenc_write(aenc, fdout);
  kvenc_reset(aenc);
  const u32 size4 = sizeof(*ioffs) * nsecs;
  write(fdout, ioffs, size4);
  const u32 ioffsoff = baseoff + size3;

  // ikeys2
  const u32 baseoff2 = size1+size2+size3+size4;
  const u32 pga = nsecs ? (ioffs[0] / PGSZ) : 0; // first pageno of index blocks
  const u32 pgz = nsecs ? (ioffs[nsecs-1] / PGSZ) : 0; // last pageno of index blocks
  const u32 ipages = nsecs ? (pgz - pga + 1) : 0; // totol number of pages of index blocks
  u32 * const ioffs2 = malloc(sizeof(*ioffs2) * ipages);

  u32 i1 = 0;
  u32 * pend2 = NULL;
  for (u32 i = 0; i < ipages; i++) {
    // search for the first anchor key in the block
    while ((ioffs[i1] / PGSZ) != (pga + i))
      i1++;
    if (pend2)
      *pend2 = i1;

    const u32 ioff2 = baseoff2 + kvenc_size(aenc);
    ioffs2[i] = ioff2; // offset of this entry
    kvenc_append_u32(aenc, i1);
    pend2 = kvenc_append_u32_backref(aenc);
    struct kv * const anchor = anchors[i1];
    kvenc_append_vi128(aenc, anchor->klen);
    kvenc_append_raw(aenc, anchor->kv, anchor->klen);
    kvenc_append_padding(aenc, 2); // x4
    i1++;
  }
  if (pend2)
    *pend2 = nsecs;

  free(ioffs);
  for (u64 i = 0; i < nsecs; i++)
    free(anchors[i]);
  free(anchors);

  const u32 size5 = kvenc_size(aenc);
  kvenc_write(aenc, fdout);
  kvenc_destroy(aenc);
  const u32 size6 = sizeof(*ioffs2) * ipages;
  write(fdout, ioffs2, size6);
  free(ioffs2);
  const u32 ioffsoff2 = baseoff2 + size5;

  // ssty metadata
  struct ssty_meta meta = {
    .nway = nway, .nkidx = nkidx, .ptroff = size1, .inr1 = nsecs,
    .ioff1 = ioffsoff, .inr2 = ipages, .ioff2 = ioffsoff2, .totkv = totkv,
    .totsz = (u32)totsz, .valid = bi.valid, .magic = magic,};

  // in the ssty file, each uniqx[i] is the number of unique keys at [i:n] levels if they are merged
  u32 uniq = 0;
  for (u32 i = nway-1; i < nway; i--) {
    uniq += bi.uniqx[i];
    meta.uniqx[i] = uniq;
  }
  const bool succ = write(fdout, &meta, sizeof(meta)) == sizeof(meta);
  const size_t fsize = size1+size2+size3+size4+size5+size6+sizeof(meta);
  debug_assert(fsize < UINT32_MAX);

  // done
  fsync(fdout);
  close(fdout);
  return succ ? (u32)fsize : 0;
}

  u32
ssty_build(const char * const dirname, struct msst * const x1,
    const u64 seq, const u32 nway, struct msst * const y0, const u32 way0)
{
  const int dirfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dirfd < 0)
    return 0;
  const u32 ret = ssty_build_at(dirfd, x1, seq, nway, y0, way0);
  close(dirfd);
  return ret;
}
// }}} main

// }}} ssty_build

// msstv {{{
struct msstv { // similar to a version in leveldb
  u64 version;
  u64 nr; // number of partitions
  u64 nslots; // assert(nr <= nslots)
  struct msstv * next; // to older msstvs
  au64 rdrcnt; // active readers
  struct rcache * rc; // rcache

  struct msstv_part {
    struct kv * anchor; // magic in anchor->priv; anchor->vlen == 1 for rejected partition
    struct msst * msst; // mssty
  } es[0];
};

struct msstv_iter {
  struct msstv * v;
  u64 nr;
  u64 i; // select mssty
  struct mssty_iter iter;
};

struct msstv_ref { // ref is iter
  struct msstv_iter vi;
};

  inline void
msstv_rcache(struct msstv * const v, struct rcache * const rc)
{
  v->rc = rc;
  for (u64 i = 0; i < v->nr; i++)
    msst_rcache(v->es[i].msst, rc);
}

// for debugging now
  struct msstv *
msstv_create(const u64 nslots, const u64 version)
{
  // msstv does not record nslots
  // caller need to do it right
  struct msstv * const v = calloc(1, sizeof(*v) + (sizeof(v->es[0]) * nslots));
  v->version = version;
  v->nslots = nslots;
  // v->next is maintained externally
  return v;
}

// anchor can be NULL for auto detection; for new partitions only
// a private copy of the anchor will be duplicated if not NULL
  void
msstv_append(struct msstv * const v, struct msst * const msst, const struct kv * const anchor)
{
  debug_assert(msst && msst->ssty);
  debug_assert(v->nr < v->nslots);

  struct msstv_part * const e = &(v->es[v->nr]);
  if (v->nr && (anchor == NULL)) { // auto generate anchor
    struct kv * const first = mssty_first(msst, NULL); // malloced
    debug_assert(first); // major compaction should never generate an empty mssty
    struct kv * const plast = mssty_last(v->es[v->nr-1].msst, NULL); // malloced; might be NULL
    if (plast) {
      first->klen = kv_key_lcp(plast, first) + 1;
      //kv_update_hash(first);
      free(plast);
    }
    e->anchor = first;
  } else {
    debug_assert(anchor);
    e->anchor = kv_dup_key(anchor);
  }

  msst->refcnt++;
  // save magic in anchor->priv; anchor->hash is not saved
  e->anchor->priv = msst->ssty->meta->magic;
  e->msst = msst;
  v->nr++;
}

// save to a file
  static bool
msstv_save(struct msstv * const v, const int dirfd)
{
  char fn[24];
  sprintf(fn, "%lu.ver", v->version);
  int fd = openat(dirfd, fn, O_CREAT|O_WRONLY|O_TRUNC, 00644);
  if (fd < 0)
    return false;

  FILE * const fout = fdopen(fd, "w");
  if (fout == NULL)
    return false;
  setvbuf(fout, NULL, _IOFBF, 1lu << 16); // 64kB
  fwrite(&(v->version), sizeof(v->version), 1, fout);
  fwrite(&(v->nr), sizeof(v->nr), 1, fout);
  char bufz[8] = {};
  for (u64 i = 0; i < v->nr; i++) {
    const u64 keysize = key_size(v->es[i].anchor);
    fwrite(v->es[i].anchor, keysize, 1, fout);
    const u64 size = bits_round_up(keysize, 3);
    if (size > keysize)
      fwrite(bufz, size - keysize, 1, fout);
  }
  fclose(fout);
  return true;
}

// open version and open all msstys
  static struct msstv *
msstv_open_at(const int dirfd, const char * const filename)
{
  const int fd = openat(dirfd, filename, O_RDONLY);
  if (fd < 0)
    return NULL;

  const u64 filesz = fdsize(fd);
  if (filesz < (sizeof(u64) * 2 + sizeof(struct kv))) {
    close(fd);
    return NULL;
  }

  u8 * const buf = malloc(filesz);
  const ssize_t nread = pread(fd, buf, filesz, 0);
  if (filesz != (u64)nread) {
    free(buf);
    close(fd);
    return NULL;
  }
  close(fd);

  const u64 v1 = ((const u64 *)buf)[0];
  const u64 nr = ((const u64 *)buf)[1];
  debug_assert(nr);

  // open msstys
  struct msstv * const v = msstv_create(nr, v1);
  u8 * cursor = buf + (sizeof(u64) * 2);
  for (u64 i = 0; i < nr; i++) {
    struct kv * const anchor = (typeof(anchor))cursor;
    const u64 magic = anchor->priv;
    // rc: msstz_open sets rc later; compaction sets rc manually
    struct msst * const mssty = mssty_open_at(dirfd, magic / 100, magic % 100);
    if (!mssty) {
      msstv_destroy(v);
      free(buf);
      return NULL;
    }
    msstv_append(v, mssty, anchor);
    cursor += (bits_round_up(key_size(anchor), 3));
  }

  debug_assert((u64)(cursor - buf) == filesz);
  free(buf);
  return v;
}

  struct msstv *
msstv_open(const char * const dirname, const char * const filename)
{
  const int dirfd = open(dirname, O_RDONLY|O_DIRECTORY);
  if (dirfd < 0)
    return NULL;
  struct msstv * const v = msstv_open_at(dirfd, filename);
  close(dirfd);
  return v;
}

  struct msstv *
msstv_open_version(const char * const dirname, const u64 version)
{
  char filename[32];
  sprintf(filename, "%lu.ver", version);
  return msstv_open(dirname, filename);
}

  static void
msstv_destroy_lazy(struct msstv * const v)
{
  for (u64 i = 0; i < v->nr; i++) {
    // mssty can be shared by mutliple versions
    struct msst * const msst = v->es[i].msst;
    if (msst->refcnt == 1)
      mssty_destroy_lazy(msst);
    else
      msst->refcnt--;

    free(v->es[i].anchor);
  }
  free(v);
}

// it does not free the msstys
  void
msstv_destroy(struct msstv * const v)
{
  for (u64 i = 0; i < v->nr; i++) {
    // mssty can be shared by mutliple versions
    struct msst * const msst = v->es[i].msst;
    if (msst->refcnt == 1)
      mssty_destroy(msst);
    else
      msst->refcnt--;

    free(v->es[i].anchor);
  }
  free(v);
}

  struct msstv_ref *
msstv_ref(struct msstv * const v)
{
  struct msstv_iter * const vi = calloc(1, sizeof(*vi));
  vi->v = v;
  vi->nr = v->nr;
  vi->i = v->nr; // invalid
  return (struct msstv_ref *)vi;
}

  struct msstv *
msstv_unref(struct msstv_ref * const ref)
{
  struct msstv * const v = ref->vi.v;
  free(ref);
  return v;
}

  static u64
msstv_search_le(struct msstv * const v, const struct kref * const key)
{
  u64 l = 0;
  u64 r = v->nr;
  while ((l + 1) < r) {
    const u64 m = (l + r) >> 1;
    const int cmp = kref_kv_compare(key, v->es[m].anchor);
    if (cmp < 0)
      r = m; // m always > 0
    else if (cmp > 0)
      l = m;
    else
      return m;
  }
  return l;
}

  struct kv *
msstv_last(struct msstv * const v, struct kv * const out)
{
  struct msst * const plast = v->es[v->nr-1].msst;
  return mssty_last(plast, out);
}

  struct kv *
msstv_get(struct msstv_ref * const ref, const struct kref * const key, struct kv * const out)
{
  struct msstv_iter * const vi = (typeof(vi))ref;
  const u64 i = msstv_search_le(vi->v, key);
  debug_assert(i < vi->nr);
  if (i != vi->i)
    mssty_iter_init(&(vi->iter), vi->v->es[i].msst);
  struct kv * const ret = mssty_get((struct mssty_ref *)&(vi->iter), key, out);
  mssty_iter_park(&(vi->iter));
  return ret;
}

  bool
msstv_probe(struct msstv_ref * const ref, const struct kref * const key)
{
  struct msstv_iter * const vi = (typeof(vi))ref;
  const u64 i = msstv_search_le(vi->v, key);
  debug_assert(i < vi->nr);
  if (i != vi->i)
    mssty_iter_init(&(vi->iter), vi->v->es[i].msst);
  const bool r = mssty_probe((struct mssty_ref *)&(vi->iter), key);
  mssty_iter_park(&(vi->iter));
  return r;
}

  struct kv *
msstv_get_ts(struct msstv_ref * const ref, const struct kref * const key, struct kv * const out)
{
  struct msstv_iter * const vi = (typeof(vi))ref;
  const u64 i = msstv_search_le(vi->v, key);
  debug_assert(i < vi->nr);
  if (i != vi->i)
    mssty_iter_init(&(vi->iter), vi->v->es[i].msst);
  struct kv * const ret = mssty_get_ts((struct mssty_ref *)&(vi->iter), key, out);
  mssty_iter_park(&(vi->iter));
  return ret;
}

  bool
msstv_probe_ts(struct msstv_ref * const ref, const struct kref * const key)
{
  struct msstv_iter * const vi = (typeof(vi))ref;
  const u64 i = msstv_search_le(vi->v, key);
  debug_assert(i < vi->nr);
  if (i != vi->i)
    mssty_iter_init(&(vi->iter), vi->v->es[i].msst);
  const bool r = mssty_probe_ts((struct mssty_ref *)&(vi->iter), key);
  mssty_iter_park(&(vi->iter));
  return r;
}

  bool
msstv_get_value_ts(struct msstv_ref * const ref, const struct kref * const key,
    void * const vbuf_out, u32 * const vlen_out)
{
  struct msstv_iter * const vi = (typeof(vi))ref;
  const u64 i = msstv_search_le(vi->v, key);
  debug_assert(i < vi->nr);
  if (i != vi->i)
    mssty_iter_init(&(vi->iter), vi->v->es[i].msst);
  const bool r = mssty_get_value_ts((struct mssty_ref *)&(vi->iter), key, vbuf_out, vlen_out);
  mssty_iter_park(&(vi->iter));
  return r;
}

  inline bool
msstv_iter_valid(struct msstv_iter * const vi)
{
  return (vi->i < vi->nr) && mssty_iter_valid(&(vi->iter));
}

  static inline bool
msstv_iter_valid_y(struct msstv_iter * const vi)
{
  return (vi->i < vi->nr);
}

  struct msstv_iter *
msstv_iter_create(struct msstv_ref * const ref)
{
  struct msstv_iter * const vi0 = (typeof(vi0))ref;
  struct msstv_iter * const vi = calloc(1, sizeof(*vi));
  vi->v = vi0->v;
  vi->nr = vi0->nr;
  vi->i = vi->nr;
  return vi;
}

  void
msstv_iter_destroy(struct msstv_iter * const vi)
{
  if (msstv_iter_valid_y(vi))
    mssty_iter_park(&(vi->iter));
  free(vi);
}

  void
msstv_iter_seek(struct msstv_iter * const vi, const struct kref * const key)
{
  struct msstv * const v = vi->v;
  const u64 i0 = msstv_search_le(v, key);
  debug_assert(i0 < vi->nr);
  if (i0 != vi->i) {
    if (msstv_iter_valid_y(vi))
      mssty_iter_park(&(vi->iter));
    vi->i = i0;
    mssty_iter_init(&(vi->iter), v->es[i0].msst);
  }

  do {
    mssty_iter_seek(&(vi->iter), key);
    if (mssty_iter_valid(&(vi->iter)))
      return;

    mssty_iter_park(&(vi->iter));
    vi->i++;
    if (!msstv_iter_valid_y(vi))
      return;
    mssty_iter_init(&(vi->iter), v->es[vi->i].msst);
  } while (true);
}

  struct kv *
msstv_iter_peek(struct msstv_iter * const vi, struct kv * const out)
{
  if (!msstv_iter_valid_y(vi))
    return NULL;
  return mssty_iter_peek(&(vi->iter), out);
}

  bool
msstv_iter_kref(struct msstv_iter * const vi, struct kref * const kref)
{
  if (!msstv_iter_valid_y(vi))
    return false;
  return mssty_iter_kref(&(vi->iter), kref);
}

  bool
msstv_iter_kvref(struct msstv_iter * const vi, struct kvref * const kvref)
{
  if (!msstv_iter_valid_y(vi))
    return false;
  return mssty_iter_kvref(&(vi->iter), kvref);
}

  inline u64
msstv_iter_retain(struct msstv_iter * const vi)
{
  debug_assert(msstv_iter_valid_y(vi));
  return mssty_iter_retain(&vi->iter);
}

  inline void
msstv_iter_release(struct msstv_iter * const vi, const u64 opaque)
{
  sst_blk_release(vi->v->rc, (const u8 *)opaque);
}

  void
msstv_iter_skip(struct msstv_iter * const vi, const u32 nr)
{
  if (!msstv_iter_valid_y(vi))
    return;
  for (u32 i = 0; i < nr; i++) {
    mssty_iter_skip(&(vi->iter), 1);
    while (!mssty_iter_valid(&(vi->iter))) { // next partition
      mssty_iter_park(&(vi->iter));
      vi->i++;
      if (msstv_iter_valid_y(vi)) {
        mssty_iter_init(&(vi->iter), vi->v->es[vi->i].msst);
        mssty_iter_seek_null(&(vi->iter));
      } else {
        return;
      }
    }
  }
}

  struct kv *
msstv_iter_next(struct msstv_iter * const vi, struct kv * const out)
{
  struct kv * const ret = msstv_iter_peek(vi, out);
  msstv_iter_skip(vi, 1);
  return ret;
}

  inline bool
msstv_iter_ts(struct msstv_iter * const vi)
{
  // assume vi is valid
  debug_assert(msstv_iter_valid_y(vi));
  return mssty_iter_ts(&(vi->iter));
}

  void
msstv_iter_seek_ts(struct msstv_iter * const vi, const struct kref * const key)
{
  msstv_iter_seek(vi, key);
  while (msstv_iter_valid(vi) && msstv_iter_ts(vi))
    msstv_iter_skip(vi, 1);
}

  void
msstv_iter_skip_ts(struct msstv_iter * const vi, const u32 nr)
{
  for (u32 i = 0; i < nr; i++) {
    if (!msstv_iter_valid(vi))
      return;

    msstv_iter_skip(vi, 1);
    while (msstv_iter_valid(vi) && msstv_iter_ts(vi))
      msstv_iter_skip(vi, 1);
  }
}

  struct kv *
msstv_iter_next_ts(struct msstv_iter * const vi, struct kv * const out)
{
  struct kv * const ret = msstv_iter_peek(vi, out);
  msstv_iter_skip_ts(vi, 1);
  return ret;
}

  void
msstv_iter_park(struct msstv_iter * const vi)
{
  if (msstv_iter_valid_y(vi))
    mssty_iter_park(&(vi->iter));
}

  void
msstv_fprint(struct msstv * const v, FILE * const out)
{
  fprintf(out, "%s v %lu nr %lu refcnt %lu rcache %s\n",
      __func__, v->version, v->nr, v->rdrcnt, v->rc ? "ON" : "OFF");

  for (u64 i = 0; i < v->nr; i++) {
    struct msst * const msst = v->es[i].msst;
    debug_assert(v->rc == msst->rc);
    struct ssty * const ssty = msst->ssty;
    const u64 magic = v->es[i].anchor->priv;
    fprintf(out, "%s [%3lu %6.3lu]", __func__, i, magic);
    for (u32 j = 0; j < ssty->nway; j++) {
      struct sst * const sst = &(msst->ssts[j]);
      debug_assert(v->rc == sst->rc);
      fprintf(out, " %7u:%9u ", sst->totkv, sst->fsize);
    }
    kv_print(v->es[i].anchor, "sn", out);
  }
}

  struct kv **
msstv_anchors(struct msstv * const v)
{
  struct kv ** const ret = malloc(sizeof(ret[0]) * (v->nr+1));
  for (u64 i = 0; i < v->nr; i++)
    ret[i] = v->es[i].anchor;
  ret[v->nr] = NULL;
  return ret;
}
// }}} msstv

// msstz {{{

// msst zoo
struct msstz {
  struct msstv * volatile hv; // the newest version
  au64 seq; // next available seq
  char * dirname;

  // compaction parameters
  u64 minsz;
  u32 nblks;
  u32 nway_major; // small
  u32 nway_minor; // large
  bool ckeys; // copy-keys
  struct rcache * rc; // read-only cache

  double t0;
  int stat_log; // for printf
  int dirfd; // could be stderr
  u64 stat_time; // time spent in comp()
  u64 stat_writes; // total bytes written to sstx&ssty
  u64 stat_reads; // total bytes read through rcache; user reads are included if running concurrently

  u64 padding1[7];
  rwlock head_lock; // writer: compaction, gc
};

  void
msstz_log(struct msstz * const z, const char * const fmt, ...)
{
  char buf[4096];
  sprintf(buf, "%010.3lf %08x ", time_diff_sec(z->t0), crc32c_u64(0x12345678, (u64)pthread_self()));
  strcat(buf, fmt);

  va_list ap;
  va_start(ap, fmt);
  vdprintf(z->stat_log, buf, ap);
  va_end(ap);
}

  static void
msstz_head_sync(const int dirfd, const u64 version)
{
  char basefn[24];
  sprintf(basefn, "./%lu.ver", version);

  unlinkat(dirfd, "HEAD", 0);
  symlinkat(basefn, dirfd, "HEAD");

  unlinkat(dirfd, "HEAD1", 0);
  symlinkat(basefn, dirfd, "HEAD1");
  return;
}

// create empty store
  static struct msstv *
msstz_create_v0(const int dirfd)
{
  // msstx nway = 0
  struct msst * const msst = msstx_open_at(dirfd, 0, 0);
  if (!msst)
    return NULL;

  if (!ssty_build_at(dirfd, msst, 0, 0, NULL, 0)) {
    msstx_destroy(msst);
    return NULL;
  }

  if (!mssty_open_y_at(dirfd, msst)) {
    msstx_destroy(msst);
    return NULL;
  }

  // msstv
  struct msstv * const v = msstv_create(1, 1); // version = 1
  if (v == NULL) {
    mssty_destroy(msst);
    return NULL;
  }
  msstv_append(v, msst, kv_null());
  return v;
}

  struct msstz *
msstz_open(const char * const dirname, const u64 cache_size_mb, const bool ckeys)
{
  // get the dir
  int dirfd = open(dirname, O_RDONLY | O_DIRECTORY);
  if (dirfd < 0) {
    mkdir(dirname, 00777);
    dirfd = open(dirname, O_RDONLY | O_DIRECTORY);
  }
  if (dirfd < 0)
    return NULL;

  // get a version
  struct msstv * hv = msstv_open_at(dirfd, "HEAD");
  if (hv == NULL)
    hv = msstv_open_at(dirfd, "HEAD1");
  if (hv == NULL)
    hv = msstz_create_v0(dirfd);
  if (hv == NULL) {
    close(dirfd);
    return NULL;
  }

  hv->rdrcnt = 0;
  u64 seq = 0;
  for (u64 i = 0; i < hv->nr; i++) {
    const u64 magic = hv->es[i].anchor->priv;
    const u64 seq1 = magic / 100;
    if (seq < seq1)
      seq = seq1;
  }
  const u64 seq0 = seq + 1; // use a new seq

  struct msstz * const z = yalloc(sizeof(*z));
  debug_assert(z);
  memset(z, 0, sizeof(*z));
  if (cache_size_mb)
    z->rc = rcache_create(cache_size_mb, 16);

  z->seq = seq0;
  z->hv = hv;
  msstv_rcache(hv, z->rc);

  z->dirname = strdup(dirname);
  debug_assert(z->dirname);

  z->minsz = MSSTZ_MINSZ; // can change later using msstz_set_minsz
  z->nblks = MSSTZ_NBLKS;
  z->nway_major = MSSTZ_NWAY_MAJOR; // fixed
  z->nway_minor = MSSTZ_NWAY_MINOR; // fixed
  z->ckeys = ckeys;
  z->dirfd = dirfd;

  char logfn[80];
  char buf[64];
  time_stamp2(buf, 64);

  sprintf(logfn, "log-%s", buf);
  z->stat_log = openat(dirfd, logfn, O_CREAT|O_WRONLY|O_TRUNC, 00644);
  debug_assert(z->stat_log >= 0);

  unlinkat(dirfd, "LOG", 0);
  symlinkat(logfn, dirfd, "LOG");

  z->t0 = time_sec();

  rwlock_init(&(z->head_lock));
  char ts[64];
  time_stamp(ts, 64);
  msstz_log(z, "%s time %s v %lu seq %lu cache %lu\n", __func__, ts, msstz_version(z), seq0, cache_size_mb);

  for (u64 i = 0; i < hv->nr; i++) {
    const u64 magic = hv->es[i].anchor->priv;
    msstz_log(z, "%s [%3lu] %5lu\n", __func__, i, magic);
  }
  return z;
}

  inline u64
msstz_stat_writes(struct msstz * const z)
{
  return z->stat_writes;
}

  inline u64
msstz_stat_reads(struct msstz * const z)
{
  return z->stat_reads;
}

  inline void
msstz_set_minsz(struct msstz * const z, const u64 minsz)
{
  z->minsz = minsz;
}

  inline u64
msstz_version(struct msstz * const z)
{
  return z->hv->version;
}

// free unused versions and delete unused files
// currently the first analyze worker do the gc
  static void
msstz_gc(struct msstz * const z)
{
  const u64 t0 = time_nsec();
  //const double t0 = time_sec();
  struct msstv * const hv = z->hv;
  debug_assert(hv);
  u64 nv = 0;
  // gc the tail, one at a time
  while (hv->next) {
    struct msstv ** pv = &(hv->next);
    // seek to &plast
    while ((*pv)->next)
      pv = &((*pv)->next);
    // stop if there is no next version, or the oldest version has version > 0

    struct msstv * const last = *pv;
    debug_assert(last->next == NULL);
    if (last->rdrcnt) {
      break;
    } else { // do gc
      *pv = NULL; // remove from the list
      msstv_destroy_lazy(last);
      nv++;
    }
  }

  const u64 nc = z->rc ? rcache_close_flush(z->rc) : 0;

  // count nr
  u64 nr = 0;
  struct msstv * v = hv;
  while (v) {
    nr += v->nr;
    v = v->next;
  }
  // collect live seq numbers
  cpu_cfence();
  // array of all live seqs
  u64 * const vseq = malloc(sizeof(*vseq) * nr);
  // array of all live magics (live ssty)
  u64 * const vall = malloc(sizeof(*vall) * nr);
  u64 nr1 = 0;
  v = hv; // start over to collect seqs
  debug_assert(v);
  do {
    for (u64 i = 0; i < v->nr; i++) {
      const u64 magic = v->es[i].anchor->priv;
      vseq[nr1] = magic / 100;
      vall[nr1] = magic;
      nr1++;
    }
    v = v->next;
  } while (v);
  debug_assert(nr1 == nr);
  // it's ok to have duplicates
  qsort_u64(vseq, nr);
  qsort_u64(vall, nr);
  const u64 maxseq = vseq[nr-1];
  // search file in dir
  DIR * const dir = opendir(z->dirname); // don't directly use the dirfd
  if (!dir) {
    msstz_log(z, "%s opendir() failed\n", __func__);
    exit(0);
  }

  u64 nu = 0;
  do {
    struct dirent * const ent = readdir(dir);
    if (!ent)
      break;
    char * dot = strchr(ent->d_name, '.');
    // has dot and is .sst*
    if (!dot)
      continue;

    if (!memcmp(dot, ".ver", 4)) {
      if (a2u64(ent->d_name) < hv->version)
        unlinkat(z->dirfd, ent->d_name, 0);
      continue;
    }

    if (memcmp(dot, ".sst", 4))
      continue;
    const u64 magic = a2u64(ent->d_name);
    const u64 seq = magic / 100;

    if (seq > maxseq)
      continue;

    if (dot[4] == 'x') {
      if (bsearch_u64(seq, vseq, nr))
        continue;
    } else if (dot[4] == 'y') {
      if (bsearch_u64(magic, vall, nr))
        continue;
    } else {
      debug_die();
    }
    // now delete
    unlinkat(z->dirfd, ent->d_name, 0);
    //msstz_log(z, "%s unlink %s\n", __func__, ent->d_name);
    nu++;
  } while (true);

  free(vseq);
  free(vall);
  closedir(dir);
  msstz_log(z, "%s gc dt-ms %lu free-v %lu close %lu unlink %lu\n", __func__, time_diff_nsec(t0)/1000000, nv, nc, nu);
}

  inline struct msstv *
msstz_getv(struct msstz * const z)
{
  rwlock_lock_read(&(z->head_lock));
  struct msstv * const v = z->hv;
  v->rdrcnt++;
  rwlock_unlock_read(&(z->head_lock));
  return v;
}

  inline void
msstz_putv(struct msstz * const z, struct msstv * const v)
{
  (void)z;
  debug_assert(v->rdrcnt);
  v->rdrcnt--;
}

  void
msstz_destroy(struct msstz * const z)
{
  struct msstv * iter = z->hv;
  debug_assert(iter);
  msstz_gc(z);
  msstz_log(z, "%s hv %lu comp_time %lu writes %lu reads %lu\n", __func__,
      iter->version, z->stat_time, z->stat_writes, z->stat_reads);
  while (iter) {
    struct msstv * next = iter->next;
    msstv_destroy(iter);
    iter = next;
  }
  if (z->rc)
    rcache_destroy(z->rc);

  close(z->stat_log);
  free(z->dirname);
  close(z->dirfd);
  free(z);
}
// }}} msstz

// msstz-comp {{{

// struct {{{
// yq allows different threads to build sstys; very useful for sequential loading
struct msstz_yq {
  au64 pseq; // producer seq
  au64 cseq; // consumer seq
  spinlock lock;
  u32 padding;
  struct msstz_ytask {
    struct msst * y1; // output; the new mssty; NULL when not done
    struct msst * y0; // old mssty
    u64 seq1; // new seq // 0 if rejected
    u32 way1; // new way
    u32 way0; // how many tables to reuse from y0
    u64 ipart;
    u64 isub; // index of new partitions generated from an old partition
    const struct kv * anchor; // provide anchor key (isub == 0) or NULL (isub > 0)
  } tasks[0];
};

// global compaction information
struct msstz_comp_info {
  struct msstz * z;
  struct msstv * v0; // the old version
  au64 seqx; // to assign analysis/compaction tasks to threads
  struct msstz_yq * yq;
  u64 n0; // total number of v0 partitions
  au64 nx; // when nx == n0, the yq has all the tasks
  u32 nr_workers;
  u32 co_per_worker;
  const struct kvmap_api * api1; // memtable api
  void * map1; // memtable map
  au64 totsz;
  au64 stat_writes; // total bytes written to sstx&ssty
  au64 stat_reads; // total bytes read through rcache; user reads are included if running concurrently
  au64 stat_minor;
  au64 stat_partial;
  au64 stat_major;
  au64 stat_append;
  au64 time_analyze;
  au64 time_comp_x;
  au64 time_comp_y;
  u64 t0;
  u64 dta;
  u64 dtc;
  struct msstz_comp_part {
    u64 idx;
    u64 newsz; // size of new data in the memtable
    u32 bestway; // how many existing (can be linked) tables to keep in the old partition
    float ratio; // write_size over read_size; newsz / totsz; the higher the better
  } parts[0];
};
// }}} struct

// y {{{
  static struct msstz_yq *
msstz_yq_create(const u64 nslots)
{
  struct msstz_yq * const yq = malloc(sizeof(*yq) + (sizeof(yq->tasks[0]) * nslots));
  yq->pseq = 0;
  yq->cseq = 0;
  spinlock_init(&yq->lock);
  return yq;
}

  static struct msstz_ytask *
msstz_yq_append(struct msstz_yq * const yq, struct msst * const y1, const u64 seq1, const u32 way1,
    struct msst * const y0, const u32 way0, const u64 ipart, const u64 isub, const struct kv * const anchor)
{
  spinlock_lock(&yq->lock);
  const u64 i = yq->pseq++;
  struct msstz_ytask * const task = &yq->tasks[i];
  task->y1 = y1; // not NULL only when append
  task->y0 = y0;
  task->seq1 = seq1;
  task->way1 = way1;
  task->way0 = way0;
  task->ipart = ipart;
  task->isub = isub;
  task->anchor = anchor;
  spinlock_unlock(&yq->lock);
  return &yq->tasks[i];
}

// return true when a task is found and executed
  static bool
msstz_yq_consume(struct msstz_comp_info * const ci)
{
  struct msstz_yq * const yq = ci->yq;
  struct msstz * const z = ci->z;
  spinlock_lock(&yq->lock);
  if (yq->cseq == yq->pseq) {
    // no task
    spinlock_unlock(&yq->lock);
    return false;
  }
  // claim a task with lock
  const u64 id = yq->cseq++;
  spinlock_unlock(&yq->lock);

  struct msstz_ytask * const task = &(yq->tasks[id]);
  // already done (only once for the store-append)
  if (task->y1)
    return true;

  // open a msstx and call ssty_build
  //const u64 t0 = time_nsec();
  struct msst * const msst = msstx_open_at_reuse(z->dirfd, task->seq1, task->way1, task->y0, task->way0);
  msst_rcache(msst, z->rc);
  const u32 ysz = ssty_build_at(z->dirfd, msst, task->seq1, task->way1, task->y0, task->way0);
  if (!ysz)
    debug_die();
  ci->stat_writes += ysz;

  // convert msstx to mssty
  const bool ry = mssty_open_y_at(z->dirfd, msst);
  if (!ry)
    debug_die();
  task->y1 = msst; // done; the new partition is now loaded and ready to use
  //const u64 dt = time_diff_nsec(t0);
  //const struct ssty_meta * const ym = msst->ssty->meta;
  //msstz_log(z, "%s dt-ms %lu ssty-build %lu %02u nkidx %u ysz %u xkv %u xsz %u uniq %u valid %u\n",
  //    __func__, dt / 1000000, task->seq1, task->way1, msst->ssty->nkidx,
  //    ysz, ym->totkv, ym->totsz, ym->uniqx[0], ym->valid);
  return true;
}
// }}} y

// x {{{
// compaction driver on one partition; it may create multiple partitions
// create ssts synchronously; queue build-ssty tasks in yq
// seq0 and way0 indicate the existing (can be linked) tables in the target partition
  static void
msstz_comp_ssts(struct msstz_comp_info * const ci, const u64 ipart, struct miter * const miter,
    const struct kv * const k0, const struct kv * const kz, const u64 seq0, const u32 way0, const bool split,
    struct msst * const y0, const bool is_append)
{
  struct msstz * const z = ci->z;
  // tmp anchor
  struct kv * const tmp = malloc(sizeof(struct kv) + SST_MAX_KVSZ); // just a buffer
  u64 seq = seq0;
  u32 way = way0;
  u32 np = 0;
  debug_assert(way < MSST_NWAY);

  if (is_append) {
    msstz_yq_append(ci->yq, y0, seq, way, NULL, 0, ipart, 0, k0); // only y0, ipart, and k0 will be used
    np++;
    seq = z->seq++;
    way = 0;
  }
  // a compaction may create new partitions, each with several new tables
  do {
    //const u64 t0 = time_nsec();
    const u64 sizex = sst_build_at(z->dirfd, miter, seq, way, z->nblks, split, z->ckeys, NULL, kz);
    //const u64 dt = time_diff_nsec(t0);
    ci->stat_writes += sizex;
    //msstz_log(z, "%s dt-ms %lu sst-build %lu-%02u %lu\n", __func__, dt / 1000000, seq, way, sizex);
    way++;

    struct kv * const tmpz = miter_peek(miter, tmp); // the current unconsumed key
    // the entire partition is done
    const bool donez = (tmpz == NULL) || (kz && (kv_compare(tmpz, kz) >= 0));

    // the current partition must close; will switch to a new partition
    const bool done1 = split ? (way >= z->nway_major) : false;
    if (donez || done1) { // close current mssty
      // provide y0 and way0 only for the first partition
      if (np == 0) { // on the original partition; use y0, way0, and k0
        msstz_yq_append(ci->yq, NULL, seq, way, y0, way0, ipart, np, k0);
      } else { // a new partition: reuse nothing, generate anchor
        msstz_yq_append(ci->yq, NULL, seq, way, NULL, 0, ipart, np, NULL);
      }
      np++;

      if (donez) { // the end
        break;
      } else if (split) { // done1: next partition
        seq = z->seq++;
        way = 0;
      } else if (way >= MSST_NWAY) {
        // it is acceptable to have tables above nway_minor; the actual threshold is MSST_NWAY
        debug_die();
      }
    }
  } while (true);
  debug_assert(split || (np == 1)); // only split can return more than one partition
  free(tmp);
  //msstz_log(z, "%s np %u seq0 %lu way0 %u seq %lu way %u\n", __func__, np, seq0, way0, seq, way);
}

  static void
msstz_comp_link(const int dirfd, const u64 seq0, const u64 seq1, const u32 nway)
{
  debug_assert(seq0 < seq1);
  char fn0[24];
  char fn1[24];

  for (u32 i = 0; i < nway; i++) {
    sprintf(fn0, "%03lu.sstx", seq0 * 100lu + i);
    sprintf(fn1, "%03lu.sstx", seq1 * 100lu + i);
    unlinkat(dirfd, fn1, 0);
    linkat(dirfd, fn0, dirfd, fn1, 0);
  }
}
// }}} x

// v {{{
  static int
msstz_cmp_ytask(const void * p1, const void * p2)
{
  const struct msstz_ytask * const t1 = p1;
  const struct msstz_ytask * const t2 = p2;
  if (t1->ipart < t2->ipart) {
    return -1;
  } else if (t1->ipart > t2->ipart) {
    return 1;
  } else if (t1->isub < t2->isub) {
    return -1;
  } else if (t1->isub > t2->isub) {
    return 1;
  } else {
    debug_die();
    return 0;
  }
}

  static void
msstz_comp_harvest(struct msstz_comp_info * const ci)
{
  struct msstz_yq * const yq = ci->yq;
  debug_assert(yq->pseq == yq->cseq);
  debug_assert(yq->pseq >= ci->n0);
  const u64 nr = yq->pseq;
  struct msstv * const v0 = ci->v0;

  // sort yq
  qsort(yq->tasks, nr, sizeof(yq->tasks[0]), msstz_cmp_ytask);

  struct msstv * const v1 = msstv_create(nr, ci->v0->version + 1); // no resizing
  // collect new partitions and create v1
  u64 sz = 0;
  for (u64 i = 0; i < nr; i++) {
    struct msstz_ytask * const t = &yq->tasks[i];
    msstv_append(v1, t->y1, t->anchor);
    v0->es[t->ipart].anchor->vlen = (t->seq1 == UINT64_MAX) ? 1 : 0; // 1: rej; 0: ok;
    sz += t->y1->ssty->size;
  }
  struct msstz * const z = ci->z;
  msstz_log(z, "%s v %lu nr %lu ssty-size %lu\n", __func__, v1->version, nr, sz);

  v1->rc = z->rc;
  v1->next = v0;
  // finalize the new version v1
  msstv_save(v1, z->dirfd);
  msstz_head_sync(z->dirfd, v1->version);

  // add the new version to z
  rwlock_lock_write(&(z->head_lock));
  z->hv = v1;
  rwlock_unlock_write(&(z->head_lock));
}
// }}} v

// analyze {{{
  static u64
msstz_comp_estimate_ssty(const u64 nkeys, const float way)
{
  const u64 nsecs = nkeys / MSSTZ_DIST;
  return (sizeof(struct sst_ptr) * (u64)ceilf(way) + 16) * nsecs + nkeys;
}

  static inline const struct kv *
msstz_comp_get_kz(struct msstv * const v, const u64 ipart)
{
  return ((ipart + 1) < v->nr) ? v->es[ipart + 1].anchor : NULL;
}

// bestway:
// 0: major, rewrite everything
// < nway0 (nway0 < MSST_NWAY): partial, rewrite a few tables
// == nway0: minor, no rewritting
// == MSST_NWAY: store-append: the last partition and new data > existing keys
  static u64
msstz_comp_analyze(struct msstz_comp_info * const ci, const u64 ipart)
{
  const u64 t0 = time_nsec();
  struct msstv_part * const part = &(ci->v0->es[ipart]);
  struct msst * const msst = part->msst;
  // k0 kz
  const struct kv * const k0 = part->anchor;
  debug_assert(k0);
  // kz == NULL for the last partition
  const struct kv * const kz = msstz_comp_get_kz(ci->v0, ipart);
  const struct kvmap_api * const api = ci->api1;
  void * const map = ci->map1;

  void * const ref = kvmap_ref(api, map);
  void * const iter = api->iter_create(ref);
  u64 newsz = 0;
  u32 newnr = 0;
  struct kv * kz_inp = NULL;
  if (kz) { // not the last partition; search where to stop
    struct kref krefz = {.ptr = kz->kv, .len = kz->klen, .hash32 = kv_crc32c(kz->kv, kz->klen)};
    api->iter_seek(iter, &krefz);
    api->iter_inp(iter, kvmap_inp_steal_kv, &kz_inp);
  }

  // check if new key has no overlap
  struct kv * const sst_kz = mssty_last(msst, NULL); // free soon
  struct kv * map_k0 = NULL;

  // start from k0
  struct kref kref0 = {.ptr = k0->kv, .len = k0->klen, .hash32 = kv_crc32c(k0->kv, k0->klen)};
  api->iter_seek(iter, &kref0);
  api->iter_inp(iter, kvmap_inp_steal_kv, &map_k0);
  const bool overlap = sst_kz && map_k0 && (kv_compare(sst_kz, map_k0) >= 0);
  free(sst_kz);

  const u32 sample_skip = 8;
  const u32 sample_mask = sample_skip-1;
  while (api->iter_valid(iter)) {
    struct kv * kv_inp = NULL;
    api->iter_inp(iter, kvmap_inp_steal_kv, &kv_inp);
    if (kv_inp == kz_inp)
      break;
    if ((newnr & sample_mask) == 0)
      newsz += (sst_kv_vi128_estimate(kv_inp) + sizeof(u16));

    newnr++;
    api->iter_skip(iter, 1);
  }
  newsz *= sample_skip;
  api->iter_destroy(iter);
  kvmap_unref(api, ref);

  struct msstz_comp_part * const cpart = &(ci->parts[ipart]);
  cpart->newsz = newsz;

  const struct ssty_meta * const meta = msst->ssty->meta;
  const u32 nway = msst->nway;

  // MAJOR: no existing data at all
  if (meta->valid == 0) { // this also avoids divide-by-zero below
    cpart->ratio = (float)newsz;
    cpart->bestway = 0;
    msstz_log(ci->z, "%s newsz %lu direct-major\n", __func__, newsz);
    return time_diff_nsec(t0);
  }

  // REJECT empty input
  if (newnr == 0) {
    cpart->ratio = 0.0f;
    cpart->bestway = MSSTZ_NWAY_MINOR; // reject
    return time_diff_nsec(t0);
  }

  // APPEND: not too small, store-wide append, partition has some data
  if (!overlap && !kz && nway > 1 && newsz > MSSTZ_ETSZ) {
    cpart->ratio = (float)newsz; // worth doing
    cpart->bestway = MSST_NWAY;
    msstz_log(ci->z, "%s newsz %lu store-append\n", __func__, newsz);
    return time_diff_nsec(t0);
  }

  debug_assert(meta->totsz);
  debug_assert(newsz);
  cpart->ratio = (float)newsz / (float)(meta->totsz);
  // calculate wa[i] if start from way[i]
  // 0: fully rewrite with real deletion
  // 1 to nway-1: partial merge
  // nway: minor compaction (wa == 1)

  debug_assert(meta->uniqx[nway] == 0);
  struct { u64 wx, wy; float nway1, wa, bonus, score; } f[MSST_NWAY+1];

  // wx: data write size
  f[0].wx = newsz + ((u64)meta->valid * meta->totsz / meta->totkv); // major
  for (u32 i = 1; i <= nway; i++)
    f[i].wx = newsz + ((u64)meta->uniqx[i] * meta->totsz / meta->totkv); // major

  // nway1: final way
  // penalty = nway1
  for (u32 i = 0; i <= nway; i++)
    f[i].nway1 = ((float)f[i].wx / (float)MSSTZ_ETSZ) + (float)i;

  // wy: ysize
  f[0].wy = msstz_comp_estimate_ssty(newnr + meta->valid, fminf(f[0].nway1, (float)MSSTZ_NWAY_MINOR));
  u64 totkvi = 0;
  for (u32 i = 1; i <= nway; i++) {
    totkvi += msst->ssts[i-1].totkv;
    f[i].wy = msstz_comp_estimate_ssty(newnr + totkvi + meta->uniqx[i], f[i].nway1);
  }
  // wa: write amp.
  for (u32 i = 0; i <= nway; i++)
    f[i].wa = (float)(f[i].wx + f[i].wy) / (float)newsz;

  // bonus
  for (u32 i = 0; i <= nway; i++)
    f[i].bonus = f[nway].nway1 - f[i].nway1; // how effective can it reduce runs
  // adjust major bonus
  if (f[nway].nway1 > (float)MSSTZ_NWAY_MINOR)
    f[0].bonus += (f[0].nway1 - (float)MSSTZ_NWAY_MAJOR); // large bonus when split is necessary
  // adjust minor bonus
  f[nway].bonus += 1.0; // +1

  u32 bestway = 0; // major by default
  for (u32 i = 0; i <= nway; i++) {
    // score: lower is better
    //const float score = (f[i].wa + sqrtf(f[i].nway1 + 1.0f)) / (f[i].bonus + 4.0f);
    const float score = (f[i].wa + (f[i].nway1 * 0.75f)) / (f[i].bonus + 4.0f);
    f[i].score = score;
    if ((i < MSSTZ_NWAY_MINOR) && (f[i].nway1 < (float)MSSTZ_NWAY_SAFE) && (f[i].score < f[bestway].score))
      bestway = i;
  }
  debug_assert(bestway < MSSTZ_NWAY_MINOR);
  cpart->bestway = bestway; // bestway is determined

  // log some details of the compaction
  for (u32 i = 0; i <= nway; i++) {
    const u64 sz = (i < nway) ? (msst->ssts[i].nblks * PGSZ) : newsz;
    const float pct = ((float)sz) * 100.0f / (float)MSSTZ_TSZ;
    msstz_log(ci->z, "%c[%c%x] sz %9lu %6.2f%% wx %6lu wy %6lu nway1 %4.1f wa %4.1f bonus %4.1f score %5.2f\n",
        (i == bestway ? '>':' '), (i == nway ? '*' : ' '), i,
        sz, pct, f[i].wx, f[i].wy, f[i].nway1, f[i].wa, f[i].bonus, f[i].score);
  }
  const u64 dt = time_diff_nsec(t0);
  msstz_log(ci->z, "%s dt-ms %lu magic0 %lu totkv0 %u valid0 %u newnr %u newsz %lu minor %.1f major %.1f bestway %u ratio %.3f\n",
      __func__, dt / 1000000, meta->magic, meta->totkv, meta->valid,
      newnr, newsz, f[nway].nway1, f[0].nway1, bestway, cpart->ratio);
  return dt;
}

  static void *
msstz_analyze_worker(void * const ptr)
{
  struct msstz_comp_info * const ci = (typeof(ci))ptr;
  const u64 n = ci->v0->nr;
  do {
    const u64 i = ci->seqx++;
    if (i == 0)
      msstz_gc(ci->z);
    if (i >= n)
      return NULL;

    ci->parts[i].idx = i; // assign idx
    ci->time_analyze += msstz_comp_analyze(ci, i);
    ci->totsz += ci->parts[i].newsz;
  } while (true);
}
// }}} analyze

// part {{{
// do compaction in a partition; bestway decides what to do
  static u64
msstz_comp_x(struct msstz_comp_info * const ci, const u64 ipart)
{
  const u64 t0 = time_nsec();
  struct msstz * const z = ci->z;
  struct msstv_part * const part = &(ci->v0->es[ipart]);
  struct msst * const y0 = part->msst;
  struct msstz_comp_part * const cpart = &(ci->parts[ipart]);
  const struct kv * const k0 = part->anchor;
  debug_assert(k0);

  const u64 magic0 = part->anchor->priv;
  const u64 seq0 = magic0 / 100lu; // seq of the old partition
  const u32 nway0 = y0->nway; // seq of the old partition

  if (cpart->bestway == MSSTZ_NWAY_MINOR) { // marked as rejected by msstz_comp()
    // reject: send to yqueue as completed; use seq = UINT64_MAX for real rejections or seq0 for newsz == 0
    msstz_yq_append(ci->yq, y0, cpart->newsz ? UINT64_MAX : seq0, nway0, NULL, 0, ipart, 0, k0); // {y0, seq, ipart, k0} will be used later
    ci->nx++;
    return 0;
  }

  const u32 bestway = cpart->bestway;
  const bool is_append = (bestway == MSST_NWAY);
  const bool is_minor = (bestway == nway0);
  const bool is_major = (bestway == 0);

  debug_assert(bestway <= MSSTZ_NWAY_MINOR || is_append);
  // k0 kz
  // kz == NULL for the last partition
  const struct kv * const kz = msstz_comp_get_kz(ci->v0, ipart);

  // need a new seq unless it's a minor compaction
  // start with a different seq unless it's a minor compaction
  const u64 seq1 = (is_minor || is_append) ? seq0 : (z->seq++);

  struct miter * const miter = miter_create();
  if (bestway < nway0) { // major or partial
    debug_assert(seq1 != seq0);
    // hard link unchanged files for major and partial
    msstz_comp_link(z->dirfd, seq0, seq1, bestway);

    if (bestway) { // partial
      for (u32 w = bestway; w < nway0; w++)
        miter_add(miter, &kvmap_api_sst, &(y0->ssts[w]));
      ci->stat_partial++;
    } else { // major
      miter_add(miter, &kvmap_api_mssty, y0);
      ci->stat_major++;
    }
  } else if (bestway == nway0) { // minor: add nothing
    debug_assert(seq1 == seq0);
    debug_assert(is_minor);
    ci->stat_minor++;
  } else { // append
    debug_assert(seq1 == seq0);
    debug_assert(is_append);
    ci->stat_append++;
  }

  // add the memtable
  miter_add(miter, ci->api1, ci->map1);
  struct kref kref0 = {.ptr = k0->kv, .len = k0->klen, .hash32 = kv_crc32c(k0->kv, k0->klen)};
  miter_seek(miter, &kref0);

  const u32 compway = is_append ? nway0 : bestway;
  // allow split (and gc tombstones) when: major or append
  const bool split = is_major || is_append;
  msstz_comp_ssts(ci, ipart, miter, k0, kz, seq1, compway, split, y0, is_append);
  miter_destroy(miter);
  ci->nx++; // done with one partition's x
  return time_diff_nsec(t0);
}
// }}} part

// driver {{{
  static void
msstz_comp_worker_func(struct msstz_comp_info * const ci)
{
  const u64 n = ci->v0->nr;
  struct coq * const coq = coq_current();
  // x loop
  do {
    const u64 i = ci->seqx++;
    if (i >= n)
      break;

    ci->time_comp_x += msstz_comp_x(ci, i);

    const u64 t0 = time_nsec();
    if (msstz_yq_consume(ci))
      ci->time_comp_y += time_diff_nsec(t0);
  } while (true);

  // process all ssty_build
  struct msstz_yq * const yq = ci->yq;
  while ((ci->nx < ci->n0) || (yq->cseq < yq->pseq)) {
    const u64 t0 = time_nsec();
    const bool r = msstz_yq_consume(ci);
    if (r) {
      ci->time_comp_y += time_diff_nsec(t0);
    } else if (coq) {
      coq_idle(coq);
    } else {
      usleep(1);
    }
  }
}

  static void
msstz_comp_worker_coq_co(void)
{
  void * const priv = co_priv();
  debug_assert(priv);
  msstz_comp_worker_func(priv);
}

// thread
  static void *
msstz_comp_worker(void * const ptr)
{
  struct msstz_comp_info * const ci = (typeof(ci))ptr;
  const u64 nco = ci->co_per_worker;
  if (nco > 1) {
    struct coq * const coq = rcache_coq_create(nco << 2);
    coq_install(coq);
    u64 hostrsp = 0;
    for (u64 i = 0; i < nco; i++) {
      struct co * const co = co_create(PGSZ * 7, msstz_comp_worker_coq_co, ptr, &hostrsp);
      corq_enqueue(coq, co);
    }
    coq_run(coq);
    coq_uninstall();
    rcache_coq_destroy(coq);
  } else {
    debug_assert(nco == 1);
    msstz_comp_worker_func(ci);
  }
  ci->stat_reads += (rcache_thread_stat_reads() * PGSZ);
  return NULL;
}

// for sorting tasks based on their sizes
  static int
msstz_cmp_ratio(const void * p1, const void * p2)
{
  const float r1 = ((const struct msstz_comp_part * const)p1)->ratio;
  const float r2 = ((const struct msstz_comp_part * const)p2)->ratio;
  debug_assert(isfinite(r1));
  debug_assert(isfinite(r2));
  if (r1 < r2) {
    return -1;
  } else if (r1 > r2) {
    return 1;
  } else {
    return 0;
  }
}

  static int
msstz_cmp_idx(const void * p1, const void * p2)
{
  const u64 * const v1 = &(((const struct msstz_comp_part * const)p1)->idx);
  const u64 * const v2 = &(((const struct msstz_comp_part * const)p2)->idx);
  return compare_u64(v1, v2);
}

  static u64
msstz_comp_reject(struct msstz_comp_info * const ci, const u64 max_reject)
{
  const u64 nr = ci->v0->nr;
  qsort(ci->parts, nr, sizeof(ci->parts[0]), msstz_cmp_ratio);

  // reject keys
  u64 rejsz = 0;
  u64 nrej = 0;
  struct msstz * const z = ci->z;
  msstz_log(z, "%s ratio min %.3f max %.3f\n", __func__, ci->parts[0].ratio, ci->parts[nr-1].ratio);
  for (u64 i = 0; i < nr; i++) {
    struct msstz_comp_part * const cp = &(ci->parts[i]);
    // no more rejections
    if ((cp->newsz > z->minsz) || ((rejsz + cp->newsz) > max_reject) || cp->ratio > 0.1f) {
      msstz_log(z, "%s i %lu/%lu (newsz %lu > minsz %lu) || ((rejsz %lu + newsz %lu) > max_reject %lu) || (ratio %.3f > 0.1)\n",
          __func__, i, nr, cp->ratio, cp->newsz, z->minsz, rejsz, cp->newsz, max_reject, cp->ratio);
      break;
    }
    rejsz += cp->newsz;
    nrej++;
    cp->bestway = MSSTZ_NWAY_MINOR; // reject
  }
  msstz_log(z, "%s reject size %lu/%lu np %lu/%lu\n", __func__, rejsz, ci->totsz, nrej, nr);

  // resume idx order
  qsort(ci->parts, nr, sizeof(ci->parts[0]), msstz_cmp_idx);
  return nrej;
}

  static void
msstz_comp_stat(struct msstz_comp_info * const ci)
{
  struct msstz * const z = ci->z;
  const u64 dt = time_diff_nsec(ci->t0);
  const u64 dw = ci->stat_writes;
  const u64 dr = ci->stat_reads;
  z->stat_time += dt;
  z->stat_writes += dw;
  z->stat_reads += dr;
  const u64 ta = ci->time_analyze;
  const u64 tx = ci->time_comp_x;
  const u64 ty = ci->time_comp_y;
  msstz_log(z, "%s dt-s %.6lf dw-mb %lu mbps %lu dr-mb %lu mbps %lu append %lu major %lu partial %lu minor %lu\n",
      __func__, ((double)dt) * 1e-9, dw>>20, (dw<<10)/dt, dr>>20, (dr<<10)/dt,
      ci->stat_append, ci->stat_major, ci->stat_partial, ci->stat_minor);
  msstz_log(z, "%s  dta %lu/%lu %3lu%% dtc (%lu+%lu)/%lu %3lu%%\n",
      __func__, ta/1000000, ci->dta/1000000, ta*100lu/ci->dta,
      tx/1000000, ty/1000000, ci->dtc/1000000, (tx+ty)*100lu/ci->dtc);
}

// comp is not thread safe
// p_min_write: 0 to 100, minimum percentage of data that must be written down
  void
msstz_comp(struct msstz * const z, const struct kvmap_api * const api1, void * const map1,
    const u32 nr_workers, const u32 co_per_worker, const u64 max_reject)
{
  struct msstv * const v0 = msstz_getv(z);
  const u64 nr = v0->nr;
  struct msstz_comp_info * const ci = calloc(1, sizeof(*ci) + (nr * sizeof(ci->parts[0])));
  ci->t0 = time_nsec();
  ci->z = z;
  ci->v0 = v0;
  ci->n0 = nr;
  ci->api1 = api1;
  ci->map1 = map1;
  ci->nr_workers = nr_workers;
  ci->co_per_worker = co_per_worker;

  // concurrent analysis + GC by seq==0
  ci->dta = thread_fork_join(nr_workers, msstz_analyze_worker, false, ci);
  const u64 nrej = msstz_comp_reject(ci, max_reject);
  if (nrej < nr) {
    ci->seqx = 0; // restart from 0
    ci->yq = msstz_yq_create((nr + 64) << 3); // large enough for adding new partitions
    // concurrent compaction
    ci->dtc = thread_fork_join(nr_workers, msstz_comp_worker, false, ci);
    msstz_comp_harvest(ci);
    free(ci->yq);
  } else {
    ci->dtc = 1; // avoid divide by zero
  }

  msstz_putv(z, v0);
  msstz_comp_stat(ci);
  free(ci);
}
// }}} driver

// }}} msstz-comp

// api {{{
//
// *sst* TOMESTONES
// regular functions: iter/get/probe
//   tompstones are treated as regular keys
//   they are always visible with iterators
//   this behavior is required by a few internal functions
//
// _ts functions:
//   tomestones are not visible to caller
const struct kvmap_api kvmap_api_sst = {
  .ordered = true,
  .readonly = true,
  .unique = true,
  .get = (void *)sst_get,
  .probe = (void *)sst_probe,
  .iter_create = (void *)sst_iter_create,
  .iter_seek = (void *)sst_iter_seek,
  .iter_valid = (void *)sst_iter_valid,
  .iter_peek = (void *)sst_iter_peek,
  .iter_kref = (void *)sst_iter_kref,
  .iter_kvref = (void *)sst_iter_kvref,
  .iter_retain = (void *)sst_iter_retain,
  .iter_release = (void *)sst_iter_release,
  .iter_skip = (void *)sst_iter_skip,
  .iter_next = (void *)sst_iter_next,
  .iter_park = (void *)sst_iter_park,
  .iter_destroy = (void *)sst_iter_destroy,
  .destroy = (void *)sst_destroy,
  .fprint = (void *)sst_fprint,
};

const struct kvmap_api kvmap_api_msstx = {
  .ordered = true,
  .readonly = true,
  .unique = false,
  .get = (void *)msstx_get,
  .probe = (void *)msstx_probe,
  .iter_create = (void *)msstx_iter_create,
  .iter_seek = (void *)msstx_iter_seek,
  .iter_valid = (void *)msstx_iter_valid,
  .iter_peek = (void *)msstx_iter_peek,
  .iter_kref = (void *)msstx_iter_kref,
  .iter_kvref = (void *)msstx_iter_kvref,
  .iter_retain = (void *)msstx_iter_retain,
  .iter_release = (void *)msstx_iter_release,
  .iter_skip = (void *)msstx_iter_skip,
  .iter_next = (void *)msstx_iter_next,
  .iter_park = (void *)msstx_iter_park,
  .iter_destroy = (void *)msstx_iter_destroy,
  .destroy = (void *)msstx_destroy,
};

const struct kvmap_api kvmap_api_mssty = {
  .ordered = true,
  .readonly = true,
  .unique = true,
  .get = (void *)mssty_get,
  .probe = (void *)mssty_probe,
  .iter_create = (void *)mssty_iter_create,
  .iter_seek = (void *)mssty_iter_seek,
  .iter_valid = (void *)mssty_iter_valid,
  .iter_peek = (void *)mssty_iter_peek,
  .iter_kref = (void *)mssty_iter_kref,
  .iter_kvref = (void *)mssty_iter_kvref,
  .iter_retain = (void *)mssty_iter_retain,
  .iter_release = (void *)mssty_iter_release,
  .iter_skip = (void *)mssty_iter_skip,
  .iter_next = (void *)mssty_iter_next,
  .iter_park = (void *)mssty_iter_park,
  .iter_destroy = (void *)mssty_iter_destroy,
  .ref = (void *)mssty_ref,
  .unref = (void *)mssty_unref,
  .destroy = (void *)mssty_destroy,
  .fprint = (void *)mssty_fprint,
};

const struct kvmap_api kvmap_api_mssty_ts = {
  .ordered = true,
  .readonly = true,
  .unique = true,
  .get = (void *)mssty_get_ts,
  .probe = (void *)mssty_probe_ts,
  .iter_create = (void *)mssty_iter_create,
  .iter_seek = (void *)mssty_iter_seek_ts,
  .iter_valid = (void *)mssty_iter_valid,
  .iter_peek = (void *)mssty_iter_peek,
  .iter_kref = (void *)mssty_iter_kref,
  .iter_kvref = (void *)mssty_iter_kvref,
  .iter_retain = (void *)mssty_iter_retain,
  .iter_release = (void *)mssty_iter_release,
  .iter_skip = (void *)mssty_iter_skip_ts,
  .iter_next = (void *)mssty_iter_next_ts,
  .iter_park = (void *)mssty_iter_park,
  .iter_destroy = (void *)mssty_iter_destroy,
  .ref = (void *)mssty_ref,
  .unref = (void *)mssty_unref,
  .destroy = (void *)mssty_destroy,
  .fprint = (void *)mssty_fprint,
};

const struct kvmap_api kvmap_api_mssty_dup = {
  .ordered = true,
  .readonly = true,
  .get = (void *)mssty_get,
  .probe = (void *)mssty_probe,
  .iter_create = (void *)mssty_iter_create,
  .iter_seek = (void *)mssty_iter_seek,
  .iter_valid = (void *)mssty_iter_valid,
  .iter_peek = (void *)mssty_iter_peek_dup,
  .iter_kref = (void *)mssty_iter_kref_dup,
  .iter_kvref = (void *)mssty_iter_kvref_dup,
  .iter_retain = (void *)mssty_iter_retain,
  .iter_release = (void *)mssty_iter_release,
  .iter_skip = (void *)mssty_iter_skip_dup,
  .iter_next = (void *)mssty_iter_next_dup,
  .iter_park = (void *)mssty_iter_park,
  .iter_destroy = (void *)mssty_iter_destroy,
  .ref = (void *)mssty_ref,
  .unref = (void *)mssty_unref,
  .destroy = (void *)mssty_destroy,
  .fprint = (void *)mssty_fprint,
};
const struct kvmap_api kvmap_api_msstv = {
  .ordered = true,
  .readonly = true,
  .unique = true,
  .get = (void *)msstv_get,
  .probe = (void *)msstv_probe,
  .iter_create = (void *)msstv_iter_create,
  .iter_seek = (void *)msstv_iter_seek,
  .iter_valid = (void *)msstv_iter_valid,
  .iter_peek = (void *)msstv_iter_peek,
  .iter_kref = (void *)msstv_iter_kref,
  .iter_kvref = (void *)msstv_iter_kvref,
  .iter_retain = (void *)msstv_iter_retain,
  .iter_release = (void *)msstv_iter_release,
  .iter_skip = (void *)msstv_iter_skip,
  .iter_next = (void *)msstv_iter_next,
  .iter_park = (void *)msstv_iter_park,
  .iter_destroy = (void *)msstv_iter_destroy,
  .ref = (void *)msstv_ref,
  .unref = (void *)msstv_unref,
  .destroy = (void *)msstv_destroy,
  .fprint = (void *)msstv_fprint,
};

const struct kvmap_api kvmap_api_msstv_ts = {
  .ordered = true,
  .readonly = true,
  .unique = true,
  .get = (void *)msstv_get_ts,
  .probe = (void *)msstv_probe_ts,
  .iter_create = (void *)msstv_iter_create,
  .iter_seek = (void *)msstv_iter_seek_ts,
  .iter_valid = (void *)msstv_iter_valid,
  .iter_peek = (void *)msstv_iter_peek,
  .iter_kref = (void *)msstv_iter_kref,
  .iter_kvref = (void *)msstv_iter_kvref,
  .iter_retain = (void *)msstv_iter_retain,
  .iter_release = (void *)msstv_iter_release,
  .iter_skip = (void *)msstv_iter_skip_ts,
  .iter_next = (void *)msstv_iter_next_ts,
  .iter_park = (void *)msstv_iter_park,
  .iter_destroy = (void *)msstv_iter_destroy,
  .ref = (void *)msstv_ref,
  .unref = (void *)msstv_unref,
  .destroy = (void *)msstv_destroy,
  .fprint = (void *)msstv_fprint,
};

  static void *
sst_kvmap_api_create(const char * const name, const struct kvmap_mm * const mm, char ** args)
{
  (void)mm;
  if (!strcmp(name, "sst")) {
    return sst_open(args[0], a2u64(args[1]), a2u32(args[2]));
  } else if (!strcmp(name, "msstx")) {
    return msstx_open(args[0], a2u64(args[1]), a2u32(args[2]));
  } else if ((!strcmp(name, "mssty")) || (!strcmp(name, "mssty_ts")) || (!strcmp(name, "mssty_dup"))) {
    return mssty_open(args[0], a2u64(args[1]), a2u32(args[2]));
  } else if ((!strcmp(name, "msstv")) || (!strcmp(name, "msstv_ts"))) {
    return msstv_open(args[0], args[1]);
  } else {
    return NULL;
  }
}

// alternatively, call the register function from main()
__attribute__((constructor))
  static void
sst_kvmap_api_init(void)
{
  kvmap_api_register(3, "sst", "<dirname> <seq> <way>", sst_kvmap_api_create, &kvmap_api_sst);
  kvmap_api_register(3, "msstx", "<dirname> <seq> <nway>", sst_kvmap_api_create, &kvmap_api_msstx);
  kvmap_api_register(3, "mssty", "<dirname> <seq> <nway>", sst_kvmap_api_create, &kvmap_api_mssty);
  kvmap_api_register(3, "mssty_ts", "<dirname> <seq> <nway>", sst_kvmap_api_create, &kvmap_api_mssty_ts);
  kvmap_api_register(3, "mssty_dup", "<dirname> <seq> <nway>", sst_kvmap_api_create, &kvmap_api_mssty_dup);
  kvmap_api_register(2, "msstv", "<dirname> <filename>", sst_kvmap_api_create, &kvmap_api_msstv);
  kvmap_api_register(2, "msstv_ts", "<dirname> <filename>", sst_kvmap_api_create, &kvmap_api_msstv_ts);
}
// }}} api

// vim:fdm=marker
