/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

#include "lib.h"
#include "kv.h"
#include "sst.h"
#include "xdb.h"

static u8 * baseline = NULL;
static u64 minerr = 0;

  static void
run_epoch(void * const xdb, const u32 epoch, const u64 range)
{
  const struct kvmap_api* api = &kvmap_api_xdb;
  const u64 mask = range - 1;
  struct kv * const tmp = calloc(1, 1lu << 16);
  struct kv * const out = calloc(1, 1lu << 16);
  memset(tmp, random_u64(), 1lu << 16);
  struct kref kref;
  void * const ref = api->ref(xdb);

#define SET_NR ((10000000))
  // set/del
  const double a0 = time_sec();
  for (u32 i = 0; i < SET_NR; i++) { // 10M operations
    const u64 r = random_u64();
    const u64 k = (r >> 8) & mask;
    const u8 v = r & 0xff;
    kv_refill_hex64_klen(tmp, k, 16, NULL, 0);
    tmp->kv[16] = v;
    baseline[k] = v;

    if (v == 0) { // delete
      kref_ref_kv(&kref, tmp);
      api->del(ref, &kref);
    } else {
      tmp->vlen = ((i & 0x3fffu) != 0x1357u) ? ((r & 0xf0) + 100) : (((r & 0xf0) << 6) + 4200);
      api->set(ref, tmp);
    }
  }
  const double da = time_diff_sec(a0);

  // get
  const double b0 = time_sec();
  u64 err = 0;
  u64 nr = 0;
  for (u64 i = 0; i < range; i++) { // range operations
    kv_refill_hex64_klen(tmp, i, 16, NULL, 0);
    kref_ref_kv(&kref, tmp);
    struct kv * const ret = api->get(ref, &kref, out);
    if ((ret ? ret->kv[16] : 0) != baseline[i])
      err++;
    if (baseline[i])
      nr++;
  }
  const double db = time_diff_sec(b0);
  if (err > minerr)
    debug_die();
  minerr = err;

  // count
  u64 cnt = 0;
  for (u64 i = 0; i < range; i++) {
    if (baseline[i])
      cnt++;
  }

  u64 nr1 = 0;
  void * const iter = api->iter_create(ref);
  struct kv * const kv1 = malloc(64);
  struct kref kref1;
  for (u64 i = 0; i < 64; i++) {
    const u64 k0 = (range >> 6) * i;
    kv_refill_hex64_klen(tmp, k0, 16, NULL, 0);
    kref_ref_kv(&kref, tmp);
    api->iter_seek(iter, &kref);
    const u64 k1 = (range >> 6) * (i+1);
    kv_refill_hex64_klen(kv1, k1, 16, NULL, 0);
    kref_ref_kv(&kref1, kv1);
    while (api->iter_valid(iter)) {
      api->iter_kref(iter, &kref);
      if (kref_compare(&kref, &kref1) < 0) {
        nr1++;
        api->iter_skip(iter, 1);
      } else {
        break;
      }
    }
  }
  free(kv1);

  api->iter_destroy(iter);
  (void)api->unref(ref);
  char ts[64];
  time_stamp(ts, sizeof(ts));
  printf("[%3u] %s put/del dt %6.3lf mops %6.3lf probe dt %6.3lf mops %6.3lf nr %lu==%lu/%lu err %lu\n",
      epoch, ts, da, (double)SET_NR / da * 1e-6, db, (double)range / db * 1e-6, nr, nr1, range, err);
  free(tmp);
  free(out);
}

  int
main(int argc, char** argv)
{
  if (argc < 4) {
    printf("Usage: <dirname> <mem-size-mb> <power> [<epochs>]\n");
    printf("    Block cache and MemTable(s) will use <mem-size-mb>; the actual usage can be 3*mb\n");
    printf("    WAL size = 2*mb\n");
    return 0;
  }

  const u64 memsz = a2u64(argv[2]);
  const u64 power = a2u64(argv[3]);
  if (power > 30) {
    printf("maximum power is 30\n");
    return 0;
  }
  void * xdb = xdb_open(argv[1], memsz, memsz, memsz<<1, 4, 1, true);
  if (!xdb) {
    fprintf(stderr, "xdb_open failed\n");
    return 0;
  }

  const u64 range = 1lu << power;
  minerr = range;
  baseline = calloc(range, 1);
  debug_assert(baseline);
  const u32 ne = (argc < 5) ? 1000000 : a2u32(argv[4]);

  for (u32 e = 0; e < ne; e++) { // epoch
    run_epoch(xdb, e, range);
    if ((e & 0xfu) == 0xfu) { // close/open every 16 epochs
      xdb_close(xdb);
      xdb = xdb_open(argv[1], memsz, memsz, memsz<<1, (e & 3) + 1, 1, (e&1) == 0);
      if (xdb) {
        printf("reopen xdb ok\n");
      } else {
        printf("xdb_open failed\n");
        return 0;
      }
    }
  }
  free(baseline);
  xdb_close(xdb);
  return 0;
}
