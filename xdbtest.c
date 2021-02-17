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

static u8 * magics = NULL;
static u64 minstale = 0;

  static void
run_update(struct xdb * const xdb, const u32 epoch, const u64 range)
{
  struct xdb_ref * const ref = remixdb_ref(xdb);
  const u64 mask = range - 1;
  u8 ktmp[16];
  u8 * const vtmp = calloc(1, 1lu << 16);
  memset(vtmp, random_u64(), 1lu << 16);

  // set/del
  const double t0 = time_sec();
#define SET_NR ((10000000))
  for (u32 i = 0; i < SET_NR; i++) { // 10M operations
    const u64 r = random_u64();
    const u64 k = (r >> 8) & mask;
    const u8 v = r & 0xff;
    vtmp[0] = v;
    magics[k] = v;
    strhex_64(ktmp, k);

    if (v == 0) { // delete
      remixdb_del(ref, ktmp, 16);
    } else { // update
      const u32 vlen = ((i & 0x3fffu) != 0x1357u) ? ((r & 0xf0) + 100) : (((r & 0xf0) << 6) + 4200);
      remixdb_set(ref, ktmp, 16, vtmp, vlen);
    }
  }

  const double dt = time_diff_sec(t0);
  char ts[64];
  time_stamp(ts, sizeof(ts));
  printf("[%3u] %s put/del dt %6.3lf mops %6.3lf\n", epoch, ts, dt, (double)SET_NR / dt * 1e-6);

  remixdb_unref(ref);
  free(vtmp);
}

  static void
run_getscan(struct xdb * const xdb, const u32 epoch, const u64 range)
{
  struct xdb_ref * const ref = remixdb_ref(xdb);
  u8 ktmp[16];
  u8 * const out = calloc(1, 1lu << 16);
  u32 vlen_out;

  // get
  u64 stale = 0;
  u64 nr = 0; // to count the expected number of keys
  const double t0 = time_sec();
  for (u64 i = 0; i < range; i++) { // range operations
    strhex_64(ktmp, i);
    const bool r = remixdb_get(ref, ktmp, 16, out, &vlen_out);
    if ((r ? out[0] : 0) != magics[i])
      stale++;
    if (magics[i])
      nr++;
  }
  const double dt = time_diff_sec(t0);
  if (stale > minstale)
    debug_die();
  minstale = stale;

  // scan
  u64 nr1 = 0;
  u32 klen_out;
  struct xdb_iter * const iter = remixdb_iter_create(ref);
  for (u64 i = 0; i < 1024; i++) {
    // seek to the first
    const u64 k0 = (range >> 10) * i;
    strhex_64(ktmp, k0);
    remixdb_iter_seek(iter, ktmp, 16);
    memset(ktmp, 0, 16);

    // prepare the end
    const u64 k1 = (range >> 10) * (i+1);
    u8 kend[16];
    strhex_64(kend, k1);

    // scan
    while (remixdb_iter_valid(iter)) {
      remixdb_iter_peek(iter, ktmp, &klen_out, NULL, NULL);
      debug_assert(klen_out == 16);
      if (memcmp(ktmp, kend, 16) < 0) {
        nr1++;
        remixdb_iter_skip(iter, 1);
      } else {
        break;
      }
    }
  }

  char ts[64];
  time_stamp(ts, sizeof(ts));
  printf("[%3u] %s probe dt %6.3lf mops %6.3lf expected %lu found %lu stale %lu\n",
      epoch, ts, dt, (double)range / dt * 1e-6, nr, nr1, stale);
  if (nr + stale != nr1)
    printf("error: expected + stale != found\n");

  remixdb_iter_destroy(iter);
  remixdb_unref(ref);
  free(out);
}

  int
main(int argc, char** argv)
{
  if (argc < 4) {
    printf("Usage: <dirname> <mem-mb> <power> [<epochs>]\n");
    printf("    Block cache and MemTable(s) will use <mem-mb>; the actual usage can be 3*mb\n");
    printf("    WAL size = 2*mb\n");
    return 0;
  }

  const u64 memsz = a2u64(argv[2]);
  const u64 power = a2u64(argv[3]);
  if (power > 30) {
    printf("maximum power is 30\n");
    return 0;
  }
  struct xdb * xdb = remixdb_open(argv[1], memsz, memsz);
  if (!xdb) {
    fprintf(stderr, "xdb_open failed\n");
    return 0;
  }

  const u64 range = 1lu << power;
  minstale = range;
  magics = calloc(range, 1);
  debug_assert(magics);
  const u32 ne = (argc < 5) ? 1000000 : a2u32(argv[4]);

  for (u32 e = 0; e < ne; e++) { // epoch
    run_update(xdb, e, range);
    if ((e & 0x7u) == 0x7u) { // close/open every 8 epochs
      remixdb_close(xdb);
      xdb = (e&1) ? remixdb_open(argv[1], memsz, memsz) : remixdb_open_compact(argv[1], memsz, memsz);
      if (xdb) {
        printf("reopen remixdb ok\n");
      } else {
        printf("reopen failed\n");
        exit(0);
      }
    }
    run_getscan(xdb, e, range);
  }
  free(magics);
  remixdb_close(xdb);
  return 0;
}
