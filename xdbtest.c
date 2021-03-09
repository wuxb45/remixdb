/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

#include "ctypes.h"
#include "lib.h"
#include "kv.h"
#include "sst.h"
#include "xdb.h"

struct xdb * xdb;
static u64 nkeys = 0;
static u64 nupdate = 0;
static u64 min_stale = 0;
static u8 * magics = NULL;
u32 nths_update = 0;
u32 nths_getscan = 0;

static u64 epoch = 0;
au64 all_seq;
au64 all_stale;
au64 all_found;

  static void *
update_worker(void * const ptr)
{
  (void)ptr;
  srandom_u64(time_nsec());
  const u64 seq = atomic_fetch_add(&all_seq, 1);
  const u64 range = nkeys / nths_update;
  const u64 mask = range - 1;
  const u64 base = seq * range;
  struct xdb_ref * const ref = remixdb_ref(xdb);
  u8 ktmp[16];
  u8 * const vtmp = calloc(1, 1lu << 16);
  memset(vtmp, (int)random_u64(), 1lu << 16);

  //printf("random update [%lu, %lu]\n", base, base+mask);
  // set/del
  for (u64 i = 0; i < nupdate; i++) {
    const u64 r = random_u64();
    const u64 k = base + ((r >> 8) & mask);
    const u8 v = r & 0xff;
    vtmp[0] = v;
    magics[k] = v;
    strhex_64(ktmp, k);

    if (v == 0) { // delete
      remixdb_del(ref, ktmp, 16);
    } else { // update
      const u32 vlen = ((i & 0x3fffu) != 0x1357u) ? (((u32)r & 0xf0) + 100) : ((((u32)r & 0xf0) << 6) + 4200);
      remixdb_set(ref, ktmp, 16, vtmp, vlen);
    }
  }

  remixdb_unref(ref);
  free(vtmp);
  return NULL;
}

  static void *
getscan_worker(void * const ptr)
{
  (void)ptr;
  const u64 seq = atomic_fetch_add(&all_seq, 1);
  const u64 unit = nkeys / nths_getscan + 1;
  const u64 min = unit * seq;
  const u64 max0 = min + unit;
  const u64 max = nkeys < max0 ? nkeys : max0;

  struct xdb_ref * const ref = remixdb_ref(xdb);

  u8 ktmp[16];
  u8 * const out = calloc(1, 1lu << 16);
  u32 vlen_out = 0;

  // get seq
  u64 stale = 0;
  for (u64 i = min; i < max; i++) {
    strhex_64(ktmp, i);
    const bool r = remixdb_get(ref, ktmp, 16, out, &vlen_out);
    if ((r ? out[0] : 0) != magics[i])
      stale++;
  }

  u32 klen_out;
  u8 kend[16];
  strhex_64(ktmp, min);
  strhex_64(kend, max);
  struct xdb_iter * const iter = remixdb_iter_create(ref);
  remixdb_iter_seek(iter, ktmp, 16);
  memset(ktmp, 0, 16);

  // scan
  u64 found = 0;
  while (remixdb_iter_valid(iter)) {
    remixdb_iter_peek(iter, ktmp, &klen_out, NULL, NULL);
    debug_assert(klen_out == 16);
    if (memcmp(ktmp, kend, 16) < 0) {
      found++;
      remixdb_iter_skip(iter, 1);
    } else {
      break;
    }
  }

  //printf("get [%lu, %lu] stale %lu found %lu\n", min, max-1, stale, found);
  atomic_fetch_add(&all_stale, stale);
  atomic_fetch_add(&all_found, found);

  remixdb_iter_destroy(iter);
  remixdb_unref(ref);
  free(out);
  return NULL;
}

  int
main(int argc, char** argv)
{
  if (argc < 5) {
    printf("Usage: <dirname> <mem-mb> <data-power> <update-power> [<epochs>]\n");
    printf("    Block cache and MemTable(s) will use <mem-mb>; the actual usage can be 3*mb\n");
    printf("    WAL size = 2*mb\n");
    return 0;
  }

  const u64 memsz = a2u64(argv[2]);
  const u64 dpower = a2u64(argv[3]);
  const u64 upower = a2u64(argv[4]);

  xdb = remixdb_open(argv[1], memsz, memsz);
  if (!xdb) {
    fprintf(stderr, "xdb_open failed\n");
    return 0;
  }

  nkeys = 1lu << dpower;
  if (nkeys < 1024)
    nkeys = 1024;
  nupdate = 1lu << upower;

  min_stale = nkeys;
  magics = calloc(nkeys, 1);
  nths_update = nths_getscan = process_affinity_count();
  if (nths_update == 0)
    debug_die();
  while (__builtin_popcount(nths_update) > 1)
    nths_update--;
  printf("write threads %u check threads %u\n", nths_update, nths_getscan);

  debug_assert(magics);
  const u32 ne = (argc < 6) ? 1000000 : a2u32(argv[5]);

  for (u32 i = 0; i < ne; i++) {
    epoch = i;

    all_seq = 0;
    const u64 dt = thread_fork_join(nths_update, update_worker, false, NULL);
    if ((epoch & 0x3u) == 0x3u) { // close/open every 4 epochs
      remixdb_close(xdb);
      // turn on/off ckeys alternatively, very stressful.
      xdb = (epoch & 1) ? remixdb_open(argv[1], memsz, memsz) : remixdb_open_compact(argv[1], memsz, memsz);
      if (xdb) {
        printf("reopen remixdb ok\n");
      } else {
        printf("reopen failed\n");
        exit(0);
      }
    }
    all_stale = 0;
    all_found = 0;
    all_seq = 0;
    (void)thread_fork_join(nths_getscan, getscan_worker, false, NULL);

    char ts[64];
    time_stamp(ts, sizeof(ts));
    const u64 nr = nupdate * nths_update;
    printf("[%4lu] %s put/del nr %lu mops %.3lf keyrange %lu keycount %lu stale %lu\n",
        epoch, ts, nr, (double)nr / (double)dt * 1e3, nkeys, all_found, all_stale);

    if (all_stale > min_stale)
      debug_die();
    min_stale = all_stale;
  }
  free(magics);
  remixdb_close(xdb);
  return 0;
}
