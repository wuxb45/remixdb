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

  int
main(int argc, char** argv)
{
  if (argc < 4) {
    printf("Usage: <dirname> <mt-mb> <cache-mb>\n");
    return 0;
  }

  struct xdb * const xdb = remixdb_open(argv[1], a2u64(argv[2]), a2u64(argv[3]));
  if (!xdb) {
    fprintf(stderr, "xdb_open failed\n");
    return 0;
  }
  struct xdb_ref * const ref = remixdb_ref(xdb);

  u64 k0 = 0;
  u8 key[20];
  for (;;) {
    strdec_64(key, k0);
    if (!remixdb_probe(ref, key, 20)) {
      printf("first missing %lu\n", k0);
      break;
    }
    k0++;
  }

  u8 value[1024];
  memset(value, 0x11, 1024);
  for (u64 i = 0; i < 1000000; i++) {
    strdec_64(key, k0 + i);
    remixdb_set(ref, key, 20, value, 1024);
  }
  printf("inserted [%lu, %lu)\n", k0, k0 + 1000000);
  remixdb_sync(ref);
  exit(0);
  return 0;
}
