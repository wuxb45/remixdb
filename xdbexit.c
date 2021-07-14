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

  struct xdb * const xdb = remixdb_open(argv[1], a2u64(argv[2]), a2u64(argv[3]), true);
  if (!xdb) {
    fprintf(stderr, "xdb_open failed\n");
    return 0;
  }
  struct xdb_ref * const ref = remixdb_ref(xdb);

  struct xdb_iter * const iter = remixdb_iter_create(ref);
  u64 kid = 0;
  remixdb_iter_seek(iter, "", 0);
  remixdb_iter_skip(iter, 1000);
  u8 key[20];
  u8 keycmp[20];
  u32 klen = 0;
  while (remixdb_iter_valid(iter)) {
    kid += 1000;
    remixdb_iter_peek(iter, key, &klen, NULL, NULL);
    strdec_64(keycmp, kid);
    if (memcmp(key, keycmp, 20)) {
      printf("key mismatch at %lu; delete %s and restart the loop\n", kid, argv[1]);
      exit(0);
    }
    remixdb_iter_skip(iter, 1000);
  }

  u64 count = kid;
  remixdb_iter_seek(iter, "", 0);
  remixdb_iter_skip(iter, kid);
  while (remixdb_iter_valid(iter)) {
    remixdb_iter_peek(iter, key, &klen, NULL, NULL);
    remixdb_iter_skip1(iter);
    strdec_64(keycmp, count);
    count++;
    if (memcmp(key, keycmp, 20)) {
      printf("key mismatch at %lu; delete %s and restart loop again\n", count, argv[1]);
      exit(0);
    }
  }
  printf("found %lu keys, last %.20s OK\n", count, key);
  remixdb_iter_destroy(iter);

  u8 value[1024];
  memset(value, 0x11, 1024);
#define NEW ((100000))
  for (u64 i = 0; i < NEW; i++) {
    strdec_64(key, count + i);
    remixdb_put(ref, key, 20, value, 1024);
  }
  printf("insert [%lu, %lu]; now exit()\n", count, count + NEW - 1);
  remixdb_sync(ref);
  exit(0);
  return 0;
}
