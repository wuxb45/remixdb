/*
 * Copyright (c) 2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#include <stdio.h>

#include "lib.h"
#include "kv.h"
#include "xdb.h"

  int
main(int argc, char ** argv)
{
  (void)argc;
  (void)argv;
  struct xdb * const xdb = remixdb_open("/tmp/xdbdemo", 256, 256); // blockcache=256MB, MemTable=256MB
  struct xdb_ref * const ref = remixdb_ref(xdb);

  bool r;

  r = remixdb_set(ref, "remix", 5, "easy", 4);
  printf("remixdb_set remix easy %c\n", r?'T':'F');

  r = remixdb_set(ref, "time_travel", 11, "impossible", 10);
  printf("remixdb_set time_travel impossible %c\n", r?'T':'F');

  r = remixdb_del(ref, "time_travel", 11);
  printf("remixdb_del time_travel %c\n", r?'T':'F');

  r = remixdb_probe(ref, "time_travel", 11);
  printf("remixdb_probe time_travel %c\n", r?'T':'F');

  u32 klen_out = 0;
  char kbuf_out[8] = {};
  u32 vlen_out = 0;
  char vbuf_out[8] = {};
  r = remixdb_get(ref, "remix", 5, vbuf_out, &vlen_out);
  printf("remixdb_get remix %c %u %.*s\n", r?'T':'F', vlen_out, vlen_out, vbuf_out);

  // prepare a few keys for range ops
  remixdb_set(ref, "00", 2, "0_value", 7);
  remixdb_set(ref, "11", 2, "1_value", 7);
  remixdb_set(ref, "22", 2, "2_value", 7);

  struct xdb_iter * const iter = remixdb_iter_create(ref);

  remixdb_iter_seek(iter, NULL, 0); // seek to the head
  printf("remixdb_iter_seek \"\"\n");
  while (remixdb_iter_valid(iter)) {
    r = remixdb_iter_peek(iter, kbuf_out, &klen_out, vbuf_out, &vlen_out);
    if (r) {
      printf("remixdb_iter_peek klen=%u key=%.*s vlen=%u value=%.*s\n",
          klen_out, klen_out, kbuf_out, vlen_out, vlen_out, vbuf_out);
    } else {
      printf("ERROR!\n");
    }
    remixdb_iter_skip(iter, 1);
  }

  // call iter_park if you will go idle but want to use the iter later
  // don't need to call iter_park if you're actively using iter
  remixdb_iter_park(iter);
  usleep(10);

  remixdb_iter_seek(iter, "0", 1);
  printf("remixdb_iter_seek \"0\"\n");
  // this time we don't want to copy the value
  r = remixdb_iter_peek(iter, kbuf_out, &klen_out, NULL, NULL);
  if (r){
    printf("remixdb_iter_peek klen=%u key=%.*s\n", klen_out, klen_out, kbuf_out);
  } else {
    printf("ERROR: iter_peek failed\n");
  }

  remixdb_iter_destroy(iter);
  // there must be no active iter when calling unref()
  remixdb_unref(ref);

  // unsafe operations: should have released all references
  remixdb_close(xdb); // destroy also calls clean interally
  return 0;
}
