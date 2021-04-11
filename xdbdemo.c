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
  // Use a small config for demo
  // In a moderate setup the recommended numbers are 4096 for both
  struct xdb * const xdb = remixdb_open("./xdbdemo", 256, 256); // blockcache=256MB, MemTable=256MB

  // A ref is required to perform the following DB operations.
  // A thread should maintain a ref and keep using it.
  // Different threads should use different refs.
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

  // Make all the data persistent in the log.
  // Performing sync is expensive.
  remixdb_sync(ref);

  // range operations
  struct xdb_iter * const iter = remixdb_iter_create(ref);

  printf("remixdb_iter_seek \"\" (zero-length string)\n");
  remixdb_iter_seek(iter, NULL, 0); // seek to the first key
  // You can actually insert an zero-size key to the store. (0 <= klen, klen+vlen <= 65500)

  while (remixdb_iter_valid(iter)) { // check whether the iter points to a valid KV pair
    r = remixdb_iter_peek(iter, kbuf_out, &klen_out, vbuf_out, &vlen_out);
    if (r) {
      printf("remixdb_iter_peek klen=%u key=%.*s vlen=%u value=%.*s\n",
          klen_out, klen_out, kbuf_out, vlen_out, vlen_out, vbuf_out);
    } else {
      printf("ERROR!\n");
    }
    remixdb_iter_skip1(iter);
  }

  // This is OPTIONAL!
  // an iter can hold some (reader) locks.
  // Other (writer) threads can be blocked by active iters.
  // call iter_park to release those resources when you need to go idle
  // don't need to call iter_park if you're actively using the iter
  remixdb_iter_park(iter);
  usleep(10);

  // after calling iter_park, you must perform a seek() to proceed with other operations.
  printf("remixdb_iter_seek \"0\" (key_length=1)\n");
  remixdb_iter_seek(iter, "0", 1);
  // this time we don't want to copy the value
  r = remixdb_iter_peek(iter, kbuf_out, &klen_out, NULL, NULL);
  if (r){
    printf("remixdb_iter_peek klen=%u key=%.*s\n", klen_out, klen_out, kbuf_out);
  } else {
    printf("ERROR: iter_peek failed\n");
  }

  remixdb_iter_destroy(iter);
  // there must be no active iters when we call unref()
  remixdb_unref(ref);

  // close is not thread-safe
  // other threads must have released their references when you call close()
  remixdb_close(xdb);
  return 0;
}
