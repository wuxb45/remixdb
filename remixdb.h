/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

struct xdb;
struct xdb_ref;
struct xdb_iter;

  extern struct xdb *
remixdb_open(const char * const dir, const size_t cache_size_mb, const size_t mt_size_mb);

  extern struct xdb *
remixdb_open_compact(const char * const dir, const size_t cache_size_mb, const size_t mt_size_mb);

  extern struct xdb_ref *
remixdb_ref(struct xdb * const xdb);

  extern void
remixdb_unref(struct xdb_ref * const ref);

  extern void
remixdb_close(struct xdb * const xdb);

  extern bool
remixdb_set(struct xdb_ref * const ref, const void * const kbuf, const uint32_t klen,
    const void * const vbuf, const uint32_t vlen);

  extern bool
remixdb_del(struct xdb_ref * const ref, const void * const kbuf, const uint32_t klen);

  extern bool
remixdb_probe(struct xdb_ref * const ref, const void * const kbuf, const uint32_t klen);

  extern bool
remixdb_get(struct xdb_ref * const ref, const void * const kbuf, const uint32_t klen,
    void * const vbuf_out, uint32_t * const vlen_out);

  extern struct xdb_iter *
remixdb_iter_create(struct xdb_ref * const ref);

  extern void
remixdb_iter_seek(struct xdb_iter * const iter, const void * const kbuf, const uint32_t klen);

  extern bool
remixdb_iter_valid(struct xdb_iter * const iter);

  extern bool
remixdb_iter_peek(struct xdb_iter * const iter,
    void * const kbuf_out, uint32_t * const klen_out,
    void * const vbuf_out, uint32_t * const vlen_out);

  extern void
remixdb_iter_skip(struct xdb_iter * const iter, const uint32_t nr);

  extern void
remixdb_iter_park(struct xdb_iter * const iter);

  extern void
remixdb_iter_destroy(struct xdb_iter * const iter);

#ifdef __cplusplus
}
#endif
// vim:fdm=marker
