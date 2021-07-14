/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#pragma once

#include "lib.h"
#include "kv.h"

#ifdef __cplusplus
extern "C" {
#endif

struct xdb;
struct xdb_ref;
struct xdb_iter;

// xdb {{{
  extern struct xdb *
xdb_open(const char * const dir, const size_t cache_size_mb, const size_t mt_size_mb, const size_t wal_size_mb,
    const bool ckeys, const bool tags, const u32 nr_workers, const u32 co_per_worker, const char * const worker_cores);

  extern void
xdb_close(struct xdb * const xdb);

// kvmap_api
  extern struct xdb_ref *
xdb_ref(struct xdb * const xdb);

  extern struct xdb*
xdb_unref(struct xdb_ref * const ref);

  extern struct kv *
xdb_get(struct xdb_ref * const ref, const struct kref * const kref, struct kv * const out);

  extern bool
xdb_probe(struct xdb_ref * const ref, const struct kref * const kref);

  extern bool
xdb_put(struct xdb_ref * const ref, const struct kv * const kv);

  extern bool
xdb_del(struct xdb_ref * const ref, const struct kref * const kref);

  extern void
xdb_sync(struct xdb_ref * const ref);

// AKA Atomic Read-Modify-Write
// A merge can fail without doing anything due to allocate failures
// uf() can be invoked multiple times due to abort and retry (these are not errors)
// The last invocation will take the actual effect if it is successful
// The returned kvs will be ignored except for the last one (returned by the last call to uf)
// Memory allocated by uf must be freed by the caller after xdb_merge has returned
// The uf can perform in-place update if kv0 is not NULL (just return kv0 from uf())
// An in-place update may still cause an memtable insertion if kv0 was not from the memtable (loaded from a partition)
  extern bool
xdb_merge(struct xdb_ref * const ref, const struct kref * const kref, kv_merge_func uf, void * const priv);

// iter
  extern struct xdb_iter *
xdb_iter_create(struct xdb_ref * const ref);

  extern void
xdb_iter_park(struct xdb_iter * const iter);

  extern void
xdb_iter_seek(struct xdb_iter * const iter, const struct kref * const key);

  extern bool
xdb_iter_valid(struct xdb_iter * const iter);

  extern struct kv *
xdb_iter_peek(struct xdb_iter * const iter, struct kv * const out);

  extern bool
xdb_iter_kref(struct xdb_iter * const iter, struct kref * const kref);

  extern bool
xdb_iter_kvref(struct xdb_iter * const iter, struct kvref * const kvref);

  extern void
xdb_iter_skip1(struct xdb_iter * const iter);

  extern void
xdb_iter_skip(struct xdb_iter * const iter, u32 n);

  extern struct kv*
xdb_iter_next(struct xdb_iter * const iter, struct kv * const out);

  extern void
xdb_iter_destroy(struct xdb_iter * const iter);

extern const struct kvmap_api kvmap_api_xdb;
// }}} xdb

// remixdb {{{
  extern struct xdb *
remixdb_open(const char * const dir, const size_t cache_size_mb, const size_t mt_size_mb, const bool tags);

  extern struct xdb *
remixdb_open_compact(const char * const dir, const size_t cache_size_mb, const size_t mt_size_mb);

  extern struct xdb_ref *
remixdb_ref(struct xdb * const xdb);

  extern void
remixdb_unref(struct xdb_ref * const ref);

  extern void
remixdb_close(struct xdb * const xdb);

  extern bool
remixdb_put(struct xdb_ref * const ref, const void * const kbuf, const u32 klen,
    const void * const vbuf, const u32 vlen);

  extern bool
remixdb_del(struct xdb_ref * const ref, const void * const kbuf, const u32 klen);

  extern bool
remixdb_probe(struct xdb_ref * const ref, const void * const kbuf, const u32 klen);

  extern bool
remixdb_get(struct xdb_ref * const ref, const void * const kbuf, const u32 klen,
    void * const vbuf_out, u32 * const vlen_out);

  extern void
remixdb_sync(struct xdb_ref * const ref);

  extern struct xdb_iter *
remixdb_iter_create(struct xdb_ref * const ref);

  extern void
remixdb_iter_seek(struct xdb_iter * const iter, const void * const kbuf, const u32 klen);

  extern bool
remixdb_iter_valid(struct xdb_iter * const iter);

  extern bool
remixdb_iter_peek(struct xdb_iter * const iter,
    void * const kbuf_out, u32 * const klen_out,
    void * const vbuf_out, u32 * const vlen_out);

  extern void
remixdb_iter_skip1(struct xdb_iter * const iter);

  extern void
remixdb_iter_skip(struct xdb_iter * const iter, const u32 nr);

  extern void
remixdb_iter_park(struct xdb_iter * const iter);

  extern void
remixdb_iter_destroy(struct xdb_iter * const iter);
// }}} remixdb

#ifdef __cplusplus
}
#endif
// vim:fdm=marker
