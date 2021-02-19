/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#pragma once

#include "blkio.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SST_VLEN_TS ((0x10000u)) // tomb stone
#define SST_VLEN_MASK ((0xffffu)) // real vlen == vlen & 0xffff

// kv {{{
  extern size_t
sst_kv_vi128_estimate(const struct kv * const kv);

  extern u8 *
sst_kv_vi128_encode(u8 * ptr, const struct kv * const kv);

  extern size_t
sst_kv_size(const struct kv * const kv);

  extern u64
sst_kvmap_estimate(const struct kvmap_api * const api, void * const map,
    const struct kref * const k0, const struct kref * const kz);

  extern struct kv *
sst_kvref_dup2_kv(struct kvref * const kvref, struct kv * const out);
// }}} kv

// mm {{{

  extern struct kv *
kvmap_mm_in_ts(struct kv * const kv, void * const priv);

  extern struct kv *
kvmap_mm_out_ts(struct kv * const kv, struct kv * const out);

extern const struct kvmap_mm kvmap_mm_ts;
// }}} mm

// sst {{{
struct sst;

  extern struct sst *
sst_open(const char * const dirname, const u64 seq, const u32 way);

  extern const struct sst_meta *
sst_meta(struct sst * const sst);

  extern void
sst_rcache(struct sst * const sst, struct rcache * const rc);

  extern struct kv *
sst_get(struct sst * const map, const struct kref * const key, struct kv * const out);

  extern bool
sst_probe(struct sst* const map, const struct kref * const key);

  extern void
sst_destroy(struct sst * const map);

  extern void
sst_dump(struct sst * const sst, const char * const fn);

  extern void
sst_fprint(struct sst * const map, FILE * const out);

struct sst_iter;

  extern struct sst_iter *
sst_iter_create(struct sst * const sst);

  extern bool
sst_iter_ts(struct sst_iter * const iter);

  extern void
sst_iter_seek(struct sst_iter * const iter, const struct kref * const key);

  extern void
sst_iter_seek_null(struct sst_iter * const iter);

  extern bool
sst_iter_valid(struct sst_iter * const iter);

  extern struct kv *
sst_iter_peek(struct sst_iter * const iter, struct kv * const out);

  extern bool
sst_iter_kref(struct sst_iter * const iter, struct kref * const kref);

  extern bool
sst_iter_kvref(struct sst_iter * const iter, struct kvref * const kvref);

  extern u64
sst_iter_retain(struct sst_iter * const iter);

  extern void
sst_iter_release(struct sst_iter * const iter, const u64 opaque);

  extern void
sst_iter_skip(struct sst_iter * const iter, const u32 nr);

  extern struct kv *
sst_iter_next(struct sst_iter * const iter, struct kv * const out);

  extern void
sst_iter_park(struct sst_iter * const iter);

  u64
sst_iter_retain(struct sst_iter * const iter);

  void
sst_iter_release(struct sst_iter * const iter, const u64 opaque);

  extern void
sst_iter_destroy(struct sst_iter * const iter);
// }}} sst

// build-sst {{{
// api contains sorted keys and supports iter_next().
// all keys in the map_api will be added to the sstable.
  extern u64
sst_build(const char * const dirname, struct miter * const miter,
    const u64 seq, const u32 way, const u32 maxblkid0, const bool del, const bool ckeys,
    const struct kv * const k0, const struct kv * const kz);
// }}} build-sst

// msstx {{{
// msst (multi-sst)
struct msst;
struct msstx_iter;

// msstx
  extern struct msst *
msstx_open(const char * const dirname, const u64 seq, const u32 nway);

  extern void
msst_rcache(struct msst * const msst, struct rcache * const rc);

  extern void
msstx_destroy(struct msst * const msst);

  extern struct msstx_iter *
msstx_iter_create(struct msst * const msst);

  extern struct kv *
msstx_get(struct msst * const msst, const struct kref * const key, struct kv * const out);

  extern bool
msstx_probe(struct msst * const msst, const struct kref * const key);

  extern bool
msstx_iter_valid(struct msstx_iter * const iter);

  extern void
msstx_iter_seek(struct msstx_iter * const iter, const struct kref * const key);

  extern void
msstx_iter_seek_null(struct msstx_iter * const iter);

  extern struct kv *
msstx_iter_peek(struct msstx_iter * const iter, struct kv * const out);

  extern bool
msstx_iter_kref(struct msstx_iter * const iter, struct kref * const kref);

  extern bool
msstx_iter_kvref(struct msstx_iter * const iter, struct kvref * const kvref);

  extern u64
msstx_iter_retain(struct msstx_iter * const iter);

  extern void
msstx_iter_release(struct msstx_iter * const iter, const u64 opaque);

  extern void
msstx_iter_skip(struct msstx_iter * const iter, const u32 nr);

  extern struct kv *
msstx_iter_next(struct msstx_iter * const iter, struct kv * const out);

  extern void
msstx_iter_park(struct msstx_iter * const iter);

  extern void
msstx_iter_destroy(struct msstx_iter * const iter);
// }}} msstx

// ssty {{{
struct ssty;

  extern struct ssty *
ssty_open(const char * const dirname, const u64 seq, const u32 nway);

  extern void
ssty_destroy(struct ssty * const ssty);

  extern void
ssty_fprint(struct ssty * const ssty, FILE * const fout);
// }}} ssty

// mssty {{{
struct mssty_ref;
struct mssty_iter;

  extern bool
mssty_open_y(const char * const dirname, struct msst * const msst);

  extern struct msst *
mssty_open(const char * const dirname, const u64 seq, const u32 nway);

  extern void
mssty_destroy(struct msst * const msst);

  extern void
mssty_fprint(struct msst * const msst, FILE * const fout);

  extern struct mssty_ref *
mssty_ref(struct msst * const msst);

  extern struct msst *
mssty_unref(struct mssty_ref * const ref);

  extern struct kv *
mssty_get(struct mssty_ref * const ref, const struct kref * const key, struct kv * const out);

  extern bool
mssty_probe(struct mssty_ref * const ref, const struct kref * const key);

// return NULL for tomestone
  extern struct kv *
mssty_get_ts(struct mssty_ref * const ref, const struct kref * const key, struct kv * const out);

// return false for tomestone
  extern bool
mssty_probe_ts(struct mssty_ref * const ref, const struct kref * const key);

  extern bool
mssty_get_value_ts(struct mssty_ref * const ref, const struct kref * const key,
    void * const vbuf_out, u32 * const vlen_out);

  extern struct mssty_iter *
mssty_iter_create(struct mssty_ref * const ref);

  extern bool
mssty_iter_valid(struct mssty_iter * const iter);

  extern void
mssty_iter_seek(struct mssty_iter * const iter, const struct kref * const key);

  extern void
mssty_iter_seek_null(struct mssty_iter * const iter);

  extern void
mssty_iter_seek_near(struct mssty_iter * const iter, const struct kref * const key, const bool bsearch_keys);

  extern struct kv *
mssty_iter_peek(struct mssty_iter * const iter, struct kv * const out);

  extern bool
mssty_iter_kref(struct mssty_iter * const iter, struct kref * const kref);

  extern bool
mssty_iter_kvref(struct mssty_iter * const iter, struct kvref * const kvref);

  extern u64
mssty_iter_retain(struct mssty_iter * const iter);

  extern void
mssty_iter_release(struct mssty_iter * const iter, const u64 opaque);

  extern void
mssty_iter_skip(struct mssty_iter * const iter, const u32 nr);

  extern struct kv *
mssty_iter_next(struct mssty_iter * const iter, struct kv * const out);

  extern void
mssty_iter_park(struct mssty_iter * const iter);

  extern void
mssty_iter_destroy(struct mssty_iter * const iter);

// ts iter: ignore a key if its newest version is a tombstone
  extern bool
mssty_iter_ts(struct mssty_iter * const iter);

  extern void
mssty_iter_seek_ts(struct mssty_iter * const iter, const struct kref * const key);

  extern void
mssty_iter_skip_ts(struct mssty_iter * const iter, const u32 nr);

  extern struct kv *
mssty_iter_next_ts(struct mssty_iter * const iter, struct kv * const out);

// dup iter: return all versions, including old keys and tombstones
  extern struct kv *
mssty_iter_peek_dup(struct mssty_iter * const iter, struct kv * const out);

  extern void
mssty_iter_skip_dup(struct mssty_iter * const iter, const u32 nr);

  extern struct kv *
mssty_iter_next_dup(struct mssty_iter * const iter, struct kv * const out);

  extern bool
mssty_iter_kref_dup(struct mssty_iter * const iter, struct kref * const kref);

  extern bool
mssty_iter_kvref_dup(struct mssty_iter * const iter, struct kvref * const kvref);

  extern struct kv *
mssty_first(struct msst * const msst, struct kv * const out);

  extern struct kv *
mssty_last(struct msst * const msst, struct kv * const out);

  extern void
mssty_dump(struct msst * const msst, const char * const fn);
// }}} mssty

// build-ssty {{{
// build extended metadata based on a set of sstables.
// y0 and way0 are optional for speeding up the sorting
  extern u32
ssty_build(const char * const dirname, struct msst * const msst,
    const u64 seq, const u32 way, struct msst * const y0, const u32 way0);
// }}} build-ssty

// msstv {{{
struct msstv;
struct msstv_iter;
struct msstv_ref;

  extern struct msstv *
msstv_create(const u64 nslots, const u64 version);

  extern void
msstv_append(struct msstv * const v, struct msst * const msst, const struct kv * const anchor);

  extern void
msstv_rcache(struct msstv * const v, struct rcache * const rc);

  extern void
msstv_destroy(struct msstv * const v);

  extern struct msstv *
msstv_open(const char * const dirname, const char * const filename);

  extern struct msstv *
msstv_open_version(const char * const dirname, const u64 version);

  extern struct msstv_ref *
msstv_ref(struct msstv * const v);

  extern struct msstv *
msstv_unref(struct msstv_ref * const ref);

  extern struct kv *
msstv_get(struct msstv_ref * const ref, const struct kref * const key, struct kv * const out);

  extern bool
msstv_probe(struct msstv_ref * const ref, const struct kref * const key);

// return NULL for tomestone
  extern struct kv *
msstv_get_ts(struct msstv_ref * const ref, const struct kref * const key, struct kv * const out);

// return false for tomestone
  extern bool
msstv_probe_ts(struct msstv_ref * const ref, const struct kref * const key);

  extern bool
msstv_get_value_ts(struct msstv_ref * const ref, const struct kref * const key,
    void * const vbuf_out, u32 * const vlen_out);

  extern struct msstv_iter *
msstv_iter_create(struct msstv_ref * const ref);

  extern bool
msstv_iter_valid(struct msstv_iter * const vi);

  extern void
msstv_iter_seek(struct msstv_iter * const vi, const struct kref * const key);

  extern struct kv *
msstv_iter_peek(struct msstv_iter * const vi, struct kv * const out);

  extern bool
msstv_iter_kref(struct msstv_iter * const vi, struct kref * const kref);

  extern bool
msstv_iter_kvref(struct msstv_iter * const vi, struct kvref * const kvref);

  extern u64
msstv_iter_retain(struct msstv_iter * const vi);

  extern void
msstv_iter_release(struct msstv_iter * const vi, const u64 opaque);

  extern void
msstv_iter_skip(struct msstv_iter * const vi, const u32 nr);

  extern struct kv *
msstv_iter_next(struct msstv_iter * const vi, struct kv * const out);

  extern void
msstv_iter_park(struct msstv_iter * const vi);

  extern bool
msstv_iter_ts(struct msstv_iter * const vi);

  extern void
msstv_iter_seek_ts(struct msstv_iter * const vi, const struct kref * const key);

  extern void
msstv_iter_skip_ts(struct msstv_iter * const vi, const u32 nr);

  extern struct kv *
msstv_iter_next_ts(struct msstv_iter * const vi, struct kv * const out);

  extern void
msstv_fprint(struct msstv * const v, FILE * const out);

  extern void
msstv_iter_destroy(struct msstv_iter * const vi);

// UNSAFE!
// return the anchors of msstv terminated with NULL
// the returned pointer should be freed after use
// must use when holding a msstv
// anchor->vlen: 0: accepted; 1: rejected
  extern struct kv **
msstv_anchors(struct msstv * const v);
// }}} msstv

// msstz {{{
struct msstz;

  extern struct msstz *
msstz_open(const char * const dirname, const u64 cache_size_mb, const bool ckeys);

  extern void
msstz_destroy(struct msstz * const z);

  extern void
msstz_log(struct msstz * const z, const char * const fmt, ...);

// return number of bytes written since opened
  extern u64
msstz_stat_writes(struct msstz * const z);

  extern u64
msstz_stat_reads(struct msstz * const z);

// default is 0
  extern void
msstz_set_minsz(struct msstz * const z, const u64 minsz);

  extern u64
msstz_version(struct msstz * const z);

  extern struct msstv *
msstz_getv(struct msstz * const z);

  extern void
msstz_putv(struct msstz * const z, struct msstv * const v);

typedef void (*msstz_range_cb)(void * priv, const bool accepted, const struct kv * k0, const struct kv * kz);

  extern void
msstz_comp(struct msstz * const z, const struct kvmap_api * const api1, void * const map1,
    const u32 nr_workers, const u32 co_per_worker, const u64 max_reject);
// }}} msstz

// api {{{
extern const struct kvmap_api kvmap_api_sst;
extern const struct kvmap_api kvmap_api_msstx;
extern const struct kvmap_api kvmap_api_mssty;
extern const struct kvmap_api kvmap_api_mssty_ts;
extern const struct kvmap_api kvmap_api_msstv;
extern const struct kvmap_api kvmap_api_msstv_ts;
// }}} api

#ifdef __cplusplus
}
#endif
// vim:fdm=marker
