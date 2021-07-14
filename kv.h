/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// crc32c {{{
#define KV_CRC32C_SEED ((0xDEADBEEFu))

  extern u32
kv_crc32c(const void * const ptr, u32 len);

  extern u64
kv_crc32c_extend(const u32 crc32c);
// }}} crc32c

// kv {{{

// struct {{{
/*
 * Some internal union names can be ignored:
 * struct kv {
 *   u32 klen;
 *   u32 vlen;
 *   u64 hash;
 *   u8 kv[];
 * };
 */
struct kv {
  union { // the first u64
    u64 kvlen;
    struct {
      u32 klen;
      union { u32 vlen; u32 refcnt; };
    };
  };
  union {
    u64 hash; // hashvalue of the key
    u64 priv; // can hide a value here if hash is not used
    void * privptr;
    struct { u32 hashlo; u32 hashhi; }; // little endian
    struct { u32 privlo; u32 privhi; };
  };
  u8 kv[0];  // len(kv) == klen + vlen
} __attribute__((packed));

struct kref {
  u32 len;
  union { u32 hash32; u32 priv; };
  const u8 * ptr;
} __attribute__((packed));

struct kvref {
  const u8 * kptr; // read-only
  const u8 * vptr; // read-only
  struct kv hdr; // hdr.kv[] is invalid
};
// }}} struct

// kv {{{
typedef int  (*kv_kv_cmp_func)(const struct kv *, const struct kv *);

  extern size_t
kv_size(const struct kv * const kv);

  extern size_t
kv_size_align(const struct kv * const kv, const u64 align);

  extern size_t
key_size(const struct kv * const key);

  extern size_t
key_size_align(const struct kv * const key, const u64 align);

  extern void
kv_update_hash(struct kv * const kv);

  extern void
kv_refill_value(struct kv * const kv, const void * const value, const u32 vlen);

  extern void
kv_refill(struct kv * const kv, const void * const key, const u32 klen,
    const void * const value, const u32 vlen);

  extern void
kv_refill_str(struct kv * const kv, const char * const key,
    const void * const value, const u32 vlen);

  extern void
kv_refill_str_str(struct kv * const kv, const char * const key,
    const char * const value);

// the u64 key is filled in big-endian byte order
  extern void
kv_refill_u64(struct kv * const kv, const u64 key, const void * const value, const u32 vlen);

  extern void
kv_refill_hex32(struct kv * const kv, const u32 hex, const void * const value, const u32 vlen);

  extern void
kv_refill_hex64(struct kv * const kv, const u64 hex, const void * const value, const u32 vlen);

  extern void
kv_refill_hex64_klen(struct kv * const kv, const u64 hex, const u32 klen,
    const void * const value, const u32 vlen);

  extern void
kv_refill_kref(struct kv * const kv, const struct kref * const kref);

  extern void
kv_refill_kref_v(struct kv * const kv, const struct kref * const kref,
    const void * const value, const u32 vlen);

  extern struct kref
kv_kref(const struct kv * const key);

  extern struct kv *
kv_create(const void * const key, const u32 klen, const void * const value, const u32 vlen);

  extern struct kv *
kv_create_str(const char * const key, const void * const value, const u32 vlen);

  extern struct kv *
kv_create_str_str(const char * const key, const char * const value);

  extern struct kv *
kv_create_kref(const struct kref * const kref, const void * const value, const u32 vlen);

// a static kv with klen == 0
  extern const struct kv *
kv_null(void);

  extern struct kv *
kv_dup(const struct kv * const kv);

  extern struct kv *
kv_dup_key(const struct kv * const kv);

  extern struct kv *
kv_dup2(const struct kv * const from, struct kv * const to);

  extern struct kv *
kv_dup2_key(const struct kv * const from, struct kv * const to);

  extern struct kv *
kv_dup2_key_prefix(const struct kv * const from, struct kv * const to, const u32 plen);

  extern bool
kv_match(const struct kv * const key1, const struct kv * const key2);

  extern bool
kv_match_hash(const struct kv * const key1, const struct kv * const key2);

  extern bool
kv_match_full(const struct kv * const kv1, const struct kv * const kv2);

  extern bool
kv_match_kv128(const struct kv * const sk, const u8 * const kv128);

  extern int
kv_compare(const struct kv * const kv1, const struct kv * const kv2);

  extern int
kv_k128_compare(const struct kv * const sk, const u8 * const k128);

  extern int
kv_kv128_compare(const struct kv * const sk, const u8 * const kv128);

  extern void
kv_qsort(struct kv ** const kvs, const size_t nr);

  extern u32
kv_key_lcp(const struct kv * const key1, const struct kv * const key2);

  extern u32
kv_key_lcp_skip(const struct kv * const key1, const struct kv * const key2, const u32 lcp0);

  extern void
kv_psort(struct kv ** const kvs, const u64 nr, const u64 tlo, const u64 thi);

  extern void *
kv_vptr(struct kv * const kv);

  extern void *
kv_kptr(struct kv * const kv);

  extern const void *
kv_vptr_c(const struct kv * const kv);

  extern const void *
kv_kptr_c(const struct kv * const kv);

  extern void
kv_print(const struct kv * const kv, const char * const cmd, FILE * const out);
// }}} kv

// mm {{{
typedef struct kv * (* kvmap_mm_in_func)(struct kv * kv, void * priv);
typedef struct kv * (* kvmap_mm_out_func)(struct kv * kv, struct kv * out);
typedef void        (* kvmap_mm_free_func)(struct kv * kv, void * priv);

// manage internal kv data of kvmap
struct kvmap_mm {
  // to create a private copy of "kv"
  // see put() functions
  kvmap_mm_in_func in;
  // to duplicate a private copy of "kv" to "out"
  // see get() and iter_peek() functions
  kvmap_mm_out_func out;
  // to free a kv
  // see del() and put() functions
  kvmap_mm_free_func free;
  void * priv;
};

  extern struct kv *
kvmap_mm_in_noop(struct kv * const kv, void * const priv);

  extern struct kv *
kvmap_mm_out_noop(struct kv * const kv, struct kv * const out);

  extern void
kvmap_mm_free_noop(struct kv * const kv, void * const priv);

  extern struct kv *
kvmap_mm_in_dup(struct kv * const kv, void * const priv);

  extern struct kv *
kvmap_mm_out_dup(struct kv * const kv, struct kv * const out);

  extern void
kvmap_mm_free_free(struct kv * const kv, void * const priv);

// the default mm
extern const struct kvmap_mm kvmap_mm_dup; // in:Dup, out:Dup, free:Free
extern const struct kvmap_mm kvmap_mm_ndf; // in:Noop, out:Dup, free:Free
// }}} mm

// ref {{{
typedef int (*kref_kv_cmp_func)(const struct kref *, const struct kv *);

// ptr and len only
  extern void
kref_ref_raw(struct kref * const kref, const u8 * const ptr, const u32 len);

// this calculates hash32
  extern void
kref_ref_hash32(struct kref * const kref, const u8 * const ptr, const u32 len);

  extern void
kref_update_hash32(struct kref * const kref);

  extern void
kref_ref_kv(struct kref * const kref, const struct kv * const kv);

  extern void
kref_ref_kv_hash32(struct kref * const kref, const struct kv * const kv);

  extern bool
kref_match(const struct kref * const k1, const struct kref * const k2);

  extern bool
kref_kv_match(const struct kref * const kref, const struct kv * const k);

  extern int
kref_compare(const struct kref * const kref1, const struct kref * const kref2);

  extern int
kref_kv_compare(const struct kref * const kref, const struct kv * const k);

  extern u32
kref_lcp(const struct kref * const k1, const struct kref * const k2);

  extern u32
kref_kv_lcp(const struct kref * const kref, const struct kv * const kv);

  extern int
kref_k128_compare(const struct kref * const sk, const u8 * const k128);

  extern int
kref_kv128_compare(const struct kref * const sk, const u8 * const kv128);

  extern const struct kref *
kref_null(void);

  extern void
kvref_ref_kv(struct kvref * const ref, struct kv * const kv);

  extern struct kv *
kvref_dup2_kv(struct kvref * const ref, struct kv * const to);

  extern struct kv *
kvref_dup2_key(struct kvref * const ref, struct kv * const to);

  extern int
kvref_kv_compare(const struct kvref * const ref, const struct kv * const kv);
// }}} ref

// kv128 {{{
  extern size_t
kv128_estimate_kv(const struct kv * const kv);

  extern u8 *
kv128_encode_kv(const struct kv * const kv, u8 * const out, size_t * const pesize);

  extern struct kv *
kv128_decode_kv(const u8 * const ptr, struct kv * const out, size_t * const pesize);

  extern size_t
kv128_size(const u8 * const ptr);
// }}} kv128

// }}} kv

// kvmap {{{

// kvmap_api {{{
typedef void (* kv_inp_func)(struct kv * const curr, void * const priv);

// the merge function should:
// 1: return NULL if the origin kv is not changed at all
// 2: return kv0 if updates has been applied in-place
// 3: return a different kv if the original kv must be replaced
// In an in-memory kvmap, 2==1 and no further action is needed
// In a persistent kv store with a memtable, 2 will need an insertion if kv0 is not from the memtable
typedef struct kv * (* kv_merge_func)(struct kv * const kv0, void * const priv);

struct kvmap_api {
  // feature bits
  bool hashkey; // true: caller needs to provide correct hash in kv/kref
  bool ordered; // true: has iter_seek
  bool threadsafe; // true: support thread_safe access
  bool readonly; // true: no put() and del()
  bool irefsafe; // true: iter's kref/kvref can be safely accessed after iter_seek/iter_skip/iter_park
  bool unique; // provide unique keys, especially for iterators
  bool refpark; // ref has park() and resume()
  bool async; // XXX for testing KVell

  // put (aka put/upsert): return true on success; false on error
  // mm.in() controls how things move into the kvmap; the default mm make a copy with malloc()
  // mm.free() controls how old kv get disposed when replaced
  bool        (* put)     (void * const ref, struct kv * const kv);
  // get: search and return a kv if found, or NULL if not
  // with the default mm: malloc() if out == NULL; otherwise, use out as buffer
  // with custom kvmap_mm: mm.out() controls buffer; use with caution
  // caller should use the returned ptr even if out is provided
  struct kv * (* get)     (void * const ref, const struct kref * const key, struct kv * const out);
  // probe: return true on found, false on not found
  bool        (* probe)   (void * const ref, const struct kref * const key);
  // del: return true on something deleted, false on not found
  // mm.free() controls how old kv get disposed when replaced
  bool        (* del)     (void * const ref, const struct kref * const key);
  // inp: inplace operation if key exists; otherwise return false; uf() is always executed even with NULL key
  // inpr/inpw acquires r/w locks respectively.
  // Note that in inpw() you can only change the value.
  bool        (* inpr)    (void * const ref, const struct kref * const key, kv_inp_func uf, void * const priv);
  bool        (* inpw)    (void * const ref, const struct kref * const key, kv_inp_func uf, void * const priv);
  // merge: put+callback on old/new keys; another name: read-modify-write
  // return true if successfull; return false on error
  bool        (* merge)   (void * const ref, const struct kref * const key, kv_merge_func uf, void * const priv);
  // delete-range: delete all keys from start (inclusive) to end (exclusive)
  u64         (* delr)    (void * const ref, const struct kref * const start, const struct kref * const end);
  // make everything persist; for persistent maps only
  void        (* sync)    (void * const ref);

  // general guidelines for thread-safe iters:
  // - it is assumed that the key under the cursor is locked/freezed/immutable
  // - once created one must call iter_seek to make it valid
  // - the ownership of ref is given to the iter so ref should not be used until iter_destroy
  // - creating and use more than one iter based on a ref can cause deadlocks
  void *      (* iter_create)   (void * const ref);
  // move the cursor to the first key >= search-key;
  void        (* iter_seek)     (void * const iter, const struct kref * const key);
  // check if the cursor points to a valid key
  bool        (* iter_valid)    (void * const iter);
  // return the current key; copy to out if (out != NULL)
  // mm.out() controls copy-out
  struct kv * (* iter_peek)     (void * const iter, struct kv * const out);
  // similar to peek but does not copy; return false if iter is invalid
  bool        (* iter_kref)     (void * const iter, struct kref * const kref);
  // similar to iter_kref but also provide the value
  bool        (* iter_kvref)    (void * const iter, struct kvref * const kvref);
  // iter_retain makes kref or kvref of the current iter remain valid until released
  // the returned opaque pointer should be provided when releasing the hold
  u64         (* iter_retain)   (void * const iter);
  void        (* iter_release)  (void * const iter, const u64 opaque);
  // skip one element
  void        (* iter_skip1)    (void * const iter);
  // skip nr elements
  void        (* iter_skip)     (void * const iter, const u32 nr);
  // iter_next == iter_peek + iter_skip1
  struct kv * (* iter_next)     (void * const iter, struct kv * const out);
  // perform inplace opeation if the current key is valid; return false if no current key
  // the uf() is always executed even with NULL key
  bool        (* iter_inp)      (void * const iter, kv_inp_func uf, void * const priv);
  // invalidate the iter to release any resources or locks
  // afterward, must call seek() again before accessing data
  void        (* iter_park)     (void * const iter);
  // destroy iter
  void        (* iter_destroy)  (void * const iter);

  // misc:
  // create refs for maps if required; always use use kvmap_ref() and kvmap_unref()
  // if there are ref/unref functions, ref-ptr should be used as map for all kv operations
  void *      (* ref)     (void * map);
  // return the original map
  void *      (* unref)   (void * ref);
  // pause access without unref; must call resume later before access index again
  void        (* park)    (void * ref);
  // resume access of ref; must be paired with a park()
  void        (* resume)  (void * ref);

  // UNSAFE functions:
  // empty the map
  void        (* clean)   (void * map);
  // erase everything
  void        (* destroy) (void * map);
  // for debugging
  void        (* fprint)  (void * map, FILE * const out);
};

// registry
struct kvmap_api_reg {
  int nargs; // number of arguments after name
  const char * name;
  const char * args_msg; // see ...helper_message
  // multiple apis may share one create function
  // arguments: name (e.g., "rdb"), mm (usually NULL), the remaining args
  void * (*create)(const char *, const struct kvmap_mm *, char **);
  const struct kvmap_api * api;
};

// call this function to register a kvmap_api
  extern void
kvmap_api_register(const int nargs, const char * const name, const char * const args_msg,
    void * (*create)(const char *, const struct kvmap_mm *, char **), const struct kvmap_api * const api);

  extern void
kvmap_api_helper_message(void);

  extern int
kvmap_api_helper(int argc, char ** const argv, const struct kvmap_mm * const mm,
    const struct kvmap_api ** const api_out, void ** const map_out);
// }}} kvmap_api

// helpers {{{
  extern void
kvmap_inp_steal_kv(struct kv * const kv, void * const priv);

  extern void *
kvmap_ref(const struct kvmap_api * const api, void * const map);

  extern void *
kvmap_unref(const struct kvmap_api * const api, void * const ref);

  extern struct kv *
kvmap_kv_get(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key, struct kv * const out);

  extern bool
kvmap_kv_probe(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key);

  extern bool
kvmap_kv_put(const struct kvmap_api * const api, void * const ref,
    struct kv * const kv);

  extern bool
kvmap_kv_del(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key);

  extern bool
kvmap_kv_inpr(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key, kv_inp_func uf, void * const priv);

  extern bool
kvmap_kv_inpw(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key, kv_inp_func uf, void * const priv);

  extern bool
kvmap_kv_merge(const struct kvmap_api * const api, void * const ref,
    const struct kv * const key, kv_merge_func uf, void * const priv);

  extern u64
kvmap_kv_delr(const struct kvmap_api * const api, void * const ref,
    const struct kv * const start, const struct kv * const end);

  extern void
kvmap_kv_iter_seek(const struct kvmap_api * const api, void * const iter,
    const struct kv * const key);

  extern struct kv *
kvmap_raw_get(const struct kvmap_api * const api, void * const ref,
    const u32 len, const u8 * const ptr, struct kv * const out);

  extern bool
kvmap_raw_probe(const struct kvmap_api * const api, void * const ref,
    const u32 len, const u8 * const ptr);

  extern bool
kvmap_raw_del(const struct kvmap_api * const api, void * const ref,
    const u32 len, const u8 * const ptr);

  extern bool
kvmap_raw_inpr(const struct kvmap_api * const api, void * const ref,
    const u32 len, const u8 * const ptr, kv_inp_func uf, void * const priv);

  extern bool
kvmap_raw_inpw(const struct kvmap_api * const api, void * const ref,
    const u32 len, const u8 * const ptr, kv_inp_func uf, void * const priv);

  extern void
kvmap_raw_iter_seek(const struct kvmap_api * const api, void * const iter,
    const u32 len, const u8 * const ptr);

  extern u64
kvmap_dump_keys(const struct kvmap_api * const api, void * const map, const int fd);
// }}} helpers

// }}} kvmap

// miter {{{
// general-purpose merging iterator
// api functions:
// REQUIRED:
//   - iter_create
//   - iter_seek
//   - iter_peek
//   - iter_skip
//   - iter_destroy
//   - iter_kref
//   - iter_kvref
// OPTIONAL (api-specific):
//   - ref/unref
//   - iter_park
//   - resume/park (need also set api->refpark)
// OPTIONAL (performance):
//   - api->unique (faster miter_skip_unique)
//   - iter_retain/iter_release (less memcpy)

struct miter;

  extern struct miter *
miter_create(void);

// caller owns the ref and the iter; miter will not destroy them
// using the iter or the ref with an active miter can lead to undefined behavior
  extern bool
miter_add_iter(struct miter * const miter, const struct kvmap_api * const api, void * const ref, void * const iter);

// caller owns the ref; miter will create and destroy the iter
// using the underlying ref with an active miter can lead to undefined behavior
  extern void *
miter_add_ref(struct miter * const miter, const struct kvmap_api * const api, void * const ref);

// miter will take a ref of the map, create an iter, and clean up everything
// be careful of using another ref/iter in the same thread
  extern void *
miter_add(struct miter * const miter, const struct kvmap_api * const api, void * const map);

  extern u32
miter_rank(struct miter * const miter);

  extern void
miter_seek(struct miter * const miter, const struct kref * const key);

  extern void
miter_kv_seek(struct miter * const miter, const struct kv * const key);

  extern bool
miter_valid(struct miter * const miter);

  extern struct kv *
miter_peek(struct miter * const miter, struct kv * const out);

  extern bool
miter_kref(struct miter * const miter, struct kref * const kref);

  extern bool
miter_kvref(struct miter * const miter, struct kvref * const kvref);

  extern void
miter_skip1(struct miter * const miter);

  extern void
miter_skip(struct miter * const miter, const u32 nr);

  extern struct kv *
miter_next(struct miter * const miter, struct kv * const out);

  extern void
miter_skip_unique(struct miter * const miter);

  extern struct kv *
miter_next_unique(struct miter * const miter, struct kv * const out);

  extern void
miter_park(struct miter * const miter);

  extern void
miter_clean(struct miter * const miter);

  extern void
miter_destroy(struct miter * const miter);
// }}} miter

#ifdef __cplusplus
}
#endif
// vim:fdm=marker
