/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

struct wormhole;
struct wormref;

// wormhole {{{
// the wh created by wormhole_create() can work with all of safe/unsafe operations.
  extern struct wormhole *
wormhole_create(const struct kvmap_mm * const mm);

// the wh created by whunsafe_create() can only work with the unsafe operations.
  extern struct wormhole *
whunsafe_create(const struct kvmap_mm * const mm);

  extern struct kv *
wormhole_get(struct wormref * const ref, const struct kref * const key, struct kv * const out);

  extern bool
wormhole_probe(struct wormref * const ref, const struct kref * const key);

  extern bool
wormhole_set(struct wormref * const ref, struct kv * const kv);

  extern bool
wormhole_merge(struct wormref * const ref, const struct kref * const kref,
    kv_merge_func uf, void * const priv);

  extern bool
wormhole_inpr(struct wormref * const ref, const struct kref * const key,
    kv_inp_func uf, void * const priv);

  extern bool
wormhole_inpw(struct wormref * const ref, const struct kref * const key,
    kv_inp_func uf, void * const priv);

  extern bool
wormhole_del(struct wormref * const ref, const struct kref * const key);

  extern u64
wormhole_delr(struct wormref * const ref, const struct kref * const start,
    const struct kref * const end);

  extern struct wormhole_iter *
wormhole_iter_create(struct wormref * const ref);

  extern void
wormhole_iter_seek(struct wormhole_iter * const iter, const struct kref * const key);

  extern bool
wormhole_iter_valid(struct wormhole_iter * const iter);

  extern struct kv *
wormhole_iter_peek(struct wormhole_iter * const iter, struct kv * const out);

  extern bool
wormhole_iter_kref(struct wormhole_iter * const iter, struct kref * const kref);

  extern bool
wormhole_iter_kvref(struct wormhole_iter * const iter, struct kvref * const kvref);

  extern void
wormhole_iter_skip(struct wormhole_iter * const iter, const u32 nr);

  extern struct kv *
wormhole_iter_next(struct wormhole_iter * const iter, struct kv * const out);

  extern bool
wormhole_iter_inp(struct wormhole_iter * const iter, kv_inp_func uf, void * const priv);

  extern void
wormhole_iter_park(struct wormhole_iter * const iter);

  extern void
wormhole_iter_destroy(struct wormhole_iter * const iter);

  extern struct wormref *
wormhole_ref(struct wormhole * const map);

  extern struct wormhole *
wormhole_unref(struct wormref * const ref);

  extern void
wormhole_park(struct wormref * const ref);

  extern void
wormhole_resume(struct wormref * const ref);

  extern void
wormhole_refresh_qstate(struct wormref * const ref);

// clean with more threads
  extern void
wormhole_clean_th(struct wormhole * const map, const u32 nr_threads);

  extern void
wormhole_clean(struct wormhole * const map);

  extern void
wormhole_destroy(struct wormhole * const map);

// safe API (no need to refresh qstate)

  extern struct kv *
whsafe_get(struct wormref * const ref, const struct kref * const key, struct kv * const out);

  extern bool
whsafe_probe(struct wormref * const ref, const struct kref * const key);

  extern bool
whsafe_set(struct wormref * const ref, struct kv * const kv);

  extern bool
whsafe_merge(struct wormref * const ref, const struct kref * const kref,
    kv_merge_func uf, void * const priv);

  extern bool
whsafe_inpr(struct wormref * const ref, const struct kref * const key,
    kv_inp_func uf, void * const priv);

  extern bool
whsafe_inpw(struct wormref * const ref, const struct kref * const key,
    kv_inp_func uf, void * const priv);

  extern bool
whsafe_del(struct wormref * const ref, const struct kref * const key);

  extern u64
whsafe_delr(struct wormref * const ref, const struct kref * const start,
    const struct kref * const end);

// use wormhole_iter_create
  extern void
whsafe_iter_seek(struct wormhole_iter * const iter, const struct kref * const key);

  extern struct kv *
whsafe_iter_peek(struct wormhole_iter * const iter, struct kv * const out);

// use wormhole_iter_valid
// use wormhole_iter_peek
// use wormhole_iter_kref
// use wormhole_iter_kvref
// use wormhole_iter_skip
// use wormhole_iter_next
// use wormhole_iter_inp

  extern void
whsafe_iter_park(struct wormhole_iter * const iter);

  extern void
whsafe_iter_destroy(struct wormhole_iter * const iter);

  extern struct wormref *
whsafe_ref(struct wormhole * const map);

// use wormhole_unref

// unsafe API

  extern struct kv *
whunsafe_get(struct wormhole * const map, const struct kref * const key, struct kv * const out);

  extern bool
whunsafe_probe(struct wormhole * const map, const struct kref * const key);

  extern bool
whunsafe_set(struct wormhole * const map, struct kv * const kv);

  extern bool
whunsafe_merge(struct wormhole * const map, const struct kref * const kref,
    kv_merge_func uf, void * const priv);

  extern bool
whunsafe_inp(struct wormhole * const map, const struct kref * const key,
    kv_inp_func uf, void * const priv);

  extern bool
whunsafe_del(struct wormhole * const map, const struct kref * const key);

  extern u64
whunsafe_delr(struct wormhole * const map, const struct kref * const start,
    const struct kref * const end);

  extern struct wormhole_iter *
whunsafe_iter_create(struct wormhole * const map);

  extern void
whunsafe_iter_seek(struct wormhole_iter * const iter, const struct kref * const key);

  extern bool
whunsafe_iter_valid(struct wormhole_iter * const iter);

// unsafe peek: use wormhole_iter_peek
// unsafe kref: use wormhole_iter_kref

  extern void
whunsafe_iter_skip(struct wormhole_iter * const iter, const u32 nr);

  extern struct kv *
whunsafe_iter_next(struct wormhole_iter * const iter, struct kv * const out);

  extern bool
whunsafe_iter_inp(struct wormhole_iter * const iter, kv_inp_func uf, void * const priv);

  extern void
whunsafe_iter_destroy(struct wormhole_iter * const iter);

  extern void
wormhole_fprint(struct wormhole * const map, FILE * const out);

// verify & debugging
#ifdef WORMHOLE_DEBUG
  void
wormhole_fprint_verbose(struct wormhole * const map, FILE * const out);

  extern bool
wormhole_verify(struct wormhole * const map);

  extern void
wormhole_dump_memory(struct wormhole * const map, const char * const filename, const char * const opt);

  extern bool
wormhole_merge_at(struct wormref * const ref, const struct kref * const key);

  extern bool
wormhole_split_at(struct wormref * const ref, const struct kref * const key);

  extern void
wormhole_sync_at(struct wormref * const ref, const struct kref * const key);

  extern void
wormhole_print_meta_anchors(struct wormhole * const map, const char * const pattern);

  extern void
wormhole_print_leaf_anchors(struct wormhole * const map, const char * const pattern);

  extern void
wormhole_print_meta_lrmost(struct wormhole * const map, const char * const pattern);

  extern void *
wormhole_jump_leaf_only(struct wormhole * const map, const struct kref * const key);
#endif // WORMHOLE_DEBUG

extern const struct kvmap_api kvmap_api_wormhole;
extern const struct kvmap_api kvmap_api_whsafe;
extern const struct kvmap_api kvmap_api_whunsafe;
// }}} wormhole

// wh {{{
  extern struct wormhole *
wh_create(void);

  extern struct wormref *
wh_ref(struct wormhole * const wh);

  extern void
wh_unref(struct wormref * const ref);

  extern void
wh_park(struct wormref * const ref);

  extern void
wh_resume(struct wormref * const ref);

  extern void
wh_clean(struct wormhole * const map);

  extern void
wh_destroy(struct wormhole * const map);

  extern bool
wh_set(struct wormref * const ref, const void * const kbuf, const u32 klen,
    const void * const vbuf, const u32 vlen);

  extern bool
wh_del(struct wormref * const ref, const void * const kbuf, const u32 klen);

  extern bool
wh_probe(struct wormref * const ref, const void * const kbuf, const u32 klen);

  extern bool
wh_get(struct wormref * const ref, const void * const kbuf, const u32 klen,
    void * const vbuf_out, u32 * const vlen_out);

  extern bool
wh_inpr(struct wormref * const ref, const void * const kbuf, const u32 klen,
    kv_inp_func uf, void * const priv);

  extern bool
wh_inpw(struct wormref * const ref, const void * const kbuf, const u32 klen,
    kv_inp_func uf, void * const priv);

  extern bool
wh_merge(struct wormref * const ref, const void * const kbuf, const u32 klen,
    kv_merge_func uf, void * const priv);

  extern u64
wh_delr(struct wormref * const ref, const void * const kbuf_start, const u32 klen_start,
    const void * const kbuf_end, const u32 klen_end);

  extern struct wormhole_iter *
wh_iter_create(struct wormref * const ref);

  extern void
wh_iter_seek(struct wormhole_iter * const iter, const void * const kbuf, const u32 klen);

  extern bool
wh_iter_valid(struct wormhole_iter * const iter);

  extern bool
wh_iter_peek(struct wormhole_iter * const iter,
    void * const kbuf_out, u32 * const klen_out,
    void * const vbuf_out, u32 * const vlen_out);

  extern void
wh_iter_skip(struct wormhole_iter * const iter, const u32 nr);

  extern bool
wh_iter_inp(struct wormhole_iter * const iter, kv_inp_func uf, void * const priv);

  extern void
wh_iter_park(struct wormhole_iter * const iter);

  extern void
wh_iter_destroy(struct wormhole_iter * const iter);
// }}} wh

#ifdef __cplusplus
}
#endif
// vim:fdm=marker
