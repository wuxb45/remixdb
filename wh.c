/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

// headers {{{
#include <assert.h> // static_assert
#include "lib.h"
#include "ctypes.h"
#include "kv.h"
#include "wh.h"
// }}} headers

// def {{{
#define WH_HMAPINIT_SIZE ((1lu << 12)) // 10: 16KB/64KB  12: 64KB/256KB  14: 256KB/1MB
#define WH_SLABMETA_SIZE ((1lu << 21)) // 2MB

#ifndef HEAPCHECKING
#define WH_SLABLEAF_SIZE ((1lu << 21)) // 2MB is ok
#else
#define WH_SLABLEAF_SIZE ((1lu << 21)) // 2MB for valgrind
#endif

#define WH_KPN ((128u)) // keys per node; power of 2
#define WH_HDIV (((1u << 16)) / WH_KPN)
#define WH_MID ((WH_KPN >> 1)) // ideal cut point for split, the closer the better
#define WH_BKT_NR ((8))

#define WH_KPN_MRG (((WH_KPN + WH_MID) >> 1 )) // 3/4

// FO is fixed at 256. Don't change it
#define WH_FO  ((256)) // index fan-out
// number of bits in a bitmap
#define WH_BMNR ((WH_FO >> 6)) // number of u64
// }}} def

// struct {{{
struct wormmeta {
  u32 hash32;
  u16 bitmin;
  u16 klen; // we don't expect any 65536-byte meta-key
  struct kv * keyref;
  struct wormleaf * lmost;
  struct wormleaf * rmost;
  u64 bitmap[WH_BMNR];
};
static_assert(sizeof(struct wormmeta) == 64, "sizeof(wormmeta) != 64");

struct wormleaf {
  // first line
  spinlock sortlock; // to protect the seemingly "read-only" iter_seek
  u32 padding;
  struct wormleaf * prev; // prev leaf
  struct wormleaf * next; // next leaf
  au64 lv; // version

  u64 nr_sorted;
  u64 nr_keys;
  u32 klen; // a duplicate of anchor->klen;
  rwlock leaflock;
  struct kv * anchor;

  struct entry13 eh[WH_KPN]; // sorted by hashes
  struct entry13 es[WH_KPN]; // sorted by keys
};

struct wormslot {
  u16 t[WH_BKT_NR];
};

struct wormmbkt {
  struct wormmeta * e[WH_BKT_NR];
};

static_assert(sizeof(struct wormslot) == 16, "sizeof(wormslot) != 16");

struct wormhmap {
  au64 hv;
  struct wormslot * wmap;
  u32 mask;
  u32 padding1;
  struct wormmbkt * pmap;

  u32 maxplen;
  u32 hmap_id; // 0 or 1
  u64 msize;
  struct slab * slab;
  struct kv * pbuf;
};
static_assert(sizeof(struct wormhmap) == 64, "sizeof(wormhmap) != 64");

struct wormhole {
  // 1 line
  volatile au64 hmap_ptr; // struct wormhmap *
  u64 padding0[6];
  struct wormleaf * leaf0; // usually not used
  // 1 line
  struct kvmap_mm mm;
  struct qsbr * qsbr;
  struct slab * slab_leaf;
  struct kv * pbuf;
  u64 padding1;
  // 2 lines
  struct wormhmap hmap2[2];
  // fifth line
  rwlock metalock;
  au32 clean_seq;
  u32 clean_ths;
  u32 padding2[13];
};

struct wormhole_iter {
  struct wormref * ref; // safe-iter only
  struct wormhole * map;
  struct wormleaf * leaf;
  u64 next_id;
};

struct wormref {
  struct wormhole * map;
  struct qsbr_ref qref;
};
// }}} struct

// helpers {{{

// key/prefix {{{
  static inline u16
wormhole_pkey(const u32 hash32)
{
  const u16 pkey0 = ((u16)hash32) ^ ((u16)(hash32 >> 16));
  return pkey0 ? pkey0 : 1;
}

  static inline u32
wormhole_bswap(const u32 hashlo)
{
  return __builtin_bswap32(hashlo);
}

  static inline bool
wormhole_key_meta_match(const struct kv * const key, const struct wormmeta * const meta)
{
  return (key->hashlo == meta->hash32)
    && (key->klen == meta->klen)
    && (!memcmp(key->kv, meta->keyref->kv, key->klen));
}

// called by get_kref_slot
  static inline bool
wormhole_kref_meta_match(const struct kref * const kref,
    const struct wormmeta * const meta)
{
  cpu_prefetch0(meta->lmost);
  return (kref->len == meta->klen)
    && (!memcmp(kref->ptr, meta->keyref->kv, kref->len));
}

// called from get_kref1_slot
  static inline bool
wormhole_kref1_meta_match(const struct kref * const kref,
    const struct wormmeta * const meta, const u8 cid)
{
  const u8 * const keybuf = meta->keyref->kv;
  cpu_prefetch0(meta->rmost);
  const u32 plen = kref->len;
  return ((plen + 1) == meta->klen)
    && (!memcmp(kref->ptr, keybuf, plen))
    && (keybuf[plen] == cid);
}

// warning: be careful with buffer overflow
  static inline void
wormhole_prefix(struct kv * const pfx, const u32 klen)
{
  pfx->klen = klen;
  kv_update_hash(pfx);
}

// for split
  static inline void
wormhole_prefix_inc1(struct kv * const pfx)
{
  pfx->hashlo = crc32c_u8(pfx->hashlo, pfx->kv[pfx->klen]);
  pfx->klen++;
}

// meta_lcp only
  static inline void
wormhole_kref_inc(struct kref * const kref, const u32 len0,
    const u32 crc, const u32 inc)
{
  kref->hash32 = crc32c_inc(kref->ptr + len0, inc, crc);
  kref->len = len0 + inc;
}

// meta_lcp only
  static inline void
wormhole_kref_inc_123(struct kref * const kref, const u32 len0,
    const u32 crc, const u32 inc)
{
  kref->hash32 = crc32c_inc_123(kref->ptr + len0, inc, crc);
  kref->len = len0 + inc;
}
// }}} key/prefix

// alloc {{{
  static inline struct kv *
wormhole_alloc_akey(const size_t klen)
{
#ifdef ALLOCFAIL
  if (alloc_fail())
    return NULL;
#endif
  return malloc(sizeof(struct kv) + klen);
}

  static inline void
wormhole_free_akey(struct kv * const akey)
{
  free(akey);
}

  static inline struct kv *
wormhole_alloc_mkey(const size_t klen)
{
#ifdef ALLOCFAIL
  if (alloc_fail())
    return NULL;
#endif
  return malloc(sizeof(struct kv) + klen);
}

  static struct kv *
wormhole_alloc_mkey_extend(struct kv * const kv, const u32 klen)
{
  struct kv * const mkey = wormhole_alloc_mkey(klen);
  if (mkey == NULL)
    return NULL;
  kv_dup2_key(kv, mkey);
  if (klen > mkey->klen) {
    memset(&(mkey->kv[mkey->klen]), 0, klen - mkey->klen);
    mkey->klen = klen;
  }
  return mkey;
}

  static inline void
wormhole_free_mkey(struct kv * const mkey)
{
  free(mkey);
}

  static inline struct wormleaf *
wormhole_alloc_leaf(struct wormhole * const map, struct wormleaf * const prev,
    struct wormleaf * const next, struct kv * const anchor)
{
  struct wormleaf * const leaf = slab_alloc_safe(map->slab_leaf);
  if (leaf == NULL)
    return NULL;

  spinlock_init(&(leaf->sortlock));
  leaf->prev = prev;
  leaf->next = next;
  // keep the old version; new version will be assigned by split functions
  //leaf->lv = 0;

  leaf->nr_sorted = 0;
  leaf->nr_keys = 0;
  leaf->klen = anchor->klen;
  rwlock_init(&(leaf->leaflock));
  leaf->anchor = anchor;
  // eh requires zero init.
  memset(leaf->eh, 0, sizeof(leaf->eh[0]) * WH_KPN);
  return leaf;
}

  static inline struct wormmeta *
wormhole_alloc_meta(struct slab * const slab, struct wormleaf * const lrmost,
    struct kv * const keyref, const u32 hash32, const u32 klen)
{
  struct wormmeta * const meta = slab_alloc_unsafe(slab);
  if (meta == NULL)
    return NULL;
  keyref->refcnt++;
  meta->hash32 = hash32;
  debug_assert(klen < (1lu << 16));
  meta->klen = (u16)klen;
  meta->keyref = keyref;
  meta->bitmin = WH_FO; // WH_FO implies bitcount == 0
  meta->lmost = lrmost;
  meta->rmost = lrmost;
  for (u64 i = 0; i < WH_BMNR; i++)
    meta->bitmap[i] = 0;
  return meta;
}

  static inline bool
wormhole_slab_reserve(struct slab * const slab, const u32 nr)
{
#ifdef ALLOCFAIL
  if (alloc_fail())
    return false;
#endif
  return slab ? slab_reserve_unsafe(slab, nr) : true;
}

  static inline void
wormhole_free_leaf(struct slab * const slab, struct wormleaf * const leaf)
{
  debug_assert(leaf->leaflock.opaque == 0);
  wormhole_free_akey(leaf->anchor);
  slab_free_safe(slab, leaf);
}

  static inline void
wormhole_free_meta(struct slab * const slab, struct wormmeta * const meta)
{
  struct kv * const keyref = meta->keyref;
  debug_assert(keyref->refcnt);
  keyref->refcnt--;
  if (keyref->refcnt == 0)
    wormhole_free_mkey(keyref);
  slab_free_unsafe(slab, meta);
}
// }}} alloc

// meta/bitmap {{{
  static inline bool
wormhole_meta_bm_test(const struct wormmeta * const meta, const u32 id)
{
  return (bool)((meta->bitmap[id >> 6] >> (id & 0x3fu)) & 1lu);
}

  static inline void
wormhole_meta_bm_set(struct wormmeta * const meta, const u32 id)
{
  meta->bitmap[id >> 6u] |= (1lu << (id & 0x3fu));
  if (id < meta->bitmin)
    meta->bitmin = (u16)id;
}

  static inline u32
wormhole_meta_bm_gt(const struct wormmeta * const meta, const u32 id0)
{
  if ((id0 & 0x3fu) != 0x3fu) { // not at bit 63
    const u32 id = id0 + 1u;
    const u64 bits = meta->bitmap[id >> 6] >> (id & 0x3fu);
    if (bits)
      return id + (u32)__builtin_ctzl(bits);
  }
  for (u32 ix = (id0 >> 6) + 1; ix < 4; ix++)
    if (meta->bitmap[ix])
      return (ix << 6) + (u32)(__builtin_ctzl(meta->bitmap[ix]));

  return WH_FO;
}

  static inline void
wormhole_meta_bm_clear(struct wormmeta * const meta, const u32 id)
{
  meta->bitmap[id >> 6u] &= (~(1lu << (id & 0x3fu)));
  if (id == meta->bitmin) {
    meta->bitmin = (u16)wormhole_meta_bm_gt(meta, id);
    debug_assert(meta->bitmin > id);
  }
}

// find the highest bit that is lower than the id0
// return id0 if not found
  static inline u32
wormhole_meta_bm_lt(const struct wormmeta * const meta, const u32 id0)
{
  if (id0 & 0x3fu) { // not at 0
    const u32 id = id0 - 1u;
    const u64 bits = meta->bitmap[id >> 6] << (63u - (id & 0x3fu));
    if (bits)
      return id - (u32)__builtin_clzl(bits);
  }
  for (u32 ixp = id0 >> 6; ixp; ixp--)
    if (meta->bitmap[ixp-1u])
      return (ixp << 6) - 1u - (u32)(__builtin_clzl(meta->bitmap[ixp-1u]));

  return id0;
}
// }}} meta/bitmap

// lock {{{
  static void
wormhole_leaf_lock_write(struct wormleaf * const leaf, struct wormref * const ref)
{
  if (!rwlock_trylock_write(&(leaf->leaflock))) {
    wormhole_park(ref);
    rwlock_lock_write(&(leaf->leaflock));
    wormhole_resume(ref);
  }
}

  static void
wormhole_leaf_lock_read(struct wormleaf * const leaf, struct wormref * const ref)
{
  if (!rwlock_trylock_read(&(leaf->leaflock))) {
    wormhole_park(ref);
    rwlock_lock_read(&(leaf->leaflock));
    wormhole_resume(ref);
  }
}

  static void
wormhole_meta_lock(struct wormhole * const map, struct wormref * const ref)
{
  if (!rwlock_trylock_write(&(map->metalock))) {
    wormhole_park(ref);
    rwlock_lock_write(&(map->metalock));
    wormhole_resume(ref);
  }
}
// }}} lock

// atomic {{{
  static inline struct wormhmap *
wormhole_hmap_load(struct wormhole * const map)
{
  return (struct wormhmap *)atomic_load_explicit(&(map->hmap_ptr), MO_ACQUIRE);
}

  static inline struct wormhmap *
whunsafe_hmap_load(struct wormhole * const map)
{
  return (struct wormhmap *)atomic_load_explicit(&(map->hmap_ptr), MO_CONSUME);
}

  static inline void
wormhole_hmap_store(struct wormhole * const map, struct wormhmap * const hmap)
{
  atomic_store_explicit(&(map->hmap_ptr), (u64)hmap, MO_SEQ_CST);
}

  static inline u64
wormhole_hv_load(const struct wormhmap * const hmap)
{
  // no concurrent access
  return atomic_load_explicit(&(hmap->hv), MO_CONSUME);
}

  static inline void
wormhole_hv_store(struct wormhmap * const hmap, const u64 v)
{
  atomic_store_explicit(&(hmap->hv), v, MO_RELEASE);
}

  static inline u64
wormhole_lv_load(struct wormleaf * const leaf)
{
  return atomic_load_explicit(&(leaf->lv), MO_CONSUME);
}

  static inline void
wormhole_lv_store(struct wormleaf * const leaf, const u64 v)
{
  atomic_store_explicit(&(leaf->lv), v, MO_RELEASE);
}
// }}} atomic

// co {{{
  static inline void
wormhole_hmap_prefetch_pmap(const struct wormhmap * const hmap, const u32 idx)
{
#if defined(CORR)
  (void)hmap;
  (void)idx;
#else
  cpu_prefetch0(&(hmap->pmap[idx]));
#endif
}

  static inline struct wormmeta *
wormhole_hmap_get_meta(const struct wormhmap * const hmap, const u32 mid, const u32 i)
{
  struct wormmeta * const meta = hmap->pmap[mid].e[i>>1];
#if defined(CORR)
  cpu_prefetch0(meta);
  corr_yield();
#endif
  return meta;
}

  static inline struct wormleaf *
wormhole_meta_down_prev(struct wormleaf * const leaf)
{
#if defined(CORR)
  cpu_prefetch0(leaf);
  corr_yield();
  // the prev will be prefetched afterwards
  // cpu_prefetch0(leaf->prev);
#else
  cpu_prefetch0(leaf->prev);
#endif
  return leaf->prev;
}

  static inline void
wormhole_leaf_prefetch(struct wormleaf * const leaf, const u32 hashlo)
{
  const u64 i = wormhole_pkey(hashlo) / WH_HDIV;
#if defined(CORR)
  cpu_prefetch0(leaf);
  cpu_prefetch0(&(leaf->eh[i-4]));
  cpu_prefetch0(&(leaf->eh[i+4]));
  corr_yield();
#else
  cpu_prefetch0(&(leaf->eh[i]));
#endif
}

  static inline bool
wormhole_kref_kv_match(const struct kref * const key, const struct kv * const curr)
{
#if defined(CORR)
  const u8 * const ptr = (typeof(ptr))curr;
  cpu_prefetch0(ptr);
  cpu_prefetch0(ptr + 64);
  if (key->len > 56) {
    cpu_prefetch0(ptr + 128);
    cpu_prefetch0(ptr + 192);
  }
  corr_yield();
#endif
  return kref_kv_match(key, curr);
}

  static inline void
wormhole_qsbr_update_wait(struct wormref * const ref, const struct wormhmap * const ptr)
{
  qsbr_update(&ref->qref, (u64)ptr);
#if defined(CORR)
  corr_yield();
#endif
}
// }}} co

// }}} helpers

// hmap {{{
// hmap is the MetaTrieHT of Wormhole
  static bool
wormhole_hmap_init(struct wormhmap * const hmap, struct kv * const pbuf, const u32 i)
{
  hmap->slab = slab_create(sizeof(struct wormmeta), WH_SLABMETA_SIZE);
  if (hmap->slab == NULL)
    return false;
  const u64 nr = WH_HMAPINIT_SIZE;
  const u64 wsize = sizeof(hmap->wmap[0]) * nr;
  const u64 psize = sizeof(hmap->pmap[0]) * nr;
  u64 msize = wsize + psize;
  u8 * const mem = pages_alloc_best(msize, true, &msize);
  if (mem == NULL) {
    slab_destroy(hmap->slab);
    hmap->slab = NULL;
    return false;
  }
  hmap->pmap = (typeof(hmap->pmap))mem;
  hmap->wmap = (typeof(hmap->wmap))(mem + psize);
  hmap->msize = msize;
  hmap->mask = nr - 1;
  wormhole_hv_store(hmap, 0);
  hmap->maxplen = 0;
  hmap->hmap_id = i;
  hmap->pbuf = pbuf;
  return true;
}

  static inline void
wormhole_hmap_deinit(struct wormhmap * const hmap)
{
  if (hmap->slab) {
    slab_destroy(hmap->slab);
    hmap->slab = NULL;
  }
  if (hmap->pmap) {
    pages_unmap(hmap->pmap, hmap->msize);
    hmap->pmap = NULL;
    hmap->wmap = NULL;
  }
}

  static inline m128
wormhole_hmap_m128_pkey(const u16 pkey)
{
#if defined(__x86_64__)
  return _mm_set1_epi16((short)pkey);
#elif defined(__aarch64__)
  return vreinterpretq_u8_u16(vdupq_n_u16(pkey));
#endif
}

  static inline u32
wormhole_hmap_match_mask(const struct wormslot * const s, const m128 skey)
{
#if defined(__x86_64__)
  const m128 sv = _mm_load_si128((const void *)s);
  return (u32)_mm_movemask_epi8(_mm_cmpeq_epi16(skey, sv));
#elif defined(__aarch64__)
  const uint16x8_t sv = vld1q_u16((const u16 *)s);
  const uint16x8_t cmp = vceqq_u16(vreinterpretq_u16_u8(skey), sv); // cmpeq
  const uint32x4_t sr2 = vreinterpretq_u32_u16(vshrq_n_u16(cmp, 14)); // 2-bit x 8
  const uint64x2_t sr4 = vreinterpretq_u64_u32(vsraq_n_u32(sr2, sr2, 14)); // 4-bit x 4
  const uint16x8_t sr8 = vreinterpretq_u16_u64(vsraq_n_u64(sr4, sr4, 28)); // 8-bit x 2
  const u32 r = vgetq_lane_u16(sr8, 0) | (vgetq_lane_u16(sr8, 4) << 8);
  return r;
#endif
}

  static inline bool
wormhole_hmap_match_any(const struct wormslot * const s, const m128 skey)
{
#if defined(__x86_64__)
  //return wormhole_hmap_match_mask(s, skey);
  const m128 sv = _mm_load_si128((const void *)s);
  const m128 cmp = _mm_cmpeq_epi16(skey, sv);
  return !_mm_test_all_zeros(cmp, cmp);
#elif defined(__aarch64__)
  const uint16x8_t sv = vld1q_u16((const u16 *)s);
  const uint16x8_t cmp = vceqq_u16(vreinterpretq_u16_u8(skey), sv); // cmpeq
  return vmaxvq_u32(vreinterpretq_u32_u16(cmp)) != 0;
#endif
}

  static inline m128
wormhole_hmap_zero(void)
{
#if defined(__x86_64__)
  return _mm_setzero_si128();
#elif defined(__aarch64__)
  return vdupq_n_u8(0);
#endif
}

// meta_lcp only
  static inline bool
wormhole_hmap_peek(const struct wormhmap * const hmap, const u32 hash32)
{
  const m128 sk = wormhole_hmap_m128_pkey(wormhole_pkey(hash32));
  const u32 midx = hash32 & hmap->mask;
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  return wormhole_hmap_match_any(&(hmap->wmap[midx]), sk)
    || wormhole_hmap_match_any(&(hmap->wmap[midy]), sk);
}

  static inline struct wormmeta *
wormhole_hmap_get_slot(const struct wormhmap * const hmap, const u32 mid,
    const m128 skey, const struct kv * const key)
{
  u32 mask = wormhole_hmap_match_mask(&(hmap->wmap[mid]), skey);
  while (mask) {
    const u32 i2 = (u32)__builtin_ctz(mask);
    struct wormmeta * const meta = wormhole_hmap_get_meta(hmap, mid, i2);
    if (wormhole_key_meta_match(key, meta))
      return meta;
    mask ^= (3u << i2);
  }
  return NULL;
}

  static inline struct wormmeta *
wormhole_hmap_get(const struct wormhmap * const hmap, const struct kv * const key)
{
  const u32 hash32 = key->hashlo;
  const u32 midx = hash32 & hmap->mask;
  wormhole_hmap_prefetch_pmap(hmap, midx);
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  wormhole_hmap_prefetch_pmap(hmap, midy);
  const m128 skey = wormhole_hmap_m128_pkey(wormhole_pkey(hash32));

  struct wormmeta * const r = wormhole_hmap_get_slot(hmap, midx, skey, key);
  if (r)
    return r;
  return wormhole_hmap_get_slot(hmap, midy, skey, key);
}

// for meta_lcp only
  static inline struct wormmeta *
wormhole_hmap_get_kref_slot(const struct wormhmap * const hmap, const u32 mid,
    const m128 skey, const struct kref * const kref)
{
  u32 mask = wormhole_hmap_match_mask(&(hmap->wmap[mid]), skey);
  while (mask) {
    const u32 i2 = (u32)__builtin_ctz(mask);
    struct wormmeta * const meta = wormhole_hmap_get_meta(hmap, mid, i2);
    if (wormhole_kref_meta_match(kref, meta))
      return meta;

    mask ^= (3u << i2);
  }
  return NULL;
}

// for meta_lcp only
  static inline struct wormmeta *
wormhole_hmap_get_kref(const struct wormhmap * const hmap, const struct kref * const kref)
{
  const u32 hash32 = kref->hash32;
  const u32 midx = hash32 & hmap->mask;
  wormhole_hmap_prefetch_pmap(hmap, midx);
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  wormhole_hmap_prefetch_pmap(hmap, midy);
  const m128 skey = wormhole_hmap_m128_pkey(wormhole_pkey(hash32));

  struct wormmeta * const r = wormhole_hmap_get_kref_slot(hmap, midx, skey, kref);
  if (r)
    return r;
  return wormhole_hmap_get_kref_slot(hmap, midy, skey, kref);
}

// for meta_down only
  static inline struct wormmeta *
wormhole_hmap_get_kref1_slot(const struct wormhmap * const hmap, const u32 mid,
    const m128 skey, const struct kref * const kref, const u8 cid)
{
  u32 mask = wormhole_hmap_match_mask(&(hmap->wmap[mid]), skey);
  while (mask) {
    const u32 i2 = (u32)__builtin_ctz(mask);
    struct wormmeta * const meta = wormhole_hmap_get_meta(hmap, mid, i2);
    if (wormhole_kref1_meta_match(kref, meta, cid))
      return meta;

    mask ^= (3u << i2);
  }
  return NULL;
}

// for meta_down only
  static inline struct wormmeta *
wormhole_hmap_get_kref1(const struct wormhmap * const hmap,
    const struct kref * const kref, const u8 cid)
{
  const u32 hash32 = crc32c_u8(kref->hash32, cid);
  const u32 midx = hash32 & hmap->mask;
  wormhole_hmap_prefetch_pmap(hmap, midx);
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  wormhole_hmap_prefetch_pmap(hmap, midy);
  const m128 skey = wormhole_hmap_m128_pkey(wormhole_pkey(hash32));

  struct wormmeta * const r = wormhole_hmap_get_kref1_slot(hmap, midx, skey, kref, cid);
  if (r)
    return r;
  return wormhole_hmap_get_kref1_slot(hmap, midy, skey, kref, cid);
}

  static inline u64
wormhole_hmap_slot_count(const struct wormslot * const slot)
{
  const u32 mask = wormhole_hmap_match_mask(slot, wormhole_hmap_zero());
  return mask ? ((u32)__builtin_ctz(mask) >> 1) : 8;
}

  static inline void
wormhole_hmap_squeeze(const struct wormhmap * const hmap)
{
  const u64 nrs = ((u64)(hmap->mask)) + 1;
  struct wormslot * const wmap = hmap->wmap;
  struct wormmbkt * const pmap = hmap->pmap;
  const u32 mask = hmap->mask;
  for (u64 si = 0; si < nrs; si++) { // # of buckets
    u64 ci = wormhole_hmap_slot_count(&(wmap[si]));
    for (u64 ei = ci - 1; ei < WH_BKT_NR; ei--) {
      struct wormmeta * const meta = pmap[si].e[ei];
      const u64 sj = meta->hash32 & mask; // first hash
      if (sj == si)
        continue;

      // move
      const u64 ej = wormhole_hmap_slot_count(&(wmap[sj]));
      if (ej < WH_BKT_NR) { // has space at home location
        wmap[sj].t[ej] = wmap[si].t[ei];
        pmap[sj].e[ej] = pmap[si].e[ei];
        const u64 ni = ci-1;
        if (ei < ni) {
          wmap[si].t[ei] = wmap[si].t[ni];
          pmap[si].e[ei] = pmap[si].e[ni];
        }
        wmap[si].t[ni] = 0;
        pmap[si].e[ni] = NULL;
        ci--;
      }
    }
  }
}

  static inline void
wormhole_hmap_expand(struct wormhmap * const hmap)
{
  // sync expand
  const u32 mask0 = hmap->mask;
  debug_assert(mask0 < UINT32_MAX);
  const u32 nr0 = mask0 + 1;
  const u32 mask1 = mask0 + nr0;
  debug_assert(mask1 <= UINT32_MAX);
  const u64 nr1 = ((u64)nr0) << 1;
  const u64 wsize = nr1 * sizeof(hmap->wmap[0]);
  const u64 psize = nr1 * sizeof(hmap->pmap[0]);
  u64 msize = wsize + psize;
  u8 * mem = pages_alloc_best(msize, true, &msize);
  if (mem == NULL) {
    // We are at a very deep call stack from wormhole_set().
    // Gracefully handling the failure requires lots of changes.
    // Currently we simply wait for available memory
    // TODO: gracefully return with insertion failure
    char ts[64];
    time_stamp(ts, 64);
    fprintf(stderr, "%s %s sleep-wait for memory allocation %lukB\n",
        __func__, ts, msize >> 10);
    do {
      sleep(1);
      mem = pages_alloc_best(msize, true, &msize);
    } while (mem == NULL);
    time_stamp(ts, 64);
    fprintf(stderr, "%s %s memory allocation done\n", __func__, ts);
  }

  struct wormhmap hmap1 = *hmap;
  hmap1.pmap = (typeof(hmap1.pmap))mem;
  hmap1.wmap = (typeof(hmap1.wmap))(mem + psize);
  hmap1.msize = msize;
  hmap1.mask = mask1;

  const struct wormslot * const wmap0 = hmap->wmap;
  const struct wormmbkt * const pmap0 = hmap->pmap;

  for (u64 s = 0; s < nr0; s++) {
    const struct wormmbkt * const bkt = &pmap0[s];
    for (u64 i = 0; (i < WH_BKT_NR) && bkt->e[i]; i++) {
      const struct wormmeta * const meta = bkt->e[i];
      const u32 hash32 = meta->hash32;
      const u32 idx0 = hash32 & mask0;
      const u32 idx1 = ((idx0 == s) ? hash32 : wormhole_bswap(hash32)) & mask1;

      const u64 n = wormhole_hmap_slot_count(&(hmap1.wmap[idx1]));
      debug_assert(n < 8);
      hmap1.wmap[idx1].t[n] = wmap0[s].t[i];
      hmap1.pmap[idx1].e[n] = bkt->e[i];
    }
  }
  pages_unmap(hmap->pmap, hmap->msize);
  hmap->pmap = hmap1.pmap;
  hmap->wmap = hmap1.wmap;
  hmap->msize = hmap1.msize;
  hmap->mask = hmap1.mask;
  wormhole_hmap_squeeze(hmap);
}

  static inline bool
wormhole_hmap_cuckoo(struct wormhmap * const hmap, const u32 mid0,
    struct wormmeta * const e0, const u16 s0, const u64 depth)
{
  const u64 ii = wormhole_hmap_slot_count(&(hmap->wmap[mid0]));
  if (ii < WH_BKT_NR) {
    hmap->wmap[mid0].t[ii] = s0;
    hmap->pmap[mid0].e[ii] = e0;
    return true;
  } else if (depth == 0) {
    return false;
  }

  // depth > 0
  struct wormmbkt * const bkt = &(hmap->pmap[mid0]);
  u16 * const sv = &(hmap->wmap[mid0].t[0]);
  for (u64 i = 0; (i < WH_BKT_NR) && bkt->e[i]; i++) {
    const struct wormmeta * const meta = bkt->e[i];
    const u32 hash32 = meta->hash32;

    const u32 midx = hash32 & hmap->mask;
    const u32 midy = wormhole_bswap(hash32) & hmap->mask;
    const u32 midt = (midx != mid0) ? midx : midy;
    if (midt != mid0) { // possible
      // no penalty if moving someone back to its 1st hash location
      const u64 depth1 = (midt == midx) ? depth : (depth - 1);
      if (wormhole_hmap_cuckoo(hmap, midt, bkt->e[i], sv[i], depth1)) {
        bkt->e[i] = e0;
        sv[i] = s0;
        return true;
      }
    }
  }
  return false;
}

  static void
wormhole_hmap_set(struct wormhmap * const hmap, struct wormmeta * const meta)
{
  const u32 hash32 = meta->hash32;
  const u32 midx = hash32 & hmap->mask;
  wormhole_hmap_prefetch_pmap(hmap, midx);
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  wormhole_hmap_prefetch_pmap(hmap, midy);
  const u16 pkey = wormhole_pkey(hash32);
  // insert with cuckoo
  if (wormhole_hmap_cuckoo(hmap, midx, meta, pkey, 1))
    return;
  if (wormhole_hmap_cuckoo(hmap, midy, meta, pkey, 1))
    return;
  if (wormhole_hmap_cuckoo(hmap, midx, meta, pkey, 2))
    return;

  // expand
  wormhole_hmap_expand(hmap);

  wormhole_hmap_set(hmap, meta);
}

  static bool
wormhole_hmap_del_slot(struct wormhmap * const hmap, const u32 mid,
    const struct kv * const key, const m128 skey)
{
  u32 mask = wormhole_hmap_match_mask(&(hmap->wmap[mid]), skey);
  while (mask) {
    const u32 i2 = (u32)__builtin_ctz(mask);
    const struct wormmeta * const meta = hmap->pmap[mid].e[i2>>1];
    if (wormhole_key_meta_match(key, meta)) {
      const u32 i = i2 >> 1;
      const u64 j = wormhole_hmap_slot_count(&(hmap->wmap[mid])) - 1;
      hmap->wmap[mid].t[i] = hmap->wmap[mid].t[j];
      hmap->wmap[mid].t[j] = 0;
      hmap->pmap[mid].e[i] = hmap->pmap[mid].e[j];
      hmap->pmap[mid].e[j] = NULL;
      return true;
    }
    mask -= (3u << i2);
  }
  return false;
}

  static bool
wormhole_hmap_del(struct wormhmap * const hmap, const struct kv * const key)
{
  const u32 hash32 = key->hashlo;
  const u32 midx = hash32 & hmap->mask;
  wormhole_hmap_prefetch_pmap(hmap, midx);
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  wormhole_hmap_prefetch_pmap(hmap, midy);
  const m128 skey = wormhole_hmap_m128_pkey(wormhole_pkey(hash32));
  return wormhole_hmap_del_slot(hmap, midx, key, skey)
    || wormhole_hmap_del_slot(hmap, midy, key, skey);
}
// }}} hmap

// create {{{
// it's unsafe
  static bool
wormhole_create_leaf0(struct wormhole * const map)
{
  const bool sr1 = wormhole_slab_reserve(map->hmap2[0].slab, 1);
  const bool sr2 = wormhole_slab_reserve(map->hmap2[1].slab, 1);
  if (!(sr1 && sr2))
    return false;

  // create leaf of empty key
  struct kv * const anchor = wormhole_alloc_akey(0);
  if (anchor == NULL)
    return false;
  kv_dup2(kv_null(), anchor);

  struct wormleaf * const leaf0 = wormhole_alloc_leaf(map, NULL, NULL, anchor);
  if (leaf0 == NULL) {
    wormhole_free_akey(anchor);
    return false;
  }

  struct kv * const mkey = wormhole_alloc_mkey(8);
  if (mkey == NULL) {
    wormhole_free_leaf(map->slab_leaf, leaf0);
    return false;
  }

  memset(mkey, 0, sizeof(*mkey) + 8);
  wormhole_prefix(mkey, 8);
  const u32 hash32 = KV_CRC32C_SEED;
  // create meta of empty key
  for (u64 i = 0; i < 2; i++) {
    if (map->hmap2[i].slab) {
      struct wormmeta * const m0 = wormhole_alloc_meta(map->hmap2[i].slab, leaf0, mkey, hash32, 0);
      debug_assert(m0); // already reserved enough
      wormhole_hmap_set(&(map->hmap2[i]), m0);
    }
  }

  map->leaf0 = leaf0;
  return true;
}

  static struct wormhole *
wormhole_create_internal(const struct kvmap_mm * const mm, const bool hmapx2)
{
  struct wormhole * const map = yalloc(sizeof(*map));
  if (map == NULL)
    return NULL;
  memset(map, 0, sizeof(*map));
  // mm
  map->mm = mm ? (*mm) : kvmap_mm_dup;

  // pbuf for meta-merge
  map->pbuf = yalloc(1lu << 16); // 64kB
  if (map->pbuf == NULL)
    goto fail_pbuf;

  // hmap
  if (wormhole_hmap_init(&(map->hmap2[0]), map->pbuf, 0) == false)
    goto fail_hmap_0;

  if (hmapx2)
    if (wormhole_hmap_init(&(map->hmap2[1]), map->pbuf, 1) == false)
      goto fail_hmap_1;

  // slabs
  map->slab_leaf = slab_create(sizeof(struct wormleaf), WH_SLABLEAF_SIZE);
  if (map->slab_leaf == NULL)
    goto fail_lslab;

  // qsbr
  map->qsbr = qsbr_create();
  if (map->qsbr == NULL)
    goto fail_qsbr;

  // leaf0
  if (wormhole_create_leaf0(map) == false)
    goto fail_leaf0;

  rwlock_init(&(map->metalock));
  wormhole_hmap_store(map, &map->hmap2[0]);
  return map;

fail_leaf0:
  qsbr_destroy(map->qsbr);
fail_qsbr:
  slab_destroy(map->slab_leaf);
fail_lslab:
  wormhole_hmap_deinit(&(map->hmap2[1]));
fail_hmap_1:
  wormhole_hmap_deinit(&(map->hmap2[0]));
fail_hmap_0:
  free(map->pbuf);
fail_pbuf:
  free(map);
  return NULL;
}

  struct wormhole *
wormhole_create(const struct kvmap_mm * const mm)
{
  return wormhole_create_internal(mm, true);
}

  struct wormhole *
whunsafe_create(const struct kvmap_mm * const mm)
{
  return wormhole_create_internal(mm, false);
}
// }}} create

// jump {{{
// search in the hash table for the Longest Prefix Match of the search key
// The corresponding wormmeta node is returned and the LPM is recorded in kref
  static inline struct wormmeta *
wormhole_meta_lcp(const struct wormhmap * const hmap, struct kref * const kref,
    const u32 klen)
{
  // invariant: lo <= lcp < (lo + gd)
  // ending condition: gd == 1
  u32 gd = (hmap->maxplen < klen ? hmap->maxplen : klen) + 1u;
  u32 lo = 0;
  u32 loh = KV_CRC32C_SEED;

#define META_LCP_GAP_1 ((7u))
  while (META_LCP_GAP_1 < gd) {
    const u32 inc = gd >> 3 << 2; // x4
    const u32 hash32 = crc32c_inc_x4(kref->ptr + lo, inc, loh);
    if (wormhole_hmap_peek(hmap, hash32)) {
      loh = hash32;
      lo += inc;
      gd -= inc;
    } else {
      gd = inc;
    }
  }

  while (1 < gd) {
    const u32 inc = gd >> 1;
    const u32 hash32 = crc32c_inc_123(kref->ptr + lo, inc, loh);
    if (wormhole_hmap_peek(hmap, hash32)) {
      loh = hash32;
      lo += inc;
      gd -= inc;
    } else {
      gd = inc;
    }
  }
#undef META_LCP_GAP_1

  kref->hash32 = loh;
  kref->len = lo;
  struct wormmeta * ret = wormhole_hmap_get_kref(hmap, kref);
  if (ret)
    return ret;

  gd = lo;
  lo = 0;
  loh = KV_CRC32C_SEED;

#define META_LCP_GAP_2 ((5u))
  while (META_LCP_GAP_2 < gd) {
    const u32 inc = (gd * 3) >> 2;
    wormhole_kref_inc(kref, lo, loh, inc);
    struct wormmeta * const tmp = wormhole_hmap_get_kref(hmap, kref);
    if (tmp) {
      loh = kref->hash32;
      lo += inc;
      gd -= inc;
      ret = tmp;
      if (wormhole_meta_bm_test(tmp, kref->ptr[lo])) {
        loh = crc32c_u8(loh, kref->ptr[lo]);
        lo++;
        gd--;
        ret = NULL;
      } else {
        gd = 1;
        break;
      }
    } else {
      gd = inc;
    }
  }

  while (1 < gd) {
    const u32 inc = (gd * 3) >> 2;
    wormhole_kref_inc_123(kref, lo, loh, inc);
    struct wormmeta * const tmp = wormhole_hmap_get_kref(hmap, kref);
    if (tmp) {
      loh = kref->hash32;
      lo += inc;
      gd -= inc;
      ret = tmp;
      if (wormhole_meta_bm_test(tmp, kref->ptr[lo])) {
        loh = crc32c_u8(loh, kref->ptr[lo]);
        lo++;
        gd--;
        ret = NULL;
      } else {
        gd = 1;
        break;
      }
    } else {
      gd = inc;
    }
  }
#undef META_LCP_GAP_2

  if (kref->len != lo) {
    kref->hash32 = loh;
    kref->len = lo;
  }
  if (ret == NULL)
    ret = wormhole_hmap_get_kref(hmap, kref);
  debug_assert(ret);
  return ret;
}

  static inline struct wormleaf *
wormhole_meta_down(const struct wormhmap * const hmap, const struct kref * const kref,
    const struct wormmeta * const meta, const u32 klen)
{
  struct wormleaf * ret;
  if (kref->len < klen) { // partial match
    const u32 id0 = kref->ptr[kref->len];
    debug_assert(meta->bitmin != id0);
    if (meta->bitmin > id0) { // no left-sibling
      ret = meta->lmost;
      if (meta->bitmin < WH_FO) // has right-sibling
        ret = wormhole_meta_down_prev(ret);
      // otherwise, meta is a leaf node
    } else { // meta->bitmin < id0; has left-sibling
      const u32 id1 = wormhole_meta_bm_lt(meta, id0);
      const struct wormmeta * const child = wormhole_hmap_get_kref1(hmap, kref, (u8)id1);
      ret = child->rmost;
    }
  } else { // plen == klen
    debug_assert(kref->len == klen);
    ret = meta->lmost;
    if (ret->klen > kref->len)
      ret = wormhole_meta_down_prev(ret);
  }
  return ret;
}

  static struct wormleaf *
wormhole_jump_leaf(const struct wormhmap * const hmap, const struct kref * const key)
{
  struct kref kref = {.ptr = key->ptr};
  debug_assert(kv_crc32c(key->ptr, key->len) == key->hash32);

  const struct wormmeta * const meta = wormhole_meta_lcp(hmap, &kref, key->len);
  struct wormleaf * const leaf = wormhole_meta_down(hmap, &kref, meta, key->len);
  wormhole_leaf_prefetch(leaf, key->hash32);
  return leaf;
}

  static inline struct wormleaf *
wormhole_jump_leaf_read(struct wormref * const ref, const struct kref * const key)
{
  struct wormhole * const map = ref->map;
#pragma nounroll
  do {
    const struct wormhmap * const hmap = wormhole_hmap_load(map);
    qsbr_update(&ref->qref, (u64)hmap);
    struct wormleaf * const leaf = wormhole_jump_leaf(hmap, key);
    const u64 v = wormhole_hv_load(hmap);
#pragma nounroll
    do {
      if (rwlock_trylock_read_nr(&(leaf->leaflock), 64)) {
        if (wormhole_lv_load(leaf) <= v)
          return leaf;
        rwlock_unlock_read(&(leaf->leaflock));
        break;
      }
      const struct wormhmap * const hmapx = wormhole_hmap_load(map);
      if (wormhole_lv_load(leaf) > v)
        break;
      wormhole_qsbr_update_wait(ref, hmapx);
    } while (true);
  } while (true);
}

  static inline struct wormleaf *
wormhole_jump_leaf_write(struct wormref * const ref, const struct kref * const key)
{
  struct wormhole * const map = ref->map;
#pragma nounroll
  do {
    const struct wormhmap * const hmap = wormhole_hmap_load(map);
    qsbr_update(&ref->qref, (u64)hmap);
    struct wormleaf * const leaf = wormhole_jump_leaf(hmap, key);
    const u64 v = wormhole_hv_load(hmap);
#pragma nounroll
    do {
      if (rwlock_trylock_write_nr(&(leaf->leaflock), 64)) {
        if (wormhole_lv_load(leaf) <= v)
          return leaf;
        rwlock_unlock_write(&(leaf->leaflock));
        break;
      }
      const struct wormhmap * const hmapx = wormhole_hmap_load(map);
      if (wormhole_lv_load(leaf) > v)
        break;
      wormhole_qsbr_update_wait(ref, hmapx);
    } while (true);
  } while (true);
}
// }}} jump

// leaf-only read {{{
// assumes there in no duplicated keys
// bisect the first key that is >= the given key
// return 0 .. nr_sorted
  static u64
wormhole_leaf_bisect_sorted(const struct wormleaf * const leaf, const struct kref * const key)
{
  u64 lo = 0;
  u64 hi = leaf->nr_sorted;
  while (lo < hi) {
    u64 i = (lo + hi) >> 1;
    const int cmp = kref_kv_compare(key, u64_to_ptr(leaf->es[i].e3));
    if (cmp < 0)
      hi = i;
    else if (cmp > 0)  //  key > [i]
      lo = i + 1;
    else // same key
      return i;
  }
  return lo;
}

// same to bisect_sorted but very target likely goes beyond the end
  static u64
wormhole_leaf_bisect_sorted_end(const struct wormleaf * const leaf, const struct kref * const key)
{
  if (leaf->nr_sorted) {
    const int cmp = kref_kv_compare(key, u64_to_ptr(leaf->es[leaf->nr_sorted-1].e3));
    if (cmp > 0)
      return leaf->nr_sorted;
    else if (cmp == 0)
      return leaf->nr_sorted - 1;
    else
      return wormhole_leaf_bisect_sorted(leaf, key);
  } else {
    return 0;
  }
}

// fast point-lookup
// returns WH_KPN if not found
  static u64
wormhole_leaf_match(const struct wormleaf * const leaf, const struct kref * const key)
{
  const u16 pkey = wormhole_pkey(key->hash32);
  const u64 i0 = pkey / WH_HDIV;
  const struct entry13 * const eh = leaf->eh;

  if (eh[i0].e1 == pkey) {
    struct kv * const curr = u64_to_ptr(eh[i0].e3);
    if (wormhole_kref_kv_match(key, curr))
      return i0;
  }
  if (eh[i0].e1 == 0)
    return WH_KPN;

  // search left
  u64 i = i0 - 1;
  while (i < WH_KPN) {
    if (eh[i].e1 == pkey) {
      struct kv * const curr = u64_to_ptr(eh[i].e3);
      if (wormhole_kref_kv_match(key, curr))
        return i;
    } else if (eh[i].e1 < pkey) {
      break;
    }
    i--;
  }

  // search right
  i = i0 + 1;
  while (i < WH_KPN) {
    if (eh[i].e1 == pkey) {
      struct kv * const curr = u64_to_ptr(eh[i].e3);
      if (wormhole_kref_kv_match(key, curr))
        return i;
    } else if ((eh[i].e1 > pkey) || (eh[i].e1 == 0)) {
      break;
    }
    i++;
  }

  // not found
  return WH_KPN;
}

  static inline u64
wormhole_leaf_match_kv(const struct wormleaf * const leaf, const struct kv * const key)
{
  const struct kref kref = kv_kref(key);
  return wormhole_leaf_match(leaf, &kref);
}
// }}} leaf-only read

// get/probe {{{
  struct kv *
wormhole_get(struct wormref * const ref, const struct kref * const key, struct kv * const out)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_read(ref, key);
  const u64 i = wormhole_leaf_match(leaf, key);
  struct kv * const tmp = (i < WH_KPN) ? ref->map->mm.out(u64_to_ptr(leaf->eh[i].e3), out) : NULL;
  rwlock_unlock_read(&(leaf->leaflock));
  return tmp;
}

  struct kv *
whsafe_get(struct wormref * const ref, const struct kref * const key, struct kv * const out)
{
  wormhole_resume(ref);
  struct kv * const ret = wormhole_get(ref, key, out);
  wormhole_park(ref);
  return ret;
}

  struct kv *
whunsafe_get(struct wormhole * const map, const struct kref * const key, struct kv * const out)
{
  struct wormhmap * const hmap = whunsafe_hmap_load(map);
  struct wormleaf * const leaf = wormhole_jump_leaf(hmap, key);
  const u64 i = wormhole_leaf_match(leaf, key);
  return (i < WH_KPN) ? map->mm.out(u64_to_ptr(leaf->eh[i].e3), out) : NULL;
}

  bool
wormhole_probe(struct wormref * const ref, const struct kref * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_read(ref, key);
  const u64 i = wormhole_leaf_match(leaf, key);
  rwlock_unlock_read(&(leaf->leaflock));
  return i < WH_KPN;
}

  bool
whsafe_probe(struct wormref * const ref, const struct kref * const key)
{
  wormhole_resume(ref);
  const bool r = wormhole_probe(ref, key);
  wormhole_park(ref);
  return r;
}

  bool
whunsafe_probe(struct wormhole * const map, const struct kref * const key)
{
  struct wormhmap * const hmap = whunsafe_hmap_load(map);
  struct wormleaf * const leaf = wormhole_jump_leaf(hmap, key);
  return wormhole_leaf_match(leaf, key) < WH_KPN;
}
// }}} get/probe

// single-leaf modification {{{
  static inline void
wormhole_leaf_sort_m2(struct entry13 * const es, const u64 n1, const u64 n2)
{
  if (n1 == 0 || n2 == 0)
    return; // no need to sort

  struct entry13 et[WH_KPN/2]; // min(n1,n2) < KPN/2
  if (n1 <= n2) { // merge left
    memcpy(et, &(es[0]), sizeof(es[0]) * n1);
    struct entry13 * eo = es;
    struct entry13 * e1 = et; // size == n1
    struct entry13 * e2 = &(es[n1]); // size == n2
    const struct entry13 * const z1 = e1 + n1;
    const struct entry13 * const z2 = e2 + n2;
    while ((e1 < z1) && (e2 < z2)) {
      const int cmp = kv_compare(u64_to_ptr(e1->e3), u64_to_ptr(e2->e3));
      if (cmp < 0)
        *(eo++) = *(e1++);
      else if (cmp > 0)
        *(eo++) = *(e2++);
      else
        debug_die();

      if (eo == e2)
        break; // finish early
    }
    if (eo < e2)
      memcpy(eo, e1, sizeof(*eo) * (size_t)(e2 - eo));
  } else {
    memcpy(et, &(es[n1]), sizeof(es[0]) * n2);
    struct entry13 * eo = &(es[n1 + n2 - 1]); // merge backwards
    struct entry13 * e1 = &(es[n1 - 1]); // size == n1
    struct entry13 * e2 = &(et[n2 - 1]); // size == n2
    const struct entry13 * const z1 = e1 - n1;
    const struct entry13 * const z2 = e2 - n2;
    while ((e1 > z1) && (e2 > z2)) {
      const int cmp = kv_compare(u64_to_ptr(e1->e3), u64_to_ptr(e2->e3));
      if (cmp < 0)
        *(eo--) = *(e2--);
      else if (cmp > 0)
        *(eo--) = *(e1--);
      else
        debug_die();

      if (eo == e1)
        break;
    }
    if (eo > e1)
      memcpy(e1 + 1, et, sizeof(*eo) * (size_t)(eo - e1));
  }
}

  static inline int
entry13_qsort_compare(const void * const p1, const void * const p2)
{
  const struct entry13 * const e1 = (typeof(e1))p1;
  const struct entry13 * const e2 = (typeof(e2))p2;
  const struct kv * const k1 = u64_to_ptr(e1->e3);
  const struct kv * const k2 = u64_to_ptr(e2->e3);
  return kv_compare(k1, k2);
}

// make sure all keys are sorted in a leaf node
  static void
wormhole_leaf_sync_sorted(struct wormleaf * const leaf)
{
  const u64 s = leaf->nr_sorted;
  const u64 n = leaf->nr_keys;
  if (s == n)
    return;

  qsort(&(leaf->es[s]), n - s, sizeof(leaf->es[0]), entry13_qsort_compare);
  // merge-sort inplace
  wormhole_leaf_sort_m2(leaf->es, s, (n - s));
  leaf->nr_sorted = n;
}

  static void
wormhole_leaf_insert_eh(struct entry13 * const eh, const struct entry13 new)
{
  const u16 pkey = new.e1;
  const u64 i0 = pkey / WH_HDIV;
  if (eh[i0].e1 == 0) { // insert
    eh[i0] = new;
    return;
  }

  // find left-most insertion point
  u64 i = i0;
  while (i && eh[i-1].e1 && (eh[i-1].e1 >= pkey))
    i--;
  while ((i < WH_KPN) && eh[i].e1 && (eh[i].e1 < pkey)) // stop at >= or empty
    i++;
  const u64 il = --i; // i in [0, KPN]

  // find left empty slot
  if (i > (i0 - 1))
    i = i0 - 1;
  while ((i < WH_KPN) && eh[i].e1)
    i--;
  const u64 el = i; // el < i0 or el is invalid (>= KPN)

  // find right-most insertion point.
  i = il + 1;
  while ((i < WH_KPN) && eh[i].e1 && (eh[i].e1 == pkey))
    i++;
  const u64 ir = i; // ir >= il, in [0, KPN]

  // find right empty slot
  if (i < (i0 + 1))
    i = i0 + 1;
  while ((i < WH_KPN) && eh[i].e1)
    i++;
  const u64 er = i; // er > i0 or el is invalid (>= KPN)

  // el <= il < ir <= er    (if < WH_KPN)
  const u64 dl = (el < WH_KPN) ? (il - el) : WH_KPN;
  const u64 dr = (er < WH_KPN) ? (er - ir) : WH_KPN;
  if (dl <= dr) { // push left
    debug_assert(dl < WH_KPN);
    if (dl)
      memmove(&(eh[el]), &(eh[el+1]), sizeof(eh[0]) * dl);
    eh[il] = new;
  } else {
    debug_assert(dr < WH_KPN);
    if (dr)
      memmove(&(eh[ir+1]), &(eh[ir]), sizeof(eh[0]) * dr);
    eh[ir] = new;
  }
}

  static void
wormhole_leaf_insert(struct wormleaf * const leaf, const struct kv * const new)
{
  debug_assert(new->hash == kv_crc32c_extend(kv_crc32c(new->kv, new->klen)));
  debug_assert(leaf->nr_keys < WH_KPN);
  const u64 nr0 = leaf->nr_keys;
  leaf->nr_keys = nr0 + 1;

  // append to es (delayed sort)
  leaf->es[nr0].e1 = wormhole_pkey(new->hashlo);
  leaf->es[nr0].e3 = ptr_to_u64(new);
  // optimize for seq insertion
  if (nr0 == leaf->nr_sorted) {
    if (nr0) {
      const struct kv * const kvn = u64_to_ptr(leaf->es[nr0 - 1].e3);
      if (kv_compare(new, kvn) > 0)
        leaf->nr_sorted = nr0 + 1;
    } else {
      leaf->nr_sorted = 1;
    }
  }

  // insert into eh
  wormhole_leaf_insert_eh(leaf->eh, leaf->es[nr0]);
}

  static void
wormhole_leaf_magnet_eh(struct entry13 * const eh, const u64 im)
{
  // try left
  u64 i = im - 1;
  while ((i < WH_KPN) && eh[i].e1 && ((eh[i].e1 / WH_HDIV) > i)) {
    eh[i+1] = eh[i];
    eh[i].v64 = 0;
    i--;
  }
  // return if moved
  if (eh[im].e1)
    return;

  // try right
  i = im + 1;
  while ((i < WH_KPN) && eh[i].e1 && ((eh[i].e1 / WH_HDIV) < i)) {
    eh[i-1] = eh[i];
    eh[i].v64 = 0;
    i++;
  }
  // eh[im] may still be 0
}

  static struct kv *
wormhole_leaf_remove(struct wormleaf * const leaf, const u64 im)
{
  const u64 nr_keys = leaf->nr_keys;
  const u64 v64 = leaf->eh[im].v64;
  debug_assert(v64);
  // remove from es
  u64 is;
  for (is = 0; is < nr_keys; is++) {
    if (leaf->es[is].v64 == v64) {
      if (is < (nr_keys - 1))
        leaf->es[is] = leaf->es[nr_keys - 1];

      break;
    }
  }
  debug_assert(is < nr_keys);
  if (leaf->nr_sorted > is)
    leaf->nr_sorted = is;

  struct kv * const victim = u64_to_ptr(leaf->eh[im].e3);

  // remove from eh
  leaf->eh[im].v64 = 0;
  leaf->nr_keys--;

  // use magnet
  wormhole_leaf_magnet_eh(leaf->eh, im);
  return victim;
}

// for delr (delete-range)
  static void
wormhole_leaf_delete_range(struct wormhole * const map, struct wormleaf * const leaf,
    const u64 i0, const u64 end)
{
  if (i0 == end)
    return;
  debug_assert(leaf->nr_keys == leaf->nr_sorted);
  for (u64 i = i0; i < end; i++)
    map->mm.free(u64_to_ptr(leaf->es[i].e3), map->mm.priv);

  if ((end - i0) < 16) { // fix eh when deleting few
    for (u64 i = i0; i < end; i++) {
      const u64 v64 = leaf->es[i].v64;
      for (u64 ih = 0; ih < WH_KPN; ih++) {
        if (leaf->eh[ih].v64 == v64) {
          leaf->eh[ih].v64 = 0;
          wormhole_leaf_magnet_eh(leaf->eh, ih);
          break;
        }
      }
    }
  }
  // es and nr
  memmove(&(leaf->es[i0]), &(leaf->es[end]), sizeof(leaf->es[0]) * (leaf->nr_sorted - end));
  leaf->nr_sorted -= (end - i0);
  leaf->nr_keys = leaf->nr_sorted;
  // insert remaining keys to emptied eh[]
  if ((end - i0) >= 16) { // rebuild eh when deleting few
    memset(leaf->eh, 0, sizeof(leaf->eh[0]) * WH_KPN);
    for (u64 i = 0; i < leaf->nr_sorted; i++)
      wormhole_leaf_insert_eh(leaf->eh, leaf->es[i]);
  }
}

  static void
wormhole_leaf_update(struct wormhole * const map, struct wormleaf * const leaf, const u64 im,
    const struct kv * const new)
{
  debug_assert(new->hash == kv_crc32c_extend(kv_crc32c(new->kv, new->klen)));
  // search entry in es (is)
  const u64 v64 = leaf->eh[im].v64;
  const u64 nr = leaf->nr_keys;
  // TODO: use simd to search is
  u64 is;
  for (is = 0; is < nr; is++)
    if (leaf->es[is].v64 == v64)
      break;
  debug_assert(is < nr); // must exist

  struct entry13 * const e = &(leaf->eh[im]);
  struct kv * const old = u64_to_ptr(e->e3);
  debug_assert(old);
  if (map->mm.free)
    map->mm.free(old, map->mm.priv);

  e->e3 = ptr_to_u64(new);
  // e1 remains unchanged
  leaf->es[is] = *e;
}
// }}} single-leaf modification

// split/merge leaf {{{
// calculate the anchor-key length between two keys
// compare anchor with key0 if i2 == 0; only for split_at()
// return 0 if cannot cut (valid anchor is at least 1 token)
  static u32
wormhole_split_cut_alen(const struct wormleaf * const leaf, const u64 i1, const u64 i2)
{
  debug_assert(leaf->nr_keys == leaf->nr_sorted);
  debug_assert(i2 < leaf->nr_sorted);
  debug_assert((i1 < i2) || (i2 == 0));
  const struct kv * const k1 = i2 ? u64_to_ptr(leaf->es[i1].e3) : leaf->anchor;
  const struct kv * const k2 = u64_to_ptr(leaf->es[i2].e3);
  const u32 lcp = kv_key_lcp(k1, k2);
  if (lcp == k1->klen) { // k1 is k2's prefix
    // no cut if len1 == len2 after removing trailing zeros
    u32 tklen = k2->klen;
    while ((tklen > k1->klen) && (k2->kv[tklen-1] == 0))
      tklen--;
    if (tklen <= k1->klen)
      return 0;
  }
  // have valid cut
  u32 alen = lcp + 1;
  while ((alen < k2->klen) && (k2->kv[alen-1] == 0))
    alen++;
  debug_assert(k2->kv[alen-1]);
  return (alen <= UINT16_MAX) ? alen : 0;
}

// internal use only by split_cut
  static bool
wormhole_split_cut_try_alen(const struct wormleaf * const leaf, const u64 i1, const u64 i2,
    const u32 alen)
{
  debug_assert(i1 < i2);
  struct kv * const k1 = u64_to_ptr(leaf->es[i1].e3);
  struct kv * const k2 = u64_to_ptr(leaf->es[i2].e3);
  const u8 c1 = (k1->klen < alen) ? 0 : k1->kv[alen - 1];
  const u8 c2 = (k2->klen < alen) ? 0 : k2->kv[alen - 1];
  return c1 != c2;
}

// determine where to cut at leaf
// return WH_KPN if there is no valid cut point
// otherwise, return a value in the range [1..(nr_keys-1)]
  static u64
wormhole_split_cut(struct wormleaf * const leaf)
{
  wormhole_leaf_sync_sorted(leaf);
  debug_assert(leaf->nr_keys == leaf->nr_sorted);
  debug_assert(leaf->nr_keys >= 2);
  u64 lo = 0;
  u64 hi = leaf->nr_sorted-1;
  const u64 target = leaf->next ? WH_MID : WH_KPN_MRG;

  const u32 alen = wormhole_split_cut_alen(leaf, lo, hi);
  if (alen == 0)
    return WH_KPN;

  while ((lo + 1) < hi) {
    const u64 mid = (lo + hi + 1) >> 1;
    if (mid <= target) { // try right
      if (wormhole_split_cut_try_alen(leaf, mid, hi, alen))
        lo = mid;
      else
        hi = mid;
    } else { // try left
      if (wormhole_split_cut_try_alen(leaf, lo, mid, alen))
        hi = mid;
      else
        lo = mid;
    }
  }
  return hi;
}

  static void
wormhole_split_leaf_move(struct wormleaf * const leaf1, struct wormleaf * const leaf2, const u64 cut)
{
  const u64 nr_move = leaf1->nr_keys - cut;
  // copy es
  memcpy(leaf2->es, &(leaf1->es[cut]), sizeof(leaf2->es[0]) * nr_move);
  // valid keys: leaf1 [0, cut-1]; leaf2 [0, nr_all - cut - 1]

  // leaf2's eh is empty
  // remove from leaf1's eh and insert to leaf2's eh
  for (u64 i = 0; i < nr_move; i++) {
    // insert into leaf2->eh
    wormhole_leaf_insert_eh(leaf2->eh, leaf2->es[i]);
    // remove from leaf1->eh
    const struct kv * const key = u64_to_ptr(leaf2->es[i].e3);
    const u64 im = wormhole_leaf_match_kv(leaf1, key);
    debug_assert(im < WH_KPN);
    leaf1->eh[im].v64 = 0; // remove
    wormhole_leaf_magnet_eh(leaf1->eh, im);
  }

  // metadata
  leaf1->nr_keys = cut;
  leaf2->nr_keys = nr_move;

  if (leaf1->nr_sorted > cut) {
    leaf2->nr_sorted = leaf1->nr_sorted - cut;
    leaf1->nr_sorted = cut;
  } else {
    leaf2->nr_sorted = 0;
  }
}

// create an anchor for leaf-split
  static struct kv *
wormhole_split_alloc_anchor(const struct kv * const key1, const struct kv * const key2)
{
  // keys are still in leaf1
  const u32 key2len = key2->klen;
  u32 alen = kv_key_lcp(key1, key2) + 1;

  // anchor must end with non-zero
  while ((alen < key2len) && (key2->kv[alen - 1] == 0))
    alen++;
  debug_assert(alen <= key2len);

  // now we have the correct alen
  struct kv * const anchor2 = wormhole_alloc_akey(alen);
  if (anchor2)
    kv_refill(anchor2, key2->kv, alen, NULL, 0);
  return anchor2;
}

// all locked
// assumption: es[0..cut-2] < es[cut-1] < es[cut] < es[cut+1..nr-1]
// move keys starting with [cut] in leaf1 to leaf2
  static struct wormleaf *
wormhole_split_leaf(struct wormhole * const map, struct wormleaf * const leaf1, const u64 cut)
{
  // anchor of leaf2
  struct kv * const key1 = cut ? u64_to_ptr(leaf1->es[cut-1].e3) : leaf1->anchor;
  struct kv * const key2 = u64_to_ptr(leaf1->es[cut].e3);
  struct kv * const anchor2 = wormhole_split_alloc_anchor(key1, key2);
  if (anchor2 == NULL) // anchor alloc failed
    return NULL;

  // create leaf2 with anchor2
  struct wormleaf * const leaf2 = wormhole_alloc_leaf(map, leaf1, leaf1->next, anchor2);
  if (leaf2 == NULL) {
    wormhole_free_akey(anchor2);
    return NULL;
  }

  // split_hmap will unlock the leaf nodes; must move now
  wormhole_split_leaf_move(leaf1, leaf2, cut);
  return leaf2;
}

// MERGE is the only operation that deletes a leaf node (leaf2).
// It ALWAYS merges the right node into the left node even if the left is empty.
// This requires both of their writer locks to be acquired.
// This allows iterators to safely probe the next node (but not backwards).
// In other words, if either the reader or the writer lock of node X has been acquired:
// X->next (the pointer) cannot be changed by any other thread.
// X->next cannot be deleted.
// But the content in X->next can still be changed.
  static void
wormhole_merge_leaf_move(struct wormleaf * const leaf1, struct wormleaf * const leaf2)
{
  const u64 nr1 = leaf1->nr_keys;
  const u64 nr2 = leaf2->nr_keys;
  if (nr2 == 0)
    return;

  debug_assert((nr1 + nr2) <= WH_KPN);
  struct entry13 * const eh1 = leaf1->eh;
  struct entry13 * const es2 = leaf2->es;

  for (u64 i = 0; i < nr2; i++) {
    // callers are merger, no need to clear eh2
    debug_assert(es2[i].v64);
    wormhole_leaf_insert_eh(eh1, es2[i]);
  }
  leaf1->nr_keys = nr1 + nr2; // nr_sorted remain unchanged
  // move es
  memcpy(&(leaf1->es[nr1]), &(leaf2->es[0]), sizeof(leaf2->es[0]) * nr2);
  // if leaf1 is already sorted
  if (leaf1->nr_sorted == nr1)
    leaf1->nr_sorted += leaf2->nr_sorted;
}
// }}} split-merge leaf

// split meta {{{
// zero-extend an existing node
  static void
wormhole_split_meta_extend(struct wormhmap * const hmap, struct wormmeta * const meta,
    struct kv * const mkey, struct kv * const mkey2)
{
  debug_assert(meta->lmost == meta->rmost);
  debug_assert(meta->klen == mkey->klen);
  wormhole_meta_bm_set(meta, 0);
  const u32 len0 = mkey->klen;
  struct kv * mkey1 = NULL;

  if (meta->keyref->klen > len0) { // can reuse keyref of the existing meta node
    debug_assert(meta->keyref->kv[len0] == 0);
    mkey1 = meta->keyref;
  } else if (mkey->kv[len0] == 0) {
    mkey1 = mkey;
  } else if (mkey2) { // only at the last step
    debug_assert(mkey2->klen > len0);
    debug_assert(mkey2->kv[len0] == 0); // should have been prepared
    mkey1 = mkey2;
  } else {
    debug_die();
  }
  struct slab * const slab = hmap->slab;
  struct wormleaf * const lmost = meta->lmost;
  const u32 hash321 = crc32c_u8(mkey->hashlo, 0);
  const u32 len1 = len0 + 1; // new anchor at +1
  struct wormmeta * const meta1 = wormhole_alloc_meta(slab, lmost, mkey1, hash321, len1);
  debug_assert(meta1);
  wormhole_hmap_set(hmap, meta1);
}

// return true if a new node is created
  static bool
wormhole_split_meta_touch(struct wormhmap * const hmap, struct kv * const mkey,
    struct kv * const mkey2, struct wormleaf * const leaf)
{
  struct wormmeta * const meta = wormhole_hmap_get(hmap, mkey);
  if (meta) {
    if (meta->bitmin == WH_FO) // push down leaf
      wormhole_split_meta_extend(hmap, meta, mkey, mkey2);
    wormhole_meta_bm_set(meta, mkey->kv[mkey->klen]);
    if (meta->lmost == leaf->next)
      meta->lmost = leaf;
    if (meta->rmost == leaf->prev)
      meta->rmost = leaf;
    return false;
  } else { // create new node
    struct slab * const slab = hmap->slab;
    struct wormmeta * const new = wormhole_alloc_meta(slab, leaf, mkey, mkey->hashlo, mkey->klen);
    debug_assert(new);
    if (mkey->klen < leaf->klen)
      wormhole_meta_bm_set(new, mkey->kv[mkey->klen]);
    wormhole_hmap_set(hmap, new);
    return true;
  }
}

// for leaf1, a leaf2 is already linked at its right side.
// this function updates the meta-map by moving leaf1 and hooking leaf2 at correct positions
  static void
wormhole_split_meta_hmap(struct wormhmap * const hmap, struct wormleaf * const leaf,
    struct kv * const mkey, struct kv * const mkey2)
{
  // left branches
  u32 i = leaf->next ? kv_key_lcp(leaf->prev->anchor, leaf->next->anchor) : 0;

  // save klen
  const u32 mklen = mkey->klen;
  wormhole_prefix(mkey, i);
  do {
    const bool rnew = wormhole_split_meta_touch(hmap, mkey, mkey2, leaf);
    if ((i >= leaf->klen) && rnew)
      break;
    i++;
    wormhole_prefix_inc1(mkey);
    debug_assert(i < mklen);
  } while (true);

  // adjust maxplen; i is the plen of the last _touch()
  if (i > hmap->maxplen)
    hmap->maxplen = i;
  debug_assert(i < 65520);

  // restore klen
  mkey->klen = mklen;
  if (mkey2)
    mkey2->klen = mklen; // hash of mkey2 is not required
}

  static struct kv *
wormhole_split_alloc_mkey(struct wormleaf * const leaf)
{
  u32 buflen = leaf->klen;
  struct wormleaf * const next = leaf->next;
  if (next && (next->klen > buflen)) { // may need a longer mkey
    const u32 lcp = kv_key_lcp(leaf->anchor, next->anchor);
    if (lcp == buflen) { // buflen == leaf->klen
      while ((buflen < next->klen) && (next->anchor->kv[buflen] == 0))
        buflen++;
    }
  }
  buflen += 2; // very safe. mkey is long enough for split
  return wormhole_alloc_mkey_extend(leaf->anchor, buflen);
}

// we may need to allocate a mkey2 if a1 is a prefix of a2
// return true if mkey2 should be allocated
  static bool
wormhole_split_check_mkey2(const struct wormleaf * const leaf2)
{
  const struct kv * const a1 = leaf2->prev->anchor;
  const struct kv * const a2 = leaf2->anchor;
  return (a1->klen <= a2->klen) && (!memcmp(a1->kv, a2->kv, a1->klen));
}

// all locks will be released before returning
  static bool
wormhole_split_meta_ref(struct wormref * const ref, struct wormleaf * const leaf2,
    const bool unlock_leaf1)
{
  struct kv * const mkey = wormhole_split_alloc_mkey(leaf2);
  if (mkey == NULL)
    return false;
  struct kv * mkey2 = NULL;
  if (wormhole_split_check_mkey2(leaf2)) {
    mkey2 = wormhole_alloc_mkey_extend(leaf2->prev->anchor, mkey->klen);
    if (mkey2 == NULL) {
      wormhole_free_mkey(mkey);
      return false;
    }
  }

  struct wormhole * const map = ref->map;
  // metalock
  wormhole_meta_lock(map, ref);

  // check slab reserve
  const bool sr1 = wormhole_slab_reserve(map->hmap2[0].slab, mkey->klen);
  const bool sr2 = wormhole_slab_reserve(map->hmap2[1].slab, mkey->klen);
  if (!(sr1 && sr2)) {
    rwlock_unlock_write(&(map->metalock));
    wormhole_free_mkey(mkey);
    wormhole_free_mkey(mkey2);
    return false;
  }

  struct wormhmap * const hmap0 = wormhole_hmap_load(map);
  struct wormhmap * const hmap1 = &(map->hmap2[1-hmap0->hmap_id]);

  // link
  struct wormleaf * const leaf1 = leaf2->prev;
  leaf1->next = leaf2;
  if (leaf2->next)
    leaf2->next->prev = leaf2;

  // update versions
  const u64 v1 = wormhole_hv_load(hmap0) + 1;
  wormhole_lv_store(leaf1, v1);
  wormhole_lv_store(leaf2, v1);
  wormhole_hv_store(hmap1, v1);

  wormhole_split_meta_hmap(hmap1, leaf2, mkey, mkey2);

  qsbr_update(&ref->qref, (u64)hmap1);

  // switch hmap
  wormhole_hmap_store(map, hmap1);

  if (unlock_leaf1)
    rwlock_unlock_write(&(leaf1->leaflock));
  rwlock_unlock_write(&(leaf2->leaflock));

  qsbr_wait(map->qsbr, (u64)hmap1);

  wormhole_split_meta_hmap(hmap0, leaf2, mkey, mkey2);

  rwlock_unlock_write(&(map->metalock));

  if (mkey->refcnt == 0) // this is possible
    wormhole_free_mkey(mkey);
  if (mkey2 && (mkey2->refcnt == 0)) // this is possible
    wormhole_free_mkey(mkey2);
  return true;
}

// all locks (metalock + leaflocks) will be released before returning
// leaf1->lock (write) is already taken
  static bool
wormhole_split_insert_ref(struct wormref * const ref, struct wormleaf * const leaf1,
    struct kv * const new)
{
  const u64 cut = wormhole_split_cut(leaf1);
  // check for a corner case that we don't handle for now.
  // TODO: Implement fat node.
  //       Option 1: a pointer in wormleaf pointing to the extra items
  //       Option 2: make eh/es dynamically allocated
  if (cut == WH_KPN) {
    fprintf(stderr, "%s WARNING: Cannot split\n", __func__);
    rwlock_unlock_write(&(leaf1->leaflock));
    return false; // insertion failed
  }

  struct wormleaf * const leaf2 = wormhole_split_leaf(ref->map, leaf1, cut);
  if (leaf2 == NULL) {
    rwlock_unlock_write(&(leaf1->leaflock));
    return false;
  }

  rwlock_lock_write(&(leaf2->leaflock));
  const int cmp = kv_compare(new, leaf2->anchor);
  struct wormleaf * const leaf = (cmp < 0) ? leaf1 : leaf2;
  wormhole_leaf_insert(leaf, new);

  const bool rsm = wormhole_split_meta_ref(ref, leaf2, true);
  if (rsm == false) {
    // undo insertion & merge; free leaf2
    const u64 im = wormhole_leaf_match_kv(leaf, new);
    (void)wormhole_leaf_remove(leaf, im);
    wormhole_merge_leaf_move(leaf1, leaf2);
    rwlock_unlock_write(&(leaf1->leaflock));
    rwlock_unlock_write(&(leaf2->leaflock));
    wormhole_free_leaf(ref->map->slab_leaf, leaf2);
  }
  return rsm;
}

  static bool
whunsafe_split_meta(struct wormhole * const map, struct wormleaf * const leaf2)
{
  struct kv * const mkey = wormhole_split_alloc_mkey(leaf2);
  if (mkey == NULL)
    return false;
  struct kv * mkey2 = NULL;
  if (wormhole_split_check_mkey2(leaf2)) {
    mkey2 = wormhole_alloc_mkey_extend(leaf2->prev->anchor, mkey->klen);
    if (mkey2 == NULL) {
      wormhole_free_mkey(mkey);
      return false;
    }
  }

  const bool sr1 = wormhole_slab_reserve(map->hmap2[0].slab, mkey->klen);
  const bool sr2 = wormhole_slab_reserve(map->hmap2[1].slab, mkey->klen);
  if (!(sr1 && sr2)) {
    rwlock_unlock_write(&(map->metalock));
    wormhole_free_mkey(mkey);
    wormhole_free_mkey(mkey2);
    return false;
  }

  // link
  leaf2->prev->next = leaf2;
  if (leaf2->next)
    leaf2->next->prev = leaf2;

  for (u64 i = 0; i < 2; i++)
    if (map->hmap2[i].pmap)
      wormhole_split_meta_hmap(&(map->hmap2[i]), leaf2, mkey, mkey2);
  if (mkey->refcnt == 0) // this is possible
    wormhole_free_mkey(mkey);
  if (mkey2 && (mkey2->refcnt == 0)) // this is possible
    wormhole_free_mkey(mkey2);
  return true;
}

  static bool
whunsafe_split_insert(struct wormhole * const map, struct wormleaf * const leaf1,
    struct kv * const new)
{
  const u64 cut = wormhole_split_cut(leaf1);
  // check for a corner case that we don't handle for now.
  // TODO: Implement fat node.
  //       Option 1: a pointer in wormleaf pointing to the extra items
  //       Option 2: make eh/es dynamically allocated
  if (cut == WH_KPN) {
    fprintf(stderr, "%s WARNING: Cannot split\n", __func__);
    return false; // insertion failed
  }

  struct wormleaf * const leaf2 = wormhole_split_leaf(map, leaf1, cut);
  if (leaf2 == NULL)
    return false;

  const int cmp = kv_compare(new, leaf2->anchor);
  struct wormleaf * const leaf = (cmp < 0) ? leaf1 : leaf2;

  wormhole_leaf_insert(leaf, new);

  const bool rsm = whunsafe_split_meta(map, leaf2);
  if (rsm == false) {
    // undo insertion, merge, free leaf2
    const u64 im = wormhole_leaf_match_kv(leaf, new);
    (void)wormhole_leaf_remove(leaf, im);
    wormhole_merge_leaf_move(leaf1, leaf2);
    wormhole_free_leaf(map->slab_leaf, leaf2);
  }
  return rsm;
}
// }}} split meta

// set {{{
  bool
wormhole_set(struct wormref * const ref, struct kv * const kv)
{
  // we always allocate a new item on SET
  // future optimizations may perform in-place update
  struct wormhole * const map = ref->map;
  struct kv * const new = map->mm.in(kv, map->mm.priv);
  if (new == NULL)
    return false;
  const struct kref kref = kv_kref(new);

  struct wormleaf * const leaf = wormhole_jump_leaf_write(ref, &kref);
  // update
  const u64 im = wormhole_leaf_match(leaf, &kref);
  if (im < WH_KPN) {
    wormhole_leaf_update(map, leaf, im, new);
    rwlock_unlock_write(&(leaf->leaflock));
    return true;
  }

  // insert
  if (leaf->nr_keys < WH_KPN) { // just insert
    wormhole_leaf_insert(leaf, new);
    rwlock_unlock_write(&(leaf->leaflock));
    return true;
  }

  // split_insert changes hmap
  // all locks should be released in wormhole_split_insert_ref()
  const bool rsi = wormhole_split_insert_ref(ref, leaf, new);
  if (!rsi)
    map->mm.free(new, map->mm.priv);
  return rsi;
}

  bool
whsafe_set(struct wormref * const ref, struct kv * const kv)
{
  wormhole_resume(ref);
  const bool r = wormhole_set(ref, kv);
  wormhole_park(ref);
  return r;
}

  bool
whunsafe_set(struct wormhole * const map, struct kv * const kv)
{
  struct kv * const new = map->mm.in(kv, map->mm.priv);
  if (new == NULL)
    return false;
  const struct kref kref = kv_kref(new);

  struct wormhmap * const hmap = whunsafe_hmap_load(map);
  struct wormleaf * const leaf = wormhole_jump_leaf(hmap, &kref);
  // update
  const u64 im = wormhole_leaf_match(leaf, &kref);
  if (im < WH_KPN) { // overwrite
    wormhole_leaf_update(map, leaf, im, new);
    return true;
  }

  // insert
  if (leaf->nr_keys < WH_KPN) { // just insert
    wormhole_leaf_insert(leaf, new);
    return true;
  }

  // split_insert changes hmap
  const bool rsi = whunsafe_split_insert(map, leaf, new);
  if (!rsi)
    map->mm.free(new, map->mm.priv);
  return rsi;
}

  bool
wormhole_merge(struct wormref * const ref, const struct kref * const kref,
    kv_merge_func uf, void * const priv)
{
  struct wormhole * const map = ref->map;
  struct wormleaf * const leaf = wormhole_jump_leaf_write(ref, kref);
  // update
  const u64 im = wormhole_leaf_match(leaf, kref);
  if (im < WH_KPN) { // update
    struct kv * const kv0 = u64_to_ptr(leaf->eh[im].e3);
    struct kv * const kv = uf(kv0, priv);
    if (kv != kv0) { // if not inplace-update
      struct kv * const new = map->mm.in(kv, map->mm.priv);
      wormhole_leaf_update(ref->map, leaf, im, new);
    }
    rwlock_unlock_write(&(leaf->leaflock));
    return true;
  }

  struct kv * const kv = uf(NULL, priv);
  if (!kv) { // nothing to be inserted
    rwlock_unlock_write(&(leaf->leaflock));
    return true;
  }
  struct kv * const new = map->mm.in(kv, map->mm.priv);
  // insert
  if (leaf->nr_keys < WH_KPN) { // just insert
    wormhole_leaf_insert(leaf, new);
    rwlock_unlock_write(&(leaf->leaflock));
    return true;
  }

  // split_insert changes hmap
  // all locks should be released in wormhole_split_insert_ref()
  const bool rsi = wormhole_split_insert_ref(ref, leaf, new);
  if (!rsi)
    map->mm.free(new, map->mm.priv);
  return rsi;
}

  bool
whsafe_merge(struct wormref * const ref, const struct kref * const kref,
    kv_merge_func uf, void * const priv)
{
  wormhole_resume(ref);
  const bool r = wormhole_merge(ref, kref, uf, priv);
  wormhole_park(ref);
  return r;
}

  bool
whunsafe_merge(struct wormhole * const map, const struct kref * const kref,
    kv_merge_func uf, void * const priv)
{
  struct wormhmap * const hmap = whunsafe_hmap_load(map);
  struct wormleaf * const leaf = wormhole_jump_leaf(hmap, kref);
  // update
  const u64 im = wormhole_leaf_match(leaf, kref);
  if (im < WH_KPN) { // update
    struct kv * const kv0 = u64_to_ptr(leaf->eh[im].e3);
    struct kv * const kv = uf(kv0, priv);
    if (kv != kv0) { // if not inplace-update
      struct kv * const new = map->mm.in(kv, map->mm.priv);
      wormhole_leaf_update(map, leaf, im, new);
    }
    return true;
  }

  struct kv * const kv = uf(NULL, priv);
  struct kv * const new = map->mm.in(kv, map->mm.priv);
  // insert
  if (leaf->nr_keys < WH_KPN) { // just insert
    wormhole_leaf_insert(leaf, new);
    return true;
  }

  // split_insert changes hmap
  const bool rsi = whunsafe_split_insert(map, leaf, new);
  if (!rsi)
    map->mm.free(new, map->mm.priv);
  return rsi;
}
// }}} set

// inplace {{{
  bool
wormhole_inpr(struct wormref * const ref, const struct kref * const key,
    kv_inp_func uf, void * const priv)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_read(ref, key);
  const u64 im = wormhole_leaf_match(leaf, key);
  if (im < WH_KPN) {
    uf(u64_to_ptr(leaf->eh[im].e3), priv);
    rwlock_unlock_read(&(leaf->leaflock));
    return true;
  } else {
    uf(NULL, priv);
    rwlock_unlock_read(&(leaf->leaflock));
    return false;
  }
}

  bool
wormhole_inpw(struct wormref * const ref, const struct kref * const key,
    kv_inp_func uf, void * const priv)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_write(ref, key);
  const u64 im = wormhole_leaf_match(leaf, key);
  if (im < WH_KPN) {
    uf(u64_to_ptr(leaf->eh[im].e3), priv);
    rwlock_unlock_write(&(leaf->leaflock));
    return true;
  } else {
    uf(NULL, priv);
    rwlock_unlock_write(&(leaf->leaflock));
    return false;
  }
}

  bool
whsafe_inpr(struct wormref * const ref, const struct kref * const key,
    kv_inp_func uf, void * const priv)
{
  wormhole_resume(ref);
  const bool r = wormhole_inpr(ref, key, uf, priv);
  wormhole_park(ref);
  return r;
}

  bool
whsafe_inpw(struct wormref * const ref, const struct kref * const key,
    kv_inp_func uf, void * const priv)
{
  wormhole_resume(ref);
  const bool r = wormhole_inpw(ref, key, uf, priv);
  wormhole_park(ref);
  return r;
}

  bool
whunsafe_inp(struct wormhole * const map, const struct kref * const key,
    kv_inp_func uf, void * const priv)
{
  struct wormhmap * const hmap = whunsafe_hmap_load(map);
  struct wormleaf * const leaf = wormhole_jump_leaf(hmap, key);
  const u64 im = wormhole_leaf_match(leaf, key);
  if (im < WH_KPN) { // overwrite
    uf(u64_to_ptr(leaf->eh[im].e3), priv);
    return true;
  } else {
    uf(NULL, priv);
    return false;
  }
}
// }}} set

// merge meta {{{
// all locks held
  static void
wormhole_merge_meta_hmap(struct wormhmap * const hmap, struct wormleaf * const leaf)
{
  // leaf->next is the new next after merge, which can be NULL
  struct wormleaf * const prev = leaf->prev;
  struct wormleaf * const next = leaf->next;
  struct kv * const pbuf = hmap->pbuf;
  kv_dup2_key(leaf->anchor, pbuf);
  u32 i = (prev && next) ? kv_key_lcp(prev->anchor, next->anchor) : 0;
  wormhole_prefix(pbuf, i);
  struct wormmeta * parent = NULL;
  do {
    debug_assert(i <= hmap->maxplen);
    struct wormmeta * const meta = wormhole_hmap_get(hmap, pbuf);
    debug_assert(meta);
    if (meta->lmost == meta->rmost) { // delete single-child
      debug_assert(meta->lmost == leaf);
      const u32 bitmin = meta->bitmin;
      wormhole_hmap_del(hmap, pbuf);
      wormhole_free_meta(hmap->slab, meta);
      if (parent) {
        wormhole_meta_bm_clear(parent, pbuf->kv[i-1]);
        parent = NULL;
      }
      if (bitmin == WH_FO) // no child
        break;
    } else { // adjust lmost rmost
      if (meta->lmost == leaf)
        meta->lmost = next;

      if (meta->rmost == leaf)
        meta->rmost = prev;
      parent = meta;
    }

    if (i >= leaf->klen)
      pbuf->kv[i] = 0; // for zero-extended prefixes
    i++;
    wormhole_prefix_inc1(pbuf);
  } while (true);
}

// all locks (metalock + two leaflock) will be released before returning
// merge leaf2 to leaf1, removing all metadata to leaf2 and leaf2 itself
  static void
wormhole_merge_meta_ref(struct wormref * const ref, struct wormleaf * const leaf1,
    struct wormleaf * const leaf2, const bool unlock_leaf1)
{
  debug_assert(leaf1->next == leaf2);
  debug_assert(leaf2->prev == leaf1);
  struct wormhole * const map = ref->map;

  wormhole_meta_lock(map, ref);

  struct wormhmap * const hmap0 = wormhole_hmap_load(map);
  struct wormhmap * const hmap1 = &(map->hmap2[1-hmap0->hmap_id]);
  const u64 v1 = wormhole_hv_load(hmap0) + 1;

  leaf1->next = leaf2->next;
  if (leaf2->next)
    leaf2->next->prev = leaf1;

  wormhole_lv_store(leaf1, v1);
  wormhole_lv_store(leaf2, v1);
  wormhole_hv_store(hmap1, v1);

  wormhole_merge_meta_hmap(hmap1, leaf2);

  qsbr_update(&ref->qref, (u64)hmap1);

  // switch hmap
  wormhole_hmap_store(map, hmap1);

  if (unlock_leaf1)
    rwlock_unlock_write(&(leaf1->leaflock));
  rwlock_unlock_write(&(leaf2->leaflock));

  qsbr_wait(map->qsbr, (u64)hmap1);

  wormhole_merge_meta_hmap(hmap0, leaf2);
  // leaf2 is now safe to be removed
  wormhole_free_leaf(map->slab_leaf, leaf2);
  rwlock_unlock_write(&(map->metalock));
}

  static bool
wormhole_merge_meta_leaf_ref(struct wormref * const ref, struct wormleaf * const leaf)
{
  struct wormleaf * const next = leaf->next;
  debug_assert(next);

  wormhole_leaf_lock_write(next, ref);

  // double check
  if ((leaf->nr_keys + next->nr_keys) <= WH_KPN) {
    wormhole_merge_leaf_move(leaf, next);
    wormhole_merge_meta_ref(ref, leaf, next, true);
  } else { // the next contains more keys than expected
    rwlock_unlock_write(&(leaf->leaflock));
    rwlock_unlock_write(&(next->leaflock));
  }
  return true;
}

  static void
whunsafe_merge_meta_leaf(struct wormhole * const map, struct wormleaf * const leaf1,
    struct wormleaf * const leaf2)
{
  debug_assert(leaf1->next == leaf2);
  debug_assert(leaf2->prev == leaf1);
  wormhole_merge_leaf_move(leaf1, leaf2);

  leaf1->next = leaf2->next;
  if (leaf2->next)
    leaf2->next->prev = leaf1;
  for (u64 i = 0; i < 2; i++)
    if (map->hmap2[i].pmap)
      wormhole_merge_meta_hmap(&(map->hmap2[i]), leaf2);
  wormhole_free_leaf(map->slab_leaf, leaf2);
}
// }}} merge meta

// del {{{
  static void
wormhole_del_helper_ref(struct wormref * const ref, struct wormleaf * const leaf)
{
  const u64 n1 = leaf->nr_keys;
  const u64 n2 = leaf->next ? leaf->next->nr_keys : WH_KPN;
  if ((leaf->next && (n1 == 0)) || ((n1 + n2) < WH_KPN_MRG)) {
    // try merge, it may fail if malloc fails
    (void)wormhole_merge_meta_leaf_ref(ref, leaf);
    // locks are already released; immediately return
  } else {
    rwlock_unlock_write(&(leaf->leaflock));
  }
}

  bool
wormhole_del(struct wormref * const ref, const struct kref * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_write(ref, key);
  const u64 im = wormhole_leaf_match(leaf, key);
  if (im < WH_KPN) { // found
    struct kv * const kv = wormhole_leaf_remove(leaf, im);
    debug_assert(kv);
    ref->map->mm.free(kv, ref->map->mm.priv);
    wormhole_del_helper_ref(ref, leaf);
    return true;
  } else {
    rwlock_unlock_write(&(leaf->leaflock));
    return false;
  }
}

  bool
whsafe_del(struct wormref * const ref, const struct kref * const key)
{
  wormhole_resume(ref);
  const bool r = wormhole_del(ref, key);
  wormhole_park(ref);
  return r;
}

  static void
whunsafe_del_try_merge_leaf(struct wormhole * const map, struct wormleaf * const leaf)
{
  const u64 n0 = leaf->prev ? leaf->prev->nr_keys : WH_KPN;
  const u64 n1 = leaf->nr_keys;
  const u64 n2 = leaf->next ? leaf->next->nr_keys : WH_KPN;

  if ((leaf->prev && (n1 == 0)) || ((n0 + n1) < WH_KPN_MRG)) {
    whunsafe_merge_meta_leaf(map, leaf->prev, leaf);
  } else if ((leaf->next && (n1 == 0)) || ((n1 + n2) < WH_KPN_MRG)) {
    whunsafe_merge_meta_leaf(map, leaf, leaf->next);
  }
}

  bool
whunsafe_del(struct wormhole * const map, const struct kref * const key)
{
  struct wormhmap * const hmap = whunsafe_hmap_load(map);
  struct wormleaf * const leaf = wormhole_jump_leaf(hmap, key);
  const u64 im = wormhole_leaf_match(leaf, key);
  if (im < WH_KPN) { // found
    struct kv * const kv = wormhole_leaf_remove(leaf, im);
    debug_assert(kv);
    map->mm.free(kv, map->mm.priv);

    whunsafe_del_try_merge_leaf(map, leaf);
    return true;
  }
  return false;
}

  u64
wormhole_delr(struct wormref * const ref, const struct kref * const start,
    const struct kref * const end)
{
  struct wormleaf * const leafa = wormhole_jump_leaf_write(ref, start);
  wormhole_leaf_sync_sorted(leafa);
  const u64 ia = wormhole_leaf_bisect_sorted(leafa, start);
  const u64 iaz = end ? wormhole_leaf_bisect_sorted_end(leafa, end) : leafa->nr_keys;
  if (iaz < ia) { // do nothing if end < start
    rwlock_unlock_write(&(leafa->leaflock));
    return 0;
  }
  u64 ndel = iaz - ia;
  struct wormhole * const map = ref->map;
  wormhole_leaf_delete_range(map, leafa, ia, iaz);
  if (leafa->nr_keys > ia) { // end hit; done
    wormhole_del_helper_ref(ref, leafa);
    return ndel;
  }

  while (leafa->next) {
    struct wormleaf * const leafx = leafa->next;
    wormhole_leaf_lock_write(leafx, ref);
    // two leaf nodes locked
    wormhole_leaf_sync_sorted(leafx);
    const u64 iz = end ? wormhole_leaf_bisect_sorted_end(leafx, end) : leafx->nr_keys;
    ndel += iz;
    wormhole_leaf_delete_range(map, leafx, 0, iz);
    if (leafx->nr_keys == 0) { // removed all
      wormhole_merge_meta_ref(ref, leafa, leafx, false);
    } else { // partially removed; done
      if ((leafa->nr_keys + leafx->nr_keys) < WH_KPN_MRG) {
        wormhole_merge_leaf_move(leafa, leafx);
        wormhole_merge_meta_ref(ref, leafa, leafx, true);
      } else {
        rwlock_unlock_write(&(leafa->leaflock));
        rwlock_unlock_write(&(leafx->leaflock));
      }
      return ndel;
    }
  }
  rwlock_unlock_write(&(leafa->leaflock));
  return ndel;
}

  u64
whsafe_delr(struct wormref * const ref, const struct kref * const start,
    const struct kref * const end)
{
  wormhole_resume(ref);
  const u64 ret = wormhole_delr(ref, start, end);
  wormhole_park(ref);
  return ret;
}

  u64
whunsafe_delr(struct wormhole * const map, const struct kref * const start,
    const struct kref * const end)
{
  // first leaf
  struct wormhmap * const hmap = whunsafe_hmap_load(map);
  struct wormleaf * const leafa = wormhole_jump_leaf(hmap, start);
  wormhole_leaf_sync_sorted(leafa);
  // last leaf
  struct wormleaf * const leafz = end ? wormhole_jump_leaf(hmap, end) : NULL;

  // select start/end on leafa
  const u64 ia = wormhole_leaf_bisect_sorted(leafa, start);
  const u64 iaz = end ? wormhole_leaf_bisect_sorted_end(leafa, end) : leafa->nr_keys;
  if (iaz < ia)
    return 0;

  wormhole_leaf_delete_range(map, leafa, ia, iaz);
  u64 ndel = iaz - ia;

  if (leafa == leafz) { // one node only
    whunsafe_del_try_merge_leaf(map, leafa);
    return ndel;
  }

  // 0 or more nodes between leafa and leafz
  while (leafa->next != leafz) {
    struct wormleaf * const leafx = leafa->next;
    ndel += leafx->nr_keys;
    for (u64 i = 0; i < leafx->nr_keys; i++)
      map->mm.free(u64_to_ptr(leafx->es[i].e3), map->mm.priv);
    leafx->nr_keys = 0;
    leafx->nr_sorted = 0;
    whunsafe_merge_meta_leaf(map, leafa, leafx);
  }
  // delete the smaller keys in leafz
  if (leafz) {
    wormhole_leaf_sync_sorted(leafz);
    const u64 iz = wormhole_leaf_bisect_sorted_end(leafz, end);
    wormhole_leaf_delete_range(map, leafz, 0, iz);
    ndel += iz;
    whunsafe_del_try_merge_leaf(map, leafa);
  }
  return ndel;
}
// }}} del

// iter {{{
// safe iter: safe sort with read-lock acquired
// unsafe iter: allow concurrent seek/skip
  static void
wormhole_iter_leaf_sync_sorted(struct wormleaf * const leaf)
{
  if (leaf->nr_keys != leaf->nr_sorted) {
    spinlock_lock(&(leaf->sortlock));
    wormhole_leaf_sync_sorted(leaf);
    spinlock_unlock(&(leaf->sortlock));
  }
}

  struct wormhole_iter *
wormhole_iter_create(struct wormref * const ref)
{
  struct wormhole_iter * const iter = malloc(sizeof(*iter));
  if (iter == NULL)
    return NULL;
  iter->ref = ref;
  iter->map = ref->map;
  iter->leaf = NULL;
  iter->next_id = 0;
  //wormhole_iter_seek(iter, kref_null());
  return iter;
}

  static void
wormhole_iter_fix(struct wormhole_iter * const iter)
{
  if (!wormhole_iter_valid(iter))
    return;

  while (iter->next_id >= iter->leaf->nr_sorted) {
    struct wormleaf * const next = iter->leaf->next;
    if (next) {
      struct wormref * const ref = iter->ref;
      wormhole_leaf_lock_read(next, ref);
      rwlock_unlock_read(&(iter->leaf->leaflock));

      wormhole_iter_leaf_sync_sorted(next);
    } else {
      rwlock_unlock_read(&(iter->leaf->leaflock));
    }
    iter->leaf = next;
    iter->next_id = 0;
    if (!wormhole_iter_valid(iter))
      return;
  }
}

  void
wormhole_iter_seek(struct wormhole_iter * const iter, const struct kref * const key)
{
  debug_assert(key);
  if (iter->leaf)
    rwlock_unlock_read(&(iter->leaf->leaflock));

  struct wormleaf * const leaf = wormhole_jump_leaf_read(iter->ref, key);
  wormhole_iter_leaf_sync_sorted(leaf);

  iter->leaf = leaf;
  iter->next_id = wormhole_leaf_bisect_sorted(leaf, key);
  wormhole_iter_fix(iter);
}

  void
whsafe_iter_seek(struct wormhole_iter * const iter, const struct kref * const key)
{
  wormhole_resume(iter->ref);
  wormhole_iter_seek(iter, key);
}

  bool
wormhole_iter_valid(struct wormhole_iter * const iter)
{
  return iter->leaf != NULL;
}

  static struct kv *
wormhole_iter_current(struct wormhole_iter * const iter)
{
  if (wormhole_iter_valid(iter)) {
    debug_assert(iter->next_id < iter->leaf->nr_sorted);
    struct kv * const kv = u64_to_ptr(iter->leaf->es[iter->next_id].e3);
    return kv;
  }
  return NULL;
}

  struct kv *
wormhole_iter_peek(struct wormhole_iter * const iter, struct kv * const out)
{
  struct kv * const kv = wormhole_iter_current(iter);
  if (kv) {
    struct kv * const ret = iter->map->mm.out(kv, out);
    return ret;
  }
  return NULL;
}

  bool
wormhole_iter_kref(struct wormhole_iter * const iter, struct kref * const kref)
{
  struct kv * const kv = wormhole_iter_current(iter);
  if (kv) {
    kref_ref_kv(kref, kv);
    return true;
  }
  return false;
}

  bool
wormhole_iter_kvref(struct wormhole_iter * const iter, struct kvref * const kvref)
{
  struct kv * const kv = wormhole_iter_current(iter);
  if (kv) {
    kvref_ref_kv(kvref, kv);
    return true;
  }
  return false;
}

  void
wormhole_iter_skip(struct wormhole_iter * const iter, const u32 nr)
{
  for (u32 i = 0; i < nr; i++) {
    if (!wormhole_iter_valid(iter))
      return;
    iter->next_id++;
    wormhole_iter_fix(iter);
  }
}

  struct kv *
wormhole_iter_next(struct wormhole_iter * const iter, struct kv * const out)
{
  struct kv * const ret = wormhole_iter_peek(iter, out);
  if (ret)
    wormhole_iter_skip(iter, 1);
  return ret;
}

  bool
wormhole_iter_inp(struct wormhole_iter * const iter, kv_inp_func uf, void * const priv)
{
  struct kv * const kv = wormhole_iter_current(iter);
  uf(kv, priv); // call uf even if (kv == NULL)
  return kv != NULL;
}

  void
wormhole_iter_park(struct wormhole_iter * const iter)
{
  if (iter->leaf) {
    rwlock_unlock_read(&(iter->leaf->leaflock));
    iter->leaf = NULL;
  }
}

  void
whsafe_iter_park(struct wormhole_iter * const iter)
{
  wormhole_iter_park(iter);
  wormhole_park(iter->ref);
}

  void
wormhole_iter_destroy(struct wormhole_iter * const iter)
{
  if (iter->leaf)
    rwlock_unlock_read(&(iter->leaf->leaflock));
  free(iter);
}

  void
whsafe_iter_destroy(struct wormhole_iter * const iter)
{
  wormhole_park(iter->ref);
  wormhole_iter_destroy(iter);
}
// }}} iter

// unsafe iter {{{
  struct wormhole_iter *
whunsafe_iter_create(struct wormhole * const map)
{
  struct wormhole_iter * const iter = malloc(sizeof(*iter));
  if (iter == NULL)
    return NULL;
  iter->ref = NULL;
  iter->map = map;
  iter->leaf = NULL;
  iter->next_id = 0;
  whunsafe_iter_seek(iter, kref_null());
  return iter;
}

  static void
whunsafe_iter_fix(struct wormhole_iter * const iter)
{
  if (!wormhole_iter_valid(iter))
    return;

  while (iter->next_id >= iter->leaf->nr_sorted) {
    struct wormleaf * const next = iter->leaf->next;
    if (next)
      wormhole_iter_leaf_sync_sorted(next);
    iter->leaf = next;
    iter->next_id = 0;
    if (!wormhole_iter_valid(iter))
      return;
  }
}

  void
whunsafe_iter_seek(struct wormhole_iter * const iter, const struct kref * const key)
{
  struct wormhmap * const hmap = whunsafe_hmap_load(iter->map);
  struct wormleaf * const leaf = wormhole_jump_leaf(hmap, key);
  wormhole_iter_leaf_sync_sorted(leaf);

  iter->leaf = leaf;
  iter->next_id = wormhole_leaf_bisect_sorted(leaf, key);
  whunsafe_iter_fix(iter);
}

  bool
whunsafe_iter_valid(struct wormhole_iter * const iter)
{
  return wormhole_iter_valid(iter);
}

  void
whunsafe_iter_skip(struct wormhole_iter * const iter, const u32 nr)
{
  for (u32 i = 0; i < nr; i++) {
    if (!wormhole_iter_valid(iter))
      return;
    iter->next_id++;
    whunsafe_iter_fix(iter);
  }
}

  struct kv *
whunsafe_iter_next(struct wormhole_iter * const iter, struct kv * const out)
{
  struct kv * const ret = wormhole_iter_peek(iter, out);
  if (ret)
    whunsafe_iter_skip(iter, 1);
  return ret;
}

  bool
whunsafe_iter_inp(struct wormhole_iter * const iter, kv_inp_func uf, void * const priv)
{
  return wormhole_iter_inp(iter, uf, priv);
}

  void
whunsafe_iter_destroy(struct wormhole_iter * const iter)
{
  free(iter);
}
// }}} unsafe iter

// misc {{{
  inline struct wormref *
wormhole_ref(struct wormhole * const map)
{
  struct wormref * const ref = malloc(sizeof(*ref));
  if (ref == NULL)
    return NULL;
  ref->map = map;
  if (qsbr_register(map->qsbr, &(ref->qref)) == false) {
    free(ref);
    return NULL;
  }
  return ref;
}

  inline struct wormref *
whsafe_ref(struct wormhole * const map)
{
  struct wormref * const ref = wormhole_ref(map);
  if (ref)
    wormhole_park(ref);
  return ref;
}

  inline struct wormhole *
wormhole_unref(struct wormref * const ref)
{
  struct wormhole * const map = ref->map;
  qsbr_unregister(map->qsbr, &(ref->qref));
  free(ref);
  return map;
}

  inline void
wormhole_park(struct wormref * const ref)
{
  qsbr_park(&(ref->qref));
}

  inline void
wormhole_resume(struct wormref * const ref)
{
  qsbr_resume(&(ref->qref));
}

  inline void
wormhole_refresh_qstate(struct wormref * const ref)
{
  qsbr_update(&(ref->qref), (u64)wormhole_hmap_load(ref->map));
}

  static void
wormhole_clean_hmap(struct wormhole * const map)
{
  for (u64 x = 0; map->hmap2[x].pmap; x++) {
    struct wormhmap * const hmap = &(map->hmap2[x]);
    const u64 nr_slots = hmap->mask + 1;
    struct slab * const slab = hmap->slab;
    struct wormmbkt * const pmap = hmap->pmap;
    for (u64 s = 0; s < nr_slots; s++) {
      struct wormmbkt * const slot = &(pmap[s]);
      for (u64 i = 0; i < WH_BKT_NR; i++)
        if (slot->e[i])
          wormhole_free_meta(slab, slot->e[i]);
    }
    memset(hmap->pmap, 0, hmap->msize);
    hmap->maxplen = 0;
  }
}

  static void
wormhole_free_leaf_keys(struct wormleaf * const leaf, kvmap_mm_free_func free_func, void * const free_priv)
{
  void * tmp = NULL;
  for (u64 i = 0; i < WH_KPN; i++) {
    if (leaf->eh[i].v64) {
      void * const curr = u64_to_ptr(leaf->eh[i].e3);
      cpu_prefetch0(curr);
      if (tmp)
        free_func(tmp, free_priv);
      tmp = curr;
    }
  }
  cpu_prefetch0(leaf->anchor);
  if (tmp)
    free_func(tmp, free_priv);
  wormhole_free_akey(leaf->anchor);
}

  static void *
wormhole_clean_worker(void * const ptr)
{
  struct wormhole * const map = (typeof(map))ptr;
  const u32 nr = map->clean_ths;
  const u32 seq = atomic_fetch_add(&map->clean_seq, 1);
  kvmap_mm_free_func free_func = map->mm.free;
  void * const free_priv = map->mm.priv;

  struct wormleaf * leaf = map->leaf0;
  do {
    for (u32 x = 0; leaf && (x < nr); x++) {
      if (x == seq)
        wormhole_free_leaf_keys(leaf, free_func, free_priv);
      leaf = leaf->next;
    }
  } while (leaf);
  return NULL;
}

// unsafe
  static void
wormhole_clean_free(struct wormhole * const map, const u32 ths)
{
  wormhole_clean_hmap(map);
  map->clean_seq = 0;
  map->clean_ths = ths;
  thread_fork_join(ths, wormhole_clean_worker, false, map);
  slab_free_all(map->slab_leaf);
  map->leaf0 = NULL;
}

  inline void
wormhole_clean_th(struct wormhole * const map, const u32 ths)
{
  wormhole_clean_free(map, ths);
  wormhole_create_leaf0(map);
}

// unsafe
  void
wormhole_clean(struct wormhole * const map)
{
  wormhole_clean_th(map, 2);
}

  void
wormhole_destroy(struct wormhole * const map)
{
  wormhole_clean_free(map, 2);
  for (u64 x = 0; x < 2; x++)
    wormhole_hmap_deinit(&(map->hmap2[x]));
  qsbr_destroy(map->qsbr);
  slab_destroy(map->slab_leaf);
  free(map->pbuf);
  free(map);
}

  void
wormhole_fprint(struct wormhole * const map, FILE * const out)
{
  const u64 nr_slab_ul = slab_get_nalloc(map->slab_leaf);
  const u64 nr_slab_um1 = slab_get_nalloc(map->hmap2[0].slab);
  const u64 nr_slab_um2 = map->hmap2[1].slab ? slab_get_nalloc(map->hmap2[1].slab) : 0;
  fprintf(out, "%s L-SLAB %lu M-SLAB %lu %lu\n", __func__, nr_slab_ul, nr_slab_um1, nr_slab_um2);
}
// }}} misc

// api {{{
const struct kvmap_api kvmap_api_wormhole = {
  .hashkey = true,
  .ordered = true,
  .threadsafe = true,
  .unique = true,
  .refpark = true,
  .set = (void *)wormhole_set,
  .get = (void *)wormhole_get,
  .probe = (void *)wormhole_probe,
  .del = (void *)wormhole_del,
  .inpr = (void *)wormhole_inpr,
  .inpw = (void *)wormhole_inpw,
  .merge = (void *)wormhole_merge,
  .delr = (void *)wormhole_delr,
  .iter_create = (void *)wormhole_iter_create,
  .iter_seek = (void *)wormhole_iter_seek,
  .iter_valid = (void *)wormhole_iter_valid,
  .iter_peek = (void *)wormhole_iter_peek,
  .iter_kref = (void *)wormhole_iter_kref,
  .iter_kvref = (void *)wormhole_iter_kvref,
  .iter_skip = (void *)wormhole_iter_skip,
  .iter_next = (void *)wormhole_iter_next,
  .iter_inp = (void *)wormhole_iter_inp,
  .iter_park = (void *)wormhole_iter_park,
  .iter_destroy = (void *)wormhole_iter_destroy,
  .ref = (void *)wormhole_ref,
  .unref = (void *)wormhole_unref,
  .park = (void *)wormhole_park,
  .resume = (void *)wormhole_resume,
  .clean = (void *)wormhole_clean,
  .destroy = (void *)wormhole_destroy,
  .fprint = (void *)wormhole_fprint,
};

const struct kvmap_api kvmap_api_whsafe = {
  .hashkey = true,
  .ordered = true,
  .threadsafe = true,
  .unique = true,
  .set = (void *)whsafe_set,
  .get = (void *)whsafe_get,
  .probe = (void *)whsafe_probe,
  .del = (void *)whsafe_del,
  .inpr = (void *)whsafe_inpr,
  .inpw = (void *)whsafe_inpw,
  .merge = (void *)whsafe_merge,
  .delr = (void *)whsafe_delr,
  .iter_create = (void *)wormhole_iter_create,
  .iter_seek = (void *)whsafe_iter_seek,
  .iter_valid = (void *)wormhole_iter_valid,
  .iter_peek = (void *)wormhole_iter_peek,
  .iter_kref = (void *)wormhole_iter_kref,
  .iter_kvref = (void *)wormhole_iter_kvref,
  .iter_skip = (void *)wormhole_iter_skip,
  .iter_next = (void *)wormhole_iter_next,
  .iter_inp = (void *)wormhole_iter_inp,
  .iter_park = (void *)whsafe_iter_park,
  .iter_destroy = (void *)whsafe_iter_destroy,
  .ref = (void *)whsafe_ref,
  .unref = (void *)wormhole_unref,
  .clean = (void *)wormhole_clean,
  .destroy = (void *)wormhole_destroy,
  .fprint = (void *)wormhole_fprint,
};

const struct kvmap_api kvmap_api_whunsafe = {
  .hashkey = true,
  .ordered = true,
  .unique = true,
  .set = (void *)whunsafe_set,
  .get = (void *)whunsafe_get,
  .probe = (void *)whunsafe_probe,
  .del = (void *)whunsafe_del,
  .inpr = (void *)whunsafe_inp,
  .inpw = (void *)whunsafe_inp,
  .merge = (void *)whunsafe_merge,
  .delr = (void *)whunsafe_delr,
  .iter_create = (void *)whunsafe_iter_create,
  .iter_seek = (void *)whunsafe_iter_seek,
  .iter_valid = (void *)whunsafe_iter_valid,
  .iter_peek = (void *)wormhole_iter_peek,
  .iter_kref = (void *)wormhole_iter_kref,
  .iter_kvref = (void *)wormhole_iter_kvref,
  .iter_skip = (void *)whunsafe_iter_skip,
  .iter_next = (void *)whunsafe_iter_next,
  .iter_inp = (void *)whunsafe_iter_inp,
  .iter_destroy = (void *)whunsafe_iter_destroy,
  .clean = (void *)wormhole_clean,
  .destroy = (void *)wormhole_destroy,
  .fprint = (void *)wormhole_fprint,
};

  static void *
wormhole_kvmap_api_create(const char * const name, const struct kvmap_mm * const mm, char ** args)
{
  (void)args;
  if ((!strcmp(name, "wormhole")) || (!strcmp(name, "whsafe"))) {
    return wormhole_create(mm);
  } else if (!strcmp(name, "whunsafe")) {
    return whunsafe_create(mm);
  } else {
    return NULL;
  }
}

__attribute__((constructor))
  static void
wormhole_kvmap_api_init(void)
{
  kvmap_api_register(0, "wormhole", "", wormhole_kvmap_api_create, &kvmap_api_wormhole);
  kvmap_api_register(0, "whsafe", "", wormhole_kvmap_api_create, &kvmap_api_whsafe);
  kvmap_api_register(0, "whunsafe", "", wormhole_kvmap_api_create, &kvmap_api_whunsafe);
}
// }}} api

// debug {{{
#ifdef WORMHOLE_DEBUG
typedef void (*wormhole_check_meta_cb)(const struct wormmeta * const meta,
    struct kv * const pbuf, void * const priv);

  static void
wormhole_check_meta_cb_nr(const struct wormmeta * const meta,
    struct kv * const pbuf, void * const priv)
{
  (void)meta;
  (void)pbuf;
  (*(u64 *)priv)++;
}

  static void
wormhole_check_meta_cb_size(const struct wormmeta * const meta,
    struct kv * const pbuf, void * const priv)
{
  (void)pbuf;
  struct kv * const mkey = meta->keyref;
  const double mkey_share = ((double)key_size(mkey)) / (double)(mkey->refcnt);
  const double share = ((double)sizeof(struct wormmeta)) + mkey_share;
  (*(double *)priv) += share;
}

  static void
wormhole_check_meta_rec(struct wormhmap * const hmap, struct kv * const pbuf,
    wormhole_check_meta_cb cb, void * const priv)
{
  struct wormmeta * const meta = wormhole_hmap_get(hmap, pbuf);
  debug_assert(meta);
  cb(meta, pbuf, priv);

  if (meta->bitmin >= WH_FO)
    return;

  const u32 plen0 = pbuf->klen;
  const u32 plen1 = plen0 + 1;
  debug_assert(plen1 <= hmap->maxplen);
  for (u32 i = 0; i < WH_FO; i++) {
    if (wormhole_meta_bm_test(meta, i)) {
      pbuf->kv[plen0] = (u8)i;
      wormhole_prefix(pbuf, plen1);
      wormhole_check_meta_rec(hmap, pbuf, cb, priv);
    }
  }
}

// sizenr: true: size; false: nr
  static void
wormhole_check_meta(struct wormhmap * const hmap, wormhole_check_meta_cb cb, void * const priv)
{
  struct kv * const pbuf = wormhole_alloc_mkey(hmap->maxplen);
  debug_assert(pbuf);
  kv_dup2(kv_null(), pbuf);
  wormhole_check_meta_rec(hmap, pbuf, cb, priv);
  wormhole_free_mkey(pbuf);
}

  static u64
wormhole_count_leaf(struct wormhole * const map, const bool kv_node)
{
  u64 x = 0;
  for (struct wormleaf * l = map->leaf0; l; l = l->next) {
    if (kv_node) { // true: kv size
      for (u64 i = 0; i < WH_KPN; i++)
        if (l->eh[i].v64)
          x += kv_size(u64_to_ptr(l->eh[i].e3));
    } else { // false: node size (with anchor)
      x += sizeof(*l);
      x += key_size(l->anchor);
    }
  }
  return x;
}

  static void
wormhole_hmap_stat(struct wormhmap * const hmap, FILE * const out)
{
  // hmap stat
  const u64 n = hmap->mask + 1lu;
  u64 nu = 0;
  u64 c[WH_BKT_NR+1] = {};
  for (u64 i = 0; i < n; i++) {
    const struct wormmbkt * const slot = &(hmap->pmap[i]);
    u64 nb = 0;
    for (u64 j = 0; j < WH_BKT_NR; j++) {
      if (slot->e[j])
        nb++;
      else
        break;
    }
    c[nb]++;
    nu += nb;
  }
  fprintf(out, "MASK %08x SLOTS %lu 8x%lu CTR 0-8", hmap->mask, nu, n);
  fprintf(out, " %lu %lu %lu %lu %lu", c[0], c[1], c[2], c[3], c[4]);
  fprintf(out, " %lu %lu %lu %lu\n", c[5], c[6], c[7], c[8]);
}

  void
wormhole_fprint_verbose(struct wormhole * const map, FILE * const out)
{
  struct wormleaf * iter = map->leaf0;
  u64 nr_leaf = 0;
  u64 nr_keys = 0;
  u64 nr_sorted = 0;
  u64 acc_alen = 0;
  u32 max_alen = 0;
  while (iter) {
    nr_leaf++;
    nr_keys += iter->nr_keys;
    nr_sorted += iter->nr_sorted;
    const u32 len = iter->anchor->klen;
    acc_alen += len;
    if (len > max_alen)
      max_alen = len;
    iter = iter->next;
  }
  const double avg_alen = (double)acc_alen / (double)nr_leaf;
  fprintf(out, "WH MAXA %u AVGA %.2lf KEYS %lu SORTED %lu LEAF %lu ",
      max_alen, avg_alen, nr_keys, nr_sorted, nr_leaf);
  const bool hmap2 = map->hmap2[1].pmap != NULL;

  u64 nr_meta0 = 0;
  u64 nr_meta1 = 0;
  wormhole_check_meta(&(map->hmap2[0]), wormhole_check_meta_cb_nr, &nr_meta0);
  if (hmap2)
    wormhole_check_meta(&(map->hmap2[1]), wormhole_check_meta_cb_nr, &nr_meta1);
  const u64 nr_slab_ul = slab_get_nalloc(map->slab_leaf);
  const u64 nr_slab_um1 = slab_get_nalloc(map->hmap2[0].slab);
  const u64 nr_slab_um2 = hmap2 ? slab_get_nalloc(map->hmap2[1].slab) : 0;
  fprintf(out, "L-SLAB %lu META %lu %lu M-SLAB %lu %lu\n",
      nr_slab_ul, nr_meta0, nr_meta1, nr_slab_um1, nr_slab_um2);

  wormhole_hmap_stat(&(map->hmap2[0]), out);
  if (hmap2)
    wormhole_hmap_stat(&(map->hmap2[1]), out);

  double meta_size0 = 0;
  double meta_size1 = 0;
  wormhole_check_meta(&(map->hmap2[0]), wormhole_check_meta_cb_size, &meta_size0);
  if (hmap2)
    wormhole_check_meta(&(map->hmap2[1]), wormhole_check_meta_cb_size, &meta_size1);
  const u64 meta_size = (u64)(meta_size0 + meta_size1);
  const u64 hash_size = map->hmap2[0].msize + map->hmap2[1].msize;
  const u64 leaf_size = wormhole_count_leaf(map, false);
  const u64 data_size = wormhole_count_leaf(map, true);
  const u64 full_size = meta_size + leaf_size + data_size + hash_size;
  const double pmeta = ((double)meta_size) * 100.0 / ((double)full_size);
  const double phash = ((double)hash_size) * 100.0 / ((double)full_size);
  const double pleaf = ((double)leaf_size) * 100.0 / ((double)full_size);
  const double pdata = ((double)data_size) * 100.0 / ((double)full_size);
  fprintf(out, "METANODEx2 %'lu %5.2lf%% HTx2 %'lu %5.2lf%% ",
      meta_size, pmeta, hash_size, phash);
  fprintf(out, "LEAFNODE %'lu %5.2lf%% DATA %'lu %5.2lf%% ",
      leaf_size, pleaf, data_size, pdata);
  fprintf(out, "MB ALL %lu D %lu L %lu Mx2 %lu Hx2 %lu\n",
      full_size >> 20, data_size >> 20, leaf_size >> 20, meta_size >> 20, hash_size >> 20);
}

  static void
wormhole_dump_line(FILE * const out, const void * const ptr, const u64 size, const char * const tag)
{
  // L1 32-KB 8-way 64-group
  // L2 256-KB 8-way 512-group
  const u64 v64 = (u64)ptr;
  const u64 lsize = bits_round_up(size, 6);
  const u64 lines = lsize / 64;
  const u64 psize = bits_round_up(size, 12);
  const u64 pages = psize / PGSZ;
  const u64 l1 = (v64 >> 6) % 64;
  const u64 l2 = (v64 >> 6) % 512;
  fprintf(out, "%8s PTR %p size %lu pages %lu lines %lu L1group %lu L2group %lu\n",
      tag, ptr, size, pages, lines, l1, l2);
}

// opt: m: meta-nodes, l:leaf, a:anchors, k:keys
  void
wormhole_dump_memory(struct wormhole * const map, const char * const filename,
    const char * const opt)
{
  FILE * const out = fopen(filename, "w");
  if (out == NULL)
    return;
  fprintf(out, "L1  32-kB 8-way  64-group\n");
  fprintf(out, "L2 256-kB 8-way 512-group\n");
  wormhole_dump_line(out, map, sizeof(*map), "wormhole");

  // hmap x2
  wormhole_dump_line(out, map->hmap2[0].pmap, map->hmap2[0].msize, "pmap0");
  if (map->hmap2[1].pmap)
    wormhole_dump_line(out, map->hmap2[1].pmap, map->hmap2[1].msize, "pmap1");

  // meta
  const bool dumpmeta = strchr(opt, 'm') != NULL;
  if (dumpmeta) {
    for (u64 x = 0; x < 2; x++) {
      if (map->hmap2[x].pmap == NULL)
        continue;
      const u64 nr_slots = ((u64)(map->hmap2[x].mask)) + 1;
      for (u64 s = 0; s < nr_slots; s++) {
        struct wormmbkt * const slot = &(map->hmap2[x].pmap[s]);
        for (u64 i = 0; i < WH_BKT_NR; i++) {
          if (slot->e[i] == NULL)
            continue;
          struct wormmeta * const meta = slot->e[i];
          wormhole_dump_line(out, meta, sizeof(*meta), "metanode");
          wormhole_dump_line(out, meta->keyref, key_size(meta->keyref), "metakey");
        }
      }
    }
  }

  const bool dumpleaf = strchr(opt, 'l') != NULL;
  const bool dumpanchor = strchr(opt, 'a') != NULL;
  const bool dumpkeys = strchr(opt, 'k') != NULL;
  // leaf list
  struct wormleaf * iter = map->leaf0;
  while (iter) {
    if (dumpleaf)
      wormhole_dump_line(out, iter, sizeof(*iter), "leafnode");
    if (dumpanchor)
      wormhole_dump_line(out, iter->anchor, kv_size(iter->anchor), "anchor");
    if (dumpkeys) {
      for (u64 i = 0; i < WH_KPN; i++) {
        if (iter->eh[i].v64) {
          struct kv * const kv = u64_to_ptr(iter->eh[i].e3);
          wormhole_dump_line(out, kv, kv_size(kv), "kvitem");
        }
      }
    }
    iter = iter->next;
  }
  fclose(out);
}

  static void
verify_print_twokeys(const char * const note, const struct kv * const key1,
    const struct kv * const key2)
{
  fprintf(stderr, "%s\n", note);
  kv_print(key1, "sn", stderr);
  kv_print(key2, "sn", stderr);
}

  static void
wormhole_verify_leaf_data(struct wormleaf * const leaf)
{
  struct entry13 hvs[WH_KPN];
  struct entry13 svs[WH_KPN];
  u64 nh = 0;
  for (u64 i = 0; i < WH_KPN; i++) {
    if (leaf->eh[i].v64) {
      hvs[nh] = leaf->eh[i];
      nh++;
    }
  }
  if (nh != leaf->nr_keys)
    debug_die();
  qsort_u64((u64 *)hvs, nh);
  memcpy(svs, leaf->es, sizeof(svs[0]) * nh);
  qsort_u64((u64 *)svs, nh);
  if (memcmp(hvs, svs, sizeof(svs[0]) * nh))
    debug_die();
  for (u64 i = 0; i < nh; i++) {
    const struct entry13 e = hvs[i];
    struct kv * const kv = u64_to_ptr(e.e3);
    debug_assert(kv->klen); // debugging
    const u64 hash = kv_crc32c_extend(kv_crc32c(kv->kv, kv->klen));
    if (hash != kv->hash)
      debug_die();
    const u16 pkey = wormhole_pkey(kv->hashlo);
    if (pkey != e.e1)
      debug_die();
  }
}

  static void
wormhole_verify_leaf_order(struct wormleaf * const leaf)
{
  struct kv * const anchor = leaf->anchor;
  if (anchor == NULL) {
    fprintf(stderr, "LEAF %p has no anchor\n", leaf);
    return;
  }

  // hash-sorted
  u64 i0 = WH_KPN;
  u64 nreh = 0;
  for (u64 i = 0; i < WH_KPN; i++) {
    if (leaf->eh[i].v64 == 0)
      continue;
    if (i0 < WH_KPN) {
      if (leaf->eh[i].e1 < leaf->eh[i0].e1) {
        struct kv * const l = u64_to_ptr(leaf->eh[i0].e3);
        struct kv * const r = u64_to_ptr(leaf->eh[i].e3);
        verify_print_twokeys("EH [KEY-LEFT.e1 > KEY-RIGHT.e1]", l, r);
        return;
      }
    }
    i0 = i;
    nreh++;
  }
  if (nreh != leaf->nr_keys) {
    printf("NR_KEYS %lu %lu\n", nreh, leaf->nr_keys);
    return;
  }

  // sorted with no duplicate keys
  for (u64 i = 1; i < leaf->nr_sorted; i++) {
    struct kv * const l = u64_to_ptr(leaf->es[i-1].e3);
    struct kv * const r = u64_to_ptr(leaf->es[i].e3);
    const int cmp = kv_compare(l, r);
    if (cmp >= 0) {
      verify_print_twokeys("ES [KEY-LEFT >= KEY-RIGHT]", l, r);
      return;
    }
  }

  // other keys >= anchor
  for (u64 i = 0; i < WH_KPN; i++) {
    if (leaf->eh[i].v64 == 0)
      continue;
    struct kv * const k = u64_to_ptr(leaf->eh[i].e3);
    const int cmp = kv_compare(k, anchor);
    if (cmp < 0) {
      verify_print_twokeys("ANCHOR > KEY-RIGHT]", anchor, k);
      return;
    }
  }

  // keys < next-anchor
  if (leaf->prev) {
    struct wormleaf * const prev = leaf->prev;
    for (u64 i = 0; i < WH_KPN; i++) {
      if (prev->eh[i].v64 == 0)
        continue;
      struct kv * const k = u64_to_ptr(prev->eh[i].e3);
      const int cmp = kv_compare(k, anchor);
      if (cmp >= 0) {
        verify_print_twokeys("LEFT-KEY >= ANCHOR", k, anchor);
        return;
      }
    }
  }
}

  static u64
wormhole_verify_leaf_chain(struct wormhole * const map)
{
  u64 leafcount = 0;
  for (struct wormleaf * l = map->leaf0; l; l = l->next) {
    wormhole_verify_leaf_data(l);
    wormhole_verify_leaf_order(l);
    leafcount++;
  }
  return leafcount;
}

  static u64
wormhole_verify_meta_tree(struct wormhmap * const hmap, struct kv * const pbuf)
{
  // test if node at pbuf can be found
  struct wormmeta * const meta = wormhole_hmap_get(hmap, pbuf);
  if (meta == NULL) {
    fprintf(stderr, "NODE NOT FOUND ");
    kv_print(pbuf, "sn", stderr);
    return 0;
  }
  // test maxplen
  if (pbuf->klen > hmap->maxplen) {
    fprintf(stderr, "MAXPLEN too small ");
    kv_print(pbuf, "sn", stderr);
  }

  // tail
  if (meta->bitmin == WH_FO)
    return 1;

  const u32 plen0 = pbuf->klen;
  const u32 plen1 = plen0 + 1;
  u64 count = 0;
  for (u32 i = 0; i < WH_FO; i++) {
    if (wormhole_meta_bm_test(meta, i)) {
      pbuf->kv[plen0] = (u8)i;
      wormhole_prefix(pbuf, plen1);
      count += wormhole_verify_meta_tree(hmap, pbuf);
    }
  }
  return count;
}

  bool
wormhole_verify(struct wormhole * const map)
{
  const u64 c1 = wormhole_verify_leaf_chain(map);
  struct kv * const pbuf = wormhole_alloc_mkey(map->hmap2[0].maxplen + 8);
  debug_assert(pbuf);
  kv_dup2(kv_null(), pbuf);
  const u64 c2 = wormhole_verify_meta_tree(&(map->hmap2[0]), pbuf);
  kv_dup2(kv_null(), pbuf);
  const u64 c3 = wormhole_verify_meta_tree(&(map->hmap2[1]), pbuf);
  fprintf(stderr, "LEAF leafcount %lu META leafcount %lu %lu\n", c1, c2, c3);
  wormhole_free_mkey(pbuf);
  return (c1 == c2) && (c2 == c3);
}

// merge may fail if can't acquire lock before timeout
  bool
wormhole_merge_at(struct wormref * const ref, const struct kref * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_write(ref, key);
  if ((leaf->next == NULL) || ((leaf->nr_keys + leaf->next->nr_keys) > WH_KPN)) {
    rwlock_unlock_write(&(leaf->leaflock));
    return false;
  }
  return wormhole_merge_meta_leaf_ref(ref, leaf);
}

  bool
wormhole_split_at(struct wormref * const ref, const struct kref * const key)
{
  struct wormleaf * const leaf1 = wormhole_jump_leaf_write(ref, key);
  wormhole_leaf_sync_sorted(leaf1);
  const u64 cut = wormhole_leaf_bisect_sorted(leaf1, key);
  if ((cut < leaf1->nr_keys) && kref_kv_match(key, u64_to_ptr(leaf1->es[cut].e3))
      && wormhole_split_cut_alen(leaf1, cut-1, cut)) {
    struct wormleaf * const leaf2 = wormhole_split_leaf(ref->map, leaf1, cut);
    if (leaf2) {
      rwlock_lock_write(&(leaf2->leaflock));
      wormhole_split_meta_ref(ref, leaf2, true);
      return true;
    }
  }
  rwlock_unlock_write(&(leaf1->leaflock));
  return false;
}

  void
wormhole_sync_at(struct wormref * const ref, const struct kref * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_read(ref, key);
  wormhole_iter_leaf_sync_sorted(leaf);
  rwlock_unlock_read(&(leaf->leaflock));
}

  static void
wormhole_print_meta_anchors_rec(struct wormhmap * const hmap, const char * const pattern,
    struct kv * const pbuf)
{
  struct wormmeta * const meta = wormhole_hmap_get(hmap, pbuf);
  debug_assert(meta);

  // print leaf nodes only
  if (meta->bitmin == WH_FO) {
    fprintf(stdout, "%p ", meta);
    kv_print(pbuf, pattern, stdout);
  }

  const u32 plen0 = pbuf->klen;
  for (u32 i = 0; i < WH_FO; i++) {
    if (wormhole_meta_bm_test(meta, i)) {
      pbuf->kv[plen0] = (u8)i;
      wormhole_prefix(pbuf, plen0 + 1);
      wormhole_print_meta_anchors_rec(hmap, pattern, pbuf);
    }
  }
}

  void
wormhole_print_meta_anchors(struct wormhole * const map, const char * const pattern)
{
  printf("== %s ==\n", __func__);
  struct wormhmap * const hmap = whunsafe_hmap_load(map);
  struct kv * const pbuf = wormhole_alloc_mkey(hmap->maxplen + 8);
  debug_assert(pbuf);
  kv_dup2(kv_null(), pbuf);
  wormhole_print_meta_anchors_rec(hmap, pattern, pbuf);
  wormhole_free_mkey(pbuf);
}

  void
wormhole_print_leaf_anchors(struct wormhole * const map, const char * const pattern)
{
  printf("== %s ==\n", __func__);
  const struct wormleaf * leaf = map->leaf0;
  while (leaf) {
    fprintf(stdout, "%p ", leaf);
    kv_print(leaf->anchor, pattern, stdout);
    leaf = leaf->next;
  }
}

  static void
wormhole_print_meta_lrmost_rec(struct wormhmap * const hmap, const char * const pattern,
    struct kv * const pbuf)
{
  struct wormmeta * const meta = wormhole_hmap_get(hmap, pbuf);
  debug_assert(meta);

  fprintf(stdout, TERMCLR(34) "M:");
  kv_print(pbuf, pattern, stdout);
  fprintf(stdout, TERMCLR(32) "L:");
  kv_print(meta->lmost->anchor, pattern, stdout);
  fprintf(stdout, TERMCLR(35) "R:");
  kv_print(meta->rmost->anchor, pattern, stdout);
  fprintf(stdout, TERMCLR(0));

  const u32 plen0 = pbuf->klen;
  for (u32 i = 0; i < WH_FO; i++) {
    if (wormhole_meta_bm_test(meta, i)) {
      pbuf->kv[plen0] = (u8)i;
      wormhole_prefix(pbuf, plen0 + 1);
      wormhole_print_meta_lrmost_rec(hmap, pattern, pbuf);
    }
  }
}

  void
wormhole_print_meta_lrmost(struct wormhole * const map, const char * const pattern)
{
  printf("== %s ==\n", __func__);
  struct wormhmap * const hmap = whunsafe_hmap_load(map);
  struct kv * const pbuf = wormhole_alloc_mkey(hmap->maxplen + 8);
  debug_assert(pbuf);
  kv_dup2(kv_null(), pbuf);
  wormhole_print_meta_lrmost_rec(hmap, pattern, pbuf);
  wormhole_free_mkey(pbuf);
}

  void *
wormhole_jump_leaf_only(struct wormhole * const map, const struct kref * const key)
{
  struct wormhmap * const hmap = whunsafe_hmap_load(map);
  return wormhole_jump_leaf(hmap, key);
}
#endif // WORMHOLE_DEBUG
// }}} debug

// wh {{{
// Users often don't enjoy dealing with struct kv/kref and just want to use plain buffers.
// No problem!
// This example library shows you how to use Wormhole efficiently in the most intuitive way.

// Use the worry-free api
static const struct kvmap_api * const wh_api = &kvmap_api_whsafe;

// You can change the wh_api to kvmap_api_wormhole with a one-line replacement
// The standard Wormhole api can give you ~5% boost; read README for thread-safety tips
//static const struct kvmap_api * const wh_api = &kvmap_api_wormhole;

  struct wormhole *
wh_create(void)
{
  // kvmap_mm_ndf (kv.h) will let the caller allocate the kv when inserting
  // This can avoid a memcpy if the caller does not have the data in a struct kv
  return wormhole_create(&kvmap_mm_ndf);
}

  struct wormref *
wh_ref(struct wormhole * const wh)
{
  return wh_api->ref(wh);
}

  void
wh_unref(struct wormref * const ref)
{
  (void)wh_api->unref(ref);
}

  void
wh_park(struct wormref * const ref)
{
  if (wh_api->park)
    wh_api->park(ref);
}

  void
wh_resume(struct wormref * const ref)
{
  if (wh_api->resume)
    wh_api->resume(ref);
}

  void
wh_clean(struct wormhole * const map)
{
  wh_api->clean(map);
}

  void
wh_destroy(struct wormhole * const map)
{
  wh_api->destroy(map);
}

// Do set/put with explicit kv buffers
  bool
wh_set(struct wormref * const ref, const void * const kbuf, const u32 klen,
    const void * const vbuf, const u32 vlen)
{
  struct kv * const newkv = kv_create(kbuf, klen, vbuf, vlen);
  // must use with kvmap_mm_ndf (see below)
  // the newkv will be saved in the Wormhole and freed by Wormhole when upon deletion
  return wh_api->set(ref, newkv);
}

// delete a key
  bool
wh_del(struct wormref * const ref, const void * const kbuf, const u32 klen)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);
  return wh_api->del(ref, &kref);
}

// test if the key exist in Wormhole
  bool
wh_probe(struct wormref * const ref, const void * const kbuf, const u32 klen)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);
  return wh_api->probe(ref, &kref);
}

// for wh_get()
struct wh_inp_info { void * vbuf_out; u32 * vlen_out; };

// a kv_inp_func; use this to retrieve the KV's data without unnecesary memory copying
  static void
wh_inp_copy_value(struct kv * const curr, void * const priv)
{
  if (curr) { // found
    struct wh_inp_info * const info = (typeof(info))priv;
    // copy the value data out
    memcpy(info->vbuf_out, kv_vptr_c(curr), curr->vlen);
    // copy the vlen out
    *info->vlen_out = curr->vlen;
  }
}

// returns a boolean value indicating whether the key is found.
// the value's data will be written to *vlen_out and vbuf_out if the key is found
// We assume vbuf_out is large enough to hold the output value
  bool
wh_get(struct wormref * const ref, const void * const kbuf, const u32 klen,
    void * const vbuf_out, u32 * const vlen_out)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);
  struct wh_inp_info info = {vbuf_out, vlen_out};
  // use the inplace read function to get the value if it exists
  return wh_api->inpr(ref, &kref, wh_inp_copy_value, &info);
}

  bool
wh_inpr(struct wormref * const ref, const void * const kbuf, const u32 klen,
    kv_inp_func uf, void * const priv)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);
  return wh_api->inpr(ref, &kref, uf, priv);
}

// inplace update KV's value with a user-defined hook function
// the update should only modify the data in the value; It should not change the value size
  bool
wh_inpw(struct wormref * const ref, const void * const kbuf, const u32 klen,
    kv_inp_func uf, void * const priv)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);
  return wh_api->inpw(ref, &kref, uf, priv);
}

// merge existing KV with updates with a user-defined hook function
  bool
wh_merge(struct wormref * const ref, const void * const kbuf, const u32 klen,
    kv_merge_func uf, void * const priv)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);
  return wh_api->merge(ref, &kref, uf, priv);
}

// remove a range of KVs from start (inclusive) to end (exclusive); [start, end)
  u64
wh_delr(struct wormref * const ref, const void * const kbuf_start, const u32 klen_start,
    const void * const kbuf_end, const u32 klen_end)
{
  struct kref kref_start, kref_end;
  kref_ref_hash32(&kref_start, kbuf_start, klen_start);
  kref_ref_hash32(&kref_end, kbuf_end, klen_end);
  return wh_api->delr(ref, &kref_start, &kref_end);
}

  struct wormhole_iter *
wh_iter_create(struct wormref * const ref)
{
  return wh_api->iter_create(ref);
}

  void
wh_iter_seek(struct wormhole_iter * const iter, const void * const kbuf, const u32 klen)
{
  struct kref kref;
  kref_ref_hash32(&kref, kbuf, klen);
  wh_api->iter_seek(iter, &kref);
}

  bool
wh_iter_valid(struct wormhole_iter * const iter)
{
  return wh_api->iter_valid(iter);
}

// for wh_iter_peek()
// the out ptrs must be provided in pairs; use a pair of NULLs to ignore the key or value
struct wh_iter_inp_info { void * kbuf_out; u32 * klen_out; void * vbuf_out; u32 * vlen_out; };

// a kv_inp_func; use this to retrieve the KV's data without unnecesary memory copying
  static void
inp_copy_kv_cb(struct kv * const curr, void * const priv)
{
  if (curr) { // found
    struct wh_iter_inp_info * const info = (typeof(info))priv;

    // copy the key
    if (info->kbuf_out) { // it assumes klen_out is also not NULL
      // copy the key data out
      memcpy(info->kbuf_out, kv_kptr_c(curr), curr->klen);
      // copy the klen out
      *info->klen_out = curr->klen;
    }

    // copy the value
    if (info->vbuf_out) { // it assumes vlen_out is also not NULL
      // copy the value data out
      memcpy(info->vbuf_out, kv_vptr_c(curr), curr->vlen);
      // copy the vlen out
      *info->vlen_out = curr->vlen;
    }
  }
}

// seek is similar to get
  bool
wh_iter_peek(struct wormhole_iter * const iter,
    void * const kbuf_out, u32 * const klen_out,
    void * const vbuf_out, u32 * const vlen_out)
{
  struct wh_iter_inp_info info = {kbuf_out, klen_out, vbuf_out, vlen_out};
  return wh_api->iter_inp(iter, inp_copy_kv_cb, &info);
}

  void
wh_iter_skip(struct wormhole_iter * const iter, const u32 nr)
{
  wh_api->iter_skip(iter, nr);
}

  bool
wh_iter_inp(struct wormhole_iter * const iter, kv_inp_func uf, void * const priv)
{
  return wh_api->iter_inp(iter, uf, priv);
}

  void
wh_iter_park(struct wormhole_iter * const iter)
{
  wh_api->iter_park(iter);
}

  void
wh_iter_destroy(struct wormhole_iter * const iter)
{
  wh_api->iter_destroy(iter);
}
// }}} wh

// vim:fdm=marker
