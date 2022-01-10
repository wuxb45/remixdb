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
#define WH_HMAPINIT_SIZE ((1u << 12)) // 10: 16KB/64KB  12: 64KB/256KB  14: 256KB/1MB
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
#define WH_KPN2 ((WH_KPN + WH_KPN))

#define WH_KPN_MRG (((WH_KPN + WH_MID) >> 1 )) // 3/4

// FO is fixed at 256. Don't change it
#define WH_FO  ((256u)) // index fan-out
// number of bits in a bitmap
#define WH_BMNR ((WH_FO >> 6)) // number of u64
// }}} def

// struct {{{
struct wormmeta {
  struct entry13 k13; // kref+klen
  struct entry13 l13; // lmost+bitmin+bitmax
  struct entry13 r13; // rmost+hash32_lo
  struct entry13 p13; // lpath+hash32_hi
  u64 bitmap[0]; // 4 if bitmin != bitmax
};
static_assert(sizeof(struct wormmeta) == 32, "sizeof(wormmeta) != 32");

struct wormkv64 { u64 key; void * ptr; }; // u64 keys (whu64)

struct wormleaf {
  // first line
  rwlock leaflock;
  spinlock sortlock; // to protect the seemingly "read-only" iter_seek
  au64 lv; // version (dont use the first u64)
  struct wormleaf * prev; // prev leaf
  struct wormleaf * next; // next leaf
  struct kv * anchor;

  u32 nr_sorted;
  u32 nr_keys;
  u64 reserved[2];

  struct entry13 hs[WH_KPN]; // sorted by hashes
  u8 ss[WH_KPN]; // sorted by keys
};

struct wormslot { u16 t[WH_BKT_NR]; };
static_assert(sizeof(struct wormslot) == 16, "sizeof(wormslot) != 16");

struct wormmbkt { struct wormmeta * e[WH_BKT_NR]; };
static_assert(sizeof(struct wormmbkt) == 64, "sizeof(wormmbkt) != 64");

struct wormhmap {
  au64 hv;
  struct wormslot * wmap;
  struct wormmbkt * pmap;
  u32 mask;
  u32 maxplen;
  u64 msize;

  struct slab * slab1;
  struct slab * slab2;
  struct kv * pbuf;
};
static_assert(sizeof(struct wormhmap) == 64, "sizeof(wormhmap) != 64");

struct wormhole {
  // 1 line
  union {
    volatile au64 hmap_ptr; // safe
    struct wormhmap * hmap; // unsafe
  };
  u64 padding0[6];
  struct wormleaf * leaf0; // usually not used
  // 1 line
  struct kvmap_mm mm;
  struct qsbr * qsbr;
  struct slab * slab_leaf;
  struct kv * pbuf;
  u32 leaftype;
  u32 padding1;
  // 2 lines
  struct wormhmap hmap2[2];
  // fifth line
  rwlock metalock;
  u32 padding2[15];
};

struct wormhole_iter {
  struct wormref * ref; // safe-iter only
  struct wormhole * map;
  struct wormleaf * leaf;
  u32 is;
};

struct wormref {
  struct wormhole * map;
  struct qsbr_ref qref;
};
// }}} struct

// helpers {{{

// meta {{{
  static inline struct kv *
wormmeta_keyref_load(const struct wormmeta * const meta)
{
  return u64_to_ptr(meta->k13.e3);
}

  static inline u16
wormmeta_klen_load(const struct wormmeta * const meta)
{
  return meta->k13.e1;
}

  static inline struct wormleaf *
wormmeta_lmost_load(const struct wormmeta * const meta)
{
  return u64_to_ptr(meta->l13.e3 & (~0x3flu));
}

  static inline u32
wormmeta_bitmin_load(const struct wormmeta * const meta)
{
  return (u32)(meta->l13.v64 & 0x1fflu);
}

  static inline u32
wormmeta_bitmax_load(const struct wormmeta * const meta)
{
  return (u32)((meta->l13.v64 >> 9) & 0x1fflu);
}

  static inline u32
wormmeta_hash32_load(const struct wormmeta * const meta)
{
  return ((u32)meta->r13.e1) | (((u32)meta->p13.e1) << 16);
}

  static inline struct wormleaf *
wormmeta_rmost_load(const struct wormmeta * const meta)
{
  return u64_to_ptr(meta->r13.e3);
}

  static inline struct wormleaf *
wormmeta_lpath_load(const struct wormmeta * const meta)
{
  return u64_to_ptr(meta->p13.e3);
}

// internal
  static inline void
wormmeta_lpath_store(struct wormmeta * const meta, struct wormleaf * const leaf)
{
  entry13_update_e3(&meta->p13, ptr_to_u64(leaf));
}

// also updates leaf_klen_eq and
  static inline void
wormmeta_lmost_store(struct wormmeta * const meta, struct wormleaf * const leaf)
{
  const u64 minmax = meta->l13.v64 & 0x3fffflu;
  meta->l13.v64 = (((u64)leaf) << 16) | minmax;

  const bool leaf_klen_eq = leaf->anchor->klen == wormmeta_klen_load(meta);
  wormmeta_lpath_store(meta, leaf_klen_eq ? leaf : leaf->prev);
}

  static inline void
wormmeta_bitmin_store(struct wormmeta * const meta, const u32 bitmin)
{
  meta->l13.v64 = (meta->l13.v64 & (~0x1fflu)) | bitmin;
}

  static inline void
wormmeta_bitmax_store(struct wormmeta * const meta, const u32 bitmax)
{
  meta->l13.v64 = (meta->l13.v64 & (~0x3fe00lu)) | (bitmax << 9);
}

  static inline void
wormmeta_rmost_store(struct wormmeta * const meta, struct wormleaf * const leaf)
{
  entry13_update_e3(&meta->r13, ptr_to_u64(leaf));
}

// for wormmeta_alloc
  static void
wormmeta_init(struct wormmeta * const meta, struct wormleaf * const lrmost,
    struct kv * const keyref, const u32 alen, const u32 bit)
{
  keyref->refcnt++; // shared

  const u32 plen = keyref->klen;
  debug_assert(plen <= UINT16_MAX);
  meta->k13 = entry13((u16)plen, ptr_to_u64(keyref));
  meta->l13.v64 = (ptr_to_u64(lrmost) << 16) | (bit << 9) | bit;

  const u32 hash32 = keyref->hashlo;
  meta->r13 = entry13((u16)hash32, ptr_to_u64(lrmost));

  const bool leaf_klen_eq = alen == plen;
  meta->p13 = entry13((u16)(hash32 >> 16), ptr_to_u64(leaf_klen_eq ? lrmost : lrmost->prev));
}
// }}} meta

// meta-bitmap {{{
  static inline bool
wormmeta_bm_test(const struct wormmeta * const meta, const u32 id)
{
  debug_assert(id < WH_FO);
  const u32 bitmin = wormmeta_bitmin_load(meta);
  const u32 bitmax = wormmeta_bitmax_load(meta);
  if (bitmin == bitmax) { // half node
    return bitmin == id;
  } else { // full node
    return (bool)((meta->bitmap[id >> 6u] >> (id & 0x3fu)) & 1lu);
  }
}

// meta must be a full node
  static void
wormmeta_bm_set(struct wormmeta * const meta, const u32 id)
{
  // need to replace meta
  u64 * const ptr = &(meta->bitmap[id >> 6u]);
  const u64 bit = 1lu << (id & 0x3fu);
  if ((*ptr) & bit)
    return;

  (*ptr) |= bit;

  // min
  if (id < wormmeta_bitmin_load(meta))
    wormmeta_bitmin_store(meta, id);

  // max
  const u32 oldmax = wormmeta_bitmax_load(meta);
  if (oldmax == WH_FO || id > oldmax)
    wormmeta_bitmax_store(meta, id);
}

// find the lowest bit > id0
// return WH_FO if not found
  static inline u32
wormmeta_bm_gt(const struct wormmeta * const meta, const u32 id0)
{
  u32 ix = id0 >> 6;
  u64 bits = meta->bitmap[ix] & ~((1lu << (id0 & 0x3fu)) - 1lu);
  if (bits)
    return (ix << 6) + (u32)__builtin_ctzl(bits);

  while (++ix < WH_BMNR) {
    bits = meta->bitmap[ix];
    if (bits)
      return (ix << 6) + (u32)__builtin_ctzl(bits);
  }

  return WH_FO;
}

// find the highest bit that is lower than the id0
// return WH_FO if not found
  static inline u32
wormmeta_bm_lt(const struct wormmeta * const meta, const u32 id0)
{
  u32 ix = id0 >> 6;
  u64 bits = meta->bitmap[ix] & ((1lu << (id0 & 0x3fu)) - 1lu);
  if (bits)
    return (ix << 6) + 63u - (u32)__builtin_clzl(bits);

  while (ix--) {
    bits = meta->bitmap[ix];
    if (bits)
      return (ix << 6) + 63u - (u32)__builtin_clzl(bits);
  }

  return WH_FO;
}

// meta must be a full node
  static inline void
wormmeta_bm_clear(struct wormmeta * const meta, const u32 id)
{
  debug_assert(wormmeta_bitmin_load(meta) < wormmeta_bitmax_load(meta));
  meta->bitmap[id >> 6u] &= (~(1lu << (id & 0x3fu)));

  // min
  if (id == wormmeta_bitmin_load(meta))
    wormmeta_bitmin_store(meta, wormmeta_bm_gt(meta, id));

  // max
  if (id == wormmeta_bitmax_load(meta))
    wormmeta_bitmax_store(meta, wormmeta_bm_lt(meta, id));
}
// }}} meta-bitmap

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
  return (key->klen == wormmeta_klen_load(meta))
    && (!memcmp(key->kv, wormmeta_keyref_load(meta)->kv, key->klen));
}

// called by get_kref_slot
  static inline bool
wormhole_kref_meta_match(const struct kref * const kref,
    const struct wormmeta * const meta)
{
  return (kref->len == wormmeta_klen_load(meta))
    && (!memcmp(kref->ptr, wormmeta_keyref_load(meta)->kv, kref->len));
}

// called from meta_down ... get_kref1_slot
// will access rmost, prefetching is effective here
  static inline bool
wormhole_kref1_meta_match(const struct kref * const kref,
    const struct wormmeta * const meta, const u8 cid)
{
  const u8 * const keybuf = wormmeta_keyref_load(meta)->kv;
  const u32 plen = kref->len;
  return ((plen + 1) == wormmeta_klen_load(meta))
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

  static inline void
wormhole_free_mkey(struct kv * const mkey)
{
  free(mkey);
}

  static struct wormleaf *
wormleaf_alloc(struct wormhole * const map, struct wormleaf * const prev,
    struct wormleaf * const next, struct kv * const anchor)
{
  struct wormleaf * const leaf = slab_alloc_safe(map->slab_leaf);
  if (leaf == NULL)
    return NULL;

  rwlock_init(&(leaf->leaflock));
  spinlock_init(&(leaf->sortlock));

  // keep the old version; new version will be assigned by split functions
  //leaf->lv = 0;

  leaf->prev = prev;
  leaf->next = next;
  leaf->anchor = anchor;

  leaf->nr_keys = 0;
  leaf->nr_sorted = 0;

  // hs requires zero init.
  memset(leaf->hs, 0, sizeof(leaf->hs[0]) * WH_KPN);
  return leaf;
}

  static void
wormleaf_free(struct slab * const slab, struct wormleaf * const leaf)
{
  debug_assert(leaf->leaflock.opaque == 0);
  wormhole_free_akey(leaf->anchor);
  slab_free_safe(slab, leaf);
}

  static struct wormmeta *
wormmeta_alloc(struct wormhmap * const hmap, struct wormleaf * const lrmost,
    struct kv * const keyref, const u32 alen, const u32 bit)
{
  debug_assert(alen <= UINT16_MAX);
  debug_assert(lrmost && keyref);

  struct wormmeta * const meta = slab_alloc_unsafe(hmap->slab1);
  if (meta == NULL)
    return NULL;

  wormmeta_init(meta, lrmost, keyref, alen, bit);
  return meta;
}

  static inline bool
wormhole_slab_reserve(struct wormhole * const map, const u32 nr)
{
#ifdef ALLOCFAIL
  if (alloc_fail())
    return false;
#endif
  for (u32 i = 0; i < 2; i++) {
    if (!(map->hmap2[i].slab1 && map->hmap2[i].slab2))
      continue;
    if (!slab_reserve_unsafe(map->hmap2[i].slab1, nr))
      return false;
    if (!slab_reserve_unsafe(map->hmap2[i].slab2, nr))
      return false;
  }
  return true;
}

  static void
wormmeta_keyref_release(struct wormmeta * const meta)
{
  struct kv * const keyref = wormmeta_keyref_load(meta);
  debug_assert(keyref->refcnt);
  keyref->refcnt--;
  if (keyref->refcnt == 0)
    wormhole_free_mkey(keyref);
}

  static void
wormmeta_free(struct wormhmap * const hmap, struct wormmeta * const meta)
{
  wormmeta_keyref_release(meta);
  slab_free_unsafe(hmap->slab1, meta);
}
// }}} alloc

// lock {{{
  static void
wormleaf_lock_write(struct wormleaf * const leaf, struct wormref * const ref)
{
  if (!rwlock_trylock_write(&(leaf->leaflock))) {
    wormhole_park(ref);
    rwlock_lock_write(&(leaf->leaflock));
    wormhole_resume(ref);
  }
}

  static void
wormleaf_lock_read(struct wormleaf * const leaf, struct wormref * const ref)
{
  if (!rwlock_trylock_read(&(leaf->leaflock))) {
    wormhole_park(ref);
    rwlock_lock_read(&(leaf->leaflock));
    wormhole_resume(ref);
  }
}

  static void
wormleaf_unlock_write(struct wormleaf * const leaf)
{
  rwlock_unlock_write(&(leaf->leaflock));
}

  static void
wormleaf_unlock_read(struct wormleaf * const leaf)
{
  rwlock_unlock_read(&(leaf->leaflock));
}

  static void
wormhmap_lock(struct wormhole * const map, struct wormref * const ref)
{
  if (!rwlock_trylock_write(&(map->metalock))) {
    wormhole_park(ref);
    rwlock_lock_write(&(map->metalock));
    wormhole_resume(ref);
  }
}

  static inline void
wormhmap_unlock(struct wormhole * const map)
{
  rwlock_unlock_write(&(map->metalock));
}
// }}} lock

// hmap-version {{{
  static inline struct wormhmap *
wormhmap_switch(struct wormhole * const map, struct wormhmap * const hmap)
{
  return (hmap == map->hmap2) ? (hmap + 1) : (hmap - 1);
}

  static inline struct wormhmap *
wormhmap_load(struct wormhole * const map)
{
  return (struct wormhmap *)atomic_load_explicit(&(map->hmap_ptr), MO_ACQUIRE);
}

  static inline void
wormhmap_store(struct wormhole * const map, struct wormhmap * const hmap)
{
  atomic_store_explicit(&(map->hmap_ptr), (u64)hmap, MO_RELEASE);
}

  static inline u64
wormhmap_version_load(const struct wormhmap * const hmap)
{
  // no concurrent access
  return atomic_load_explicit(&(hmap->hv), MO_ACQUIRE);
}

  static inline void
wormhmap_version_store(struct wormhmap * const hmap, const u64 v)
{
  atomic_store_explicit(&(hmap->hv), v, MO_RELEASE);
}

  static inline u64
wormleaf_version_load(struct wormleaf * const leaf)
{
  return atomic_load_explicit(&(leaf->lv), MO_CONSUME);
}

  static inline void
wormleaf_version_store(struct wormleaf * const leaf, const u64 v)
{
  atomic_store_explicit(&(leaf->lv), v, MO_RELEASE);
}
// }}} hmap-version

// co {{{
  static inline void
wormhmap_prefetch_pmap(const struct wormhmap * const hmap, const u32 idx)
{
#if defined(CORR)
  (void)hmap;
  (void)idx;
#else
  cpu_prefetch0(&(hmap->pmap[idx]));
#endif
}

  static inline struct wormmeta *
wormhmap_get_meta(const struct wormhmap * const hmap, const u32 mid, const u32 i)
{
  struct wormmeta * const meta = hmap->pmap[mid].e[i];
#if defined(CORR)
  cpu_prefetch0(meta);
  corr_yield();
#endif
  return meta;
}

  static inline void
wormleaf_prefetch(struct wormleaf * const leaf, const u32 hashlo)
{
  const u32 i = wormhole_pkey(hashlo) / WH_HDIV;
#if defined(CORR)
  cpu_prefetch0(leaf);
  cpu_prefetch0(&(leaf->hs[i-4]));
  cpu_prefetch0(&(leaf->hs[i+4]));
  corr_yield();
#else
  cpu_prefetch0(&(leaf->hs[i]));
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
wormhole_qsbr_update_pause(struct wormref * const ref, const u64 v)
{
  qsbr_update(&ref->qref, v);
#if defined(CORR)
  corr_yield();
#endif
}
// }}} co

// }}} helpers

// hmap {{{
// hmap is the MetaTrieHT of Wormhole
  static bool
wormhmap_init(struct wormhmap * const hmap, struct kv * const pbuf)
{
  const u64 wsize = sizeof(hmap->wmap[0]) * WH_HMAPINIT_SIZE;
  const u64 psize = sizeof(hmap->pmap[0]) * WH_HMAPINIT_SIZE;
  u64 msize = wsize + psize;
  u8 * const mem = pages_alloc_best(msize, true, &msize);
  if (mem == NULL)
    return false;

  hmap->pmap = (typeof(hmap->pmap))mem;
  hmap->wmap = (typeof(hmap->wmap))(mem + psize);
  hmap->msize = msize;
  hmap->mask = WH_HMAPINIT_SIZE - 1;
  wormhmap_version_store(hmap, 0);
  hmap->maxplen = 0;
  hmap->pbuf = pbuf;
  return true;
}

  static inline void
wormhmap_deinit(struct wormhmap * const hmap)
{
  if (hmap->pmap) {
    pages_unmap(hmap->pmap, hmap->msize);
    hmap->pmap = NULL;
    hmap->wmap = NULL;
  }
}

  static inline m128
wormhmap_zero(void)
{
#if defined(__x86_64__)
  return _mm_setzero_si128();
#elif defined(__aarch64__)
  return vdupq_n_u8(0);
#endif
}

  static inline m128
wormhmap_m128_pkey(const u16 pkey)
{
#if defined(__x86_64__)
  return _mm_set1_epi16((short)pkey);
#elif defined(__aarch64__)
  return vreinterpretq_u8_u16(vdupq_n_u16(pkey));
#endif
}

  static inline u32
wormhmap_match_mask(const struct wormslot * const s, const m128 skey)
{
#if defined(__x86_64__)
  const m128 sv = _mm_load_si128((const void *)s);
  return (u32)_mm_movemask_epi8(_mm_cmpeq_epi16(skey, sv));
#elif defined(__aarch64__)
  const uint16x8_t sv = vld1q_u16((const u16 *)s); // load 16 bytes at s
  const uint16x8_t cmp = vceqq_u16(vreinterpretq_u16_u8(skey), sv); // cmpeq => 0xffff or 0x0000
  static const uint16x8_t mbits = {0x3, 0xc, 0x30, 0xc0, 0x300, 0xc00, 0x3000, 0xc000};
  return (u32)vaddvq_u16(vandq_u16(cmp, mbits));
#endif
}

  static inline bool
wormhmap_match_any(const struct wormslot * const s, const m128 skey)
{
#if defined(__x86_64__)
  return wormhmap_match_mask(s, skey) != 0;
#elif defined(__aarch64__)
  const uint16x8_t sv = vld1q_u16((const u16 *)s); // load 16 bytes at s
  const uint16x8_t cmp = vceqq_u16(vreinterpretq_u16_u8(skey), sv); // cmpeq => 0xffff or 0x0000
  return vaddvq_u32(vreinterpretq_u32_u16(cmp)) != 0;
#endif
}

// meta_lcp only
  static inline bool
wormhmap_peek(const struct wormhmap * const hmap, const u32 hash32)
{
  const m128 sk = wormhmap_m128_pkey(wormhole_pkey(hash32));
  const u32 midx = hash32 & hmap->mask;
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  return wormhmap_match_any(&(hmap->wmap[midx]), sk)
    || wormhmap_match_any(&(hmap->wmap[midy]), sk);
}

  static inline struct wormmeta *
wormhmap_get_slot(const struct wormhmap * const hmap, const u32 mid,
    const m128 skey, const struct kv * const key)
{
  u32 mask = wormhmap_match_mask(&(hmap->wmap[mid]), skey);
  while (mask) {
    const u32 i2 = (u32)__builtin_ctz(mask);
    struct wormmeta * const meta = wormhmap_get_meta(hmap, mid, i2>>1);
    if (likely(wormhole_key_meta_match(key, meta)))
      return meta;
    mask ^= (3u << i2);
  }
  return NULL;
}

  static struct wormmeta *
wormhmap_get(const struct wormhmap * const hmap, const struct kv * const key)
{
  const u32 hash32 = key->hashlo;
  const u32 midx = hash32 & hmap->mask;
  wormhmap_prefetch_pmap(hmap, midx);
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  wormhmap_prefetch_pmap(hmap, midy);
  const m128 skey = wormhmap_m128_pkey(wormhole_pkey(hash32));

  struct wormmeta * const r = wormhmap_get_slot(hmap, midx, skey, key);
  if (r)
    return r;
  return wormhmap_get_slot(hmap, midy, skey, key);
}

// for meta_lcp only
  static inline struct wormmeta *
wormhmap_get_kref_slot(const struct wormhmap * const hmap, const u32 mid,
    const m128 skey, const struct kref * const kref)
{
  u32 mask = wormhmap_match_mask(&(hmap->wmap[mid]), skey);
  while (mask) {
    const u32 i2 = (u32)__builtin_ctz(mask);
    struct wormmeta * const meta = wormhmap_get_meta(hmap, mid, i2>>1);
    if (likely(wormhole_kref_meta_match(kref, meta)))
      return meta;

    mask ^= (3u << i2);
  }
  return NULL;
}

// for meta_lcp only
  static inline struct wormmeta *
wormhmap_get_kref(const struct wormhmap * const hmap, const struct kref * const kref)
{
  const u32 hash32 = kref->hash32;
  const u32 midx = hash32 & hmap->mask;
  wormhmap_prefetch_pmap(hmap, midx);
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  wormhmap_prefetch_pmap(hmap, midy);
  const m128 skey = wormhmap_m128_pkey(wormhole_pkey(hash32));

  struct wormmeta * const r = wormhmap_get_kref_slot(hmap, midx, skey, kref);
  if (r)
    return r;
  return wormhmap_get_kref_slot(hmap, midy, skey, kref);
}

// for meta_down only
  static inline struct wormmeta *
wormhmap_get_kref1_slot(const struct wormhmap * const hmap, const u32 mid,
    const m128 skey, const struct kref * const kref, const u8 cid)
{
  u32 mask = wormhmap_match_mask(&(hmap->wmap[mid]), skey);
  while (mask) {
    const u32 i2 = (u32)__builtin_ctz(mask);
    struct wormmeta * const meta = wormhmap_get_meta(hmap, mid, i2>>1);
    //cpu_prefetch0(wormmeta_rmost_load(meta)); // will access
    if (likely(wormhole_kref1_meta_match(kref, meta, cid)))
      return meta;

    mask ^= (3u << i2);
  }
  return NULL;
}

// for meta_down only
  static inline struct wormmeta *
wormhmap_get_kref1(const struct wormhmap * const hmap,
    const struct kref * const kref, const u8 cid)
{
  const u32 hash32 = crc32c_u8(kref->hash32, cid);
  const u32 midx = hash32 & hmap->mask;
  wormhmap_prefetch_pmap(hmap, midx);
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  wormhmap_prefetch_pmap(hmap, midy);
  const m128 skey = wormhmap_m128_pkey(wormhole_pkey(hash32));

  struct wormmeta * const r = wormhmap_get_kref1_slot(hmap, midx, skey, kref, cid);
  if (r)
    return r;
  return wormhmap_get_kref1_slot(hmap, midy, skey, kref, cid);
}

  static inline u32
wormhmap_slot_count(const struct wormslot * const slot)
{
  const u32 mask = wormhmap_match_mask(slot, wormhmap_zero());
  return mask ? ((u32)__builtin_ctz(mask) >> 1) : 8;
}

  static inline void
wormhmap_squeeze(const struct wormhmap * const hmap)
{
  struct wormslot * const wmap = hmap->wmap;
  struct wormmbkt * const pmap = hmap->pmap;
  const u32 mask = hmap->mask;
  const u64 nrs64 = ((u64)(hmap->mask)) + 1; // must use u64; u32 can overflow
  for (u64 si64 = 0; si64 < nrs64; si64++) { // # of buckets
    const u32 si = (u32)si64;
    u32 ci = wormhmap_slot_count(&(wmap[si]));
    for (u32 ei = ci - 1; ei < WH_BKT_NR; ei--) {
      struct wormmeta * const meta = pmap[si].e[ei];
      const u32 sj = wormmeta_hash32_load(meta) & mask; // first hash
      if (sj == si)
        continue;

      // move
      const u32 ej = wormhmap_slot_count(&(wmap[sj]));
      if (ej < WH_BKT_NR) { // has space at home location
        wmap[sj].t[ej] = wmap[si].t[ei];
        pmap[sj].e[ej] = pmap[si].e[ei];
        const u32 ni = ci - 1;
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

  static void
wormhmap_expand(struct wormhmap * const hmap)
{
  // sync expand
  const u32 mask0 = hmap->mask;
  if (mask0 == UINT32_MAX)
    debug_die();
  const u32 nr0 = mask0 + 1;
  const u32 mask1 = mask0 + nr0;
  const u64 nr1 = ((u64)nr0) << 1; // must use u64; u32 can overflow
  const u64 wsize = nr1 * sizeof(hmap->wmap[0]);
  const u64 psize = nr1 * sizeof(hmap->pmap[0]);
  u64 msize = wsize + psize;
  u8 * mem = pages_alloc_best(msize, true, &msize);
  if (mem == NULL) {
    // We are at a very deep call stack from wormhole_put().
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

  for (u32 s = 0; s < nr0; s++) {
    const struct wormmbkt * const bkt = &pmap0[s];
    for (u32 i = 0; (i < WH_BKT_NR) && bkt->e[i]; i++) {
      const struct wormmeta * const meta = bkt->e[i];
      const u32 hash32 = wormmeta_hash32_load(meta);
      const u32 idx0 = hash32 & mask0;
      const u32 idx1 = ((idx0 == s) ? hash32 : wormhole_bswap(hash32)) & mask1;

      const u32 n = wormhmap_slot_count(&(hmap1.wmap[idx1]));
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
  wormhmap_squeeze(hmap);
}

  static bool
wormhmap_cuckoo(struct wormhmap * const hmap, const u32 mid0,
    struct wormmeta * const e0, const u16 s0, const u32 depth)
{
  const u32 ii = wormhmap_slot_count(&(hmap->wmap[mid0]));
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
  for (u32 i = 0; i < WH_BKT_NR; i++) {
    const struct wormmeta * const meta = bkt->e[i];
    debug_assert(meta);
    const u32 hash32 = wormmeta_hash32_load(meta);

    const u32 midx = hash32 & hmap->mask;
    const u32 midy = wormhole_bswap(hash32) & hmap->mask;
    const u32 midt = (midx != mid0) ? midx : midy;
    if (midt != mid0) { // possible
      // no penalty if moving someone back to its 1st hash location
      const u32 depth1 = (midt == midx) ? depth : (depth - 1);
      if (wormhmap_cuckoo(hmap, midt, bkt->e[i], sv[i], depth1)) {
        bkt->e[i] = e0;
        sv[i] = s0;
        return true;
      }
    }
  }
  return false;
}

  static void
wormhmap_set(struct wormhmap * const hmap, struct wormmeta * const meta)
{
  const u32 hash32 = wormmeta_hash32_load(meta);
  const u32 midx = hash32 & hmap->mask;
  wormhmap_prefetch_pmap(hmap, midx);
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  wormhmap_prefetch_pmap(hmap, midy);
  const u16 pkey = wormhole_pkey(hash32);
  // insert with cuckoo
  if (likely(wormhmap_cuckoo(hmap, midx, meta, pkey, 1)))
    return;
  if (wormhmap_cuckoo(hmap, midy, meta, pkey, 1))
    return;
  if (wormhmap_cuckoo(hmap, midx, meta, pkey, 2))
    return;

  // expand
  wormhmap_expand(hmap);

  wormhmap_set(hmap, meta);
}

  static bool
wormhmap_del_slot(struct wormhmap * const hmap, const u32 mid,
    const struct wormmeta * const meta, const m128 skey)
{
  u32 mask = wormhmap_match_mask(&(hmap->wmap[mid]), skey);
  while (mask) {
    const u32 i2 = (u32)__builtin_ctz(mask);
    const struct wormmeta * const meta1 = hmap->pmap[mid].e[i2>>1];
    if (likely(meta == meta1)) {
      const u32 i = i2 >> 1;
      const u32 j = wormhmap_slot_count(&(hmap->wmap[mid])) - 1;
      hmap->wmap[mid].t[i] = hmap->wmap[mid].t[j];
      hmap->pmap[mid].e[i] = hmap->pmap[mid].e[j];
      hmap->wmap[mid].t[j] = 0;
      hmap->pmap[mid].e[j] = NULL;
      return true;
    }
    mask -= (3u << i2);
  }
  return false;
}

  static bool
wormhmap_del(struct wormhmap * const hmap, const struct wormmeta * const meta)
{
  const u32 hash32 = wormmeta_hash32_load(meta);
  const u32 midx = hash32 & hmap->mask;
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  const m128 skey = wormhmap_m128_pkey(wormhole_pkey(hash32));
  return wormhmap_del_slot(hmap, midx, meta, skey)
    || wormhmap_del_slot(hmap, midy, meta, skey);
}

  static bool
wormhmap_replace_slot(struct wormhmap * const hmap, const u32 mid,
    const struct wormmeta * const old, const m128 skey, struct wormmeta * const new)
{
  u32 mask = wormhmap_match_mask(&(hmap->wmap[mid]), skey);
  while (mask) {
    const u32 i2 = (u32)__builtin_ctz(mask);
    struct wormmeta ** const pslot = &hmap->pmap[mid].e[i2>>1];
    if (likely(old == *pslot)) {
      *pslot = new;
      return true;
    }
    mask -= (3u << i2);
  }
  return false;
}

  static bool
wormhmap_replace(struct wormhmap * const hmap, const struct wormmeta * const old, struct wormmeta * const new)
{
  const u32 hash32 = wormmeta_hash32_load(old);
  const u32 midx = hash32 & hmap->mask;
  const u32 midy = wormhole_bswap(hash32) & hmap->mask;
  const m128 skey = wormhmap_m128_pkey(wormhole_pkey(hash32));
  return wormhmap_replace_slot(hmap, midx, old, skey, new)
    || wormhmap_replace_slot(hmap, midy, old, skey, new);
}
// }}} hmap

// create {{{
// it's unsafe
  static bool
wormhole_create_leaf0(struct wormhole * const map)
{
  const bool sr = wormhole_slab_reserve(map, 1);
  if (unlikely(!sr))
    return false;

  // create leaf of empty key
  struct kv * const anchor = wormhole_alloc_akey(0);
  if (anchor == NULL)
    return false;
  kv_dup2(kv_null(), anchor);

  struct wormleaf * const leaf0 = wormleaf_alloc(map, NULL, NULL, anchor);
  if (leaf0 == NULL) {
    wormhole_free_akey(anchor);
    return false;
  }

  struct kv * const mkey = wormhole_alloc_mkey(0);
  if (mkey == NULL) {
    wormleaf_free(map->slab_leaf, leaf0);
    return false;
  }

  wormhole_prefix(mkey, 0);
  mkey->refcnt = 0;
  // create meta of empty key
  for (u32 i = 0; i < 2; i++) {
    if (map->hmap2[i].slab1) {
      struct wormmeta * const m0 = wormmeta_alloc(&map->hmap2[i], leaf0, mkey, 0, WH_FO);
      debug_assert(m0); // already reserved enough
      wormhmap_set(&(map->hmap2[i]), m0);
    }
  }

  map->leaf0 = leaf0;
  return true;
}

  static struct wormhole *
wormhole_create_internal(const struct kvmap_mm * const mm, const u32 nh)
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
    goto fail;

  // hmap
  for (u32 i = 0; i < nh; i++) {
    struct wormhmap * const hmap = &map->hmap2[i];
    if (!wormhmap_init(hmap, map->pbuf))
      goto fail;

    hmap->slab1 = slab_create(sizeof(struct wormmeta), WH_SLABMETA_SIZE);
    if (hmap->slab1 == NULL)
      goto fail;

    hmap->slab2 = slab_create(sizeof(struct wormmeta) + (sizeof(u64) * WH_BMNR), WH_SLABMETA_SIZE);
    if (hmap->slab2 == NULL)
      goto fail;
  }

  // leaf slab
  map->slab_leaf = slab_create(sizeof(struct wormleaf), WH_SLABLEAF_SIZE);
  if (map->slab_leaf == NULL)
    goto fail;

  // qsbr
  map->qsbr = qsbr_create();
  if (map->qsbr == NULL)
    goto fail;

  // leaf0
  if (!wormhole_create_leaf0(map))
    goto fail;

  rwlock_init(&(map->metalock));
  wormhmap_store(map, &map->hmap2[0]);
  return map;

fail:
  if (map->qsbr)
    qsbr_destroy(map->qsbr);

  if (map->slab_leaf)
    slab_destroy(map->slab_leaf);

  for (u32 i = 0; i < nh; i++) {
    struct wormhmap * const hmap = &map->hmap2[i];
    if (hmap->slab1)
      slab_destroy(hmap->slab1);
    if (hmap->slab2)
      slab_destroy(hmap->slab2);
    wormhmap_deinit(hmap);
  }

  if (map->pbuf)
    free(map->pbuf);

  free(map);
  return NULL;
}

  struct wormhole *
wormhole_create(const struct kvmap_mm * const mm)
{
  return wormhole_create_internal(mm, 2);
}

  struct wormhole *
whunsafe_create(const struct kvmap_mm * const mm)
{
  return wormhole_create_internal(mm, 1);
}
// }}} create

// jump {{{

// lcp {{{
// search in the hash table for the Longest Prefix Match of the search key
// The corresponding wormmeta node is returned and the LPM is recorded in kref
  static struct wormmeta *
wormhole_meta_lcp(const struct wormhmap * const hmap, struct kref * const kref, const u32 klen)
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
    if (wormhmap_peek(hmap, hash32)) {
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
    if (wormhmap_peek(hmap, hash32)) {
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
  struct wormmeta * ret = wormhmap_get_kref(hmap, kref);
  if (likely(ret != NULL))
    return ret;

  gd = lo;
  lo = 0;
  loh = KV_CRC32C_SEED;

#define META_LCP_GAP_2 ((5u))
  while (META_LCP_GAP_2 < gd) {
    const u32 inc = (gd * 3) >> 2;
    wormhole_kref_inc(kref, lo, loh, inc);
    struct wormmeta * const tmp = wormhmap_get_kref(hmap, kref);
    if (tmp) {
      loh = kref->hash32;
      lo += inc;
      gd -= inc;
      ret = tmp;
      if (wormmeta_bm_test(tmp, kref->ptr[lo])) {
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
    struct wormmeta * const tmp = wormhmap_get_kref(hmap, kref);
    if (tmp) {
      loh = kref->hash32;
      lo += inc;
      gd -= inc;
      ret = tmp;
      if (wormmeta_bm_test(tmp, kref->ptr[lo])) {
        loh = crc32c_u8(loh, kref->ptr[lo]);
        lo++;
        gd--;
        ret = NULL;
      } else {
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
    ret = wormhmap_get_kref(hmap, kref);
  debug_assert(ret);
  return ret;
}
// }}} lcp

// down {{{
  static struct wormleaf *
wormhole_meta_down(const struct wormhmap * const hmap, const struct kref * const lcp,
    const struct wormmeta * const meta, const u32 klen)
{
  if (likely(lcp->len < klen)) { // partial match
    const u32 id0 = lcp->ptr[lcp->len];
    if (wormmeta_bitmin_load(meta) > id0) { // no left, don't care about right.
      return wormmeta_lpath_load(meta);
    } else if (wormmeta_bitmax_load(meta) < id0) { // has left sibling but no right sibling
      return wormmeta_rmost_load(meta);
    } else { // has both (expensive)
      return wormmeta_rmost_load(wormhmap_get_kref1(hmap, lcp, (u8)wormmeta_bm_lt(meta, id0)));
    }
  } else { // lcp->len == klen
    return wormmeta_lpath_load(meta);
  }
}
// }}} down

// jump-rw {{{
  static struct wormleaf *
wormhole_jump_leaf(const struct wormhmap * const hmap, const struct kref * const key)
{
  struct kref kref = {.ptr = key->ptr};
  debug_assert(kv_crc32c(key->ptr, key->len) == key->hash32);

  const struct wormmeta * const meta = wormhole_meta_lcp(hmap, &kref, key->len);
  return wormhole_meta_down(hmap, &kref, meta, key->len);
}

  static struct wormleaf *
wormhole_jump_leaf_read(struct wormref * const ref, const struct kref * const key)
{
  struct wormhole * const map = ref->map;
#pragma nounroll
  do {
    const struct wormhmap * const hmap = wormhmap_load(map);
    const u64 v = wormhmap_version_load(hmap);
    qsbr_update(&ref->qref, v);
    struct wormleaf * const leaf = wormhole_jump_leaf(hmap, key);
    wormleaf_prefetch(leaf, key->hash32);
#pragma nounroll
    do {
      if (rwlock_trylock_read_nr(&(leaf->leaflock), 64)) {
        if (wormleaf_version_load(leaf) <= v)
          return leaf;
        wormleaf_unlock_read(leaf);
        break;
      }
      // v1 is loaded before lv; if lv <= v, can update v1 without redo jump
      const u64 v1 = wormhmap_version_load(wormhmap_load(map));
      if (wormleaf_version_load(leaf) > v)
        break;
      wormhole_qsbr_update_pause(ref, v1);
    } while (true);
  } while (true);
}

  static struct wormleaf *
wormhole_jump_leaf_write(struct wormref * const ref, const struct kref * const key)
{
  struct wormhole * const map = ref->map;
#pragma nounroll
  do {
    const struct wormhmap * const hmap = wormhmap_load(map);
    const u64 v = wormhmap_version_load(hmap);
    qsbr_update(&ref->qref, v);
    struct wormleaf * const leaf = wormhole_jump_leaf(hmap, key);
    wormleaf_prefetch(leaf, key->hash32);
#pragma nounroll
    do {
      if (rwlock_trylock_write_nr(&(leaf->leaflock), 64)) {
        if (wormleaf_version_load(leaf) <= v)
          return leaf;
        wormleaf_unlock_write(leaf);
        break;
      }
      // v1 is loaded before lv; if lv <= v, can update v1 without redo jump
      const u64 v1 = wormhmap_version_load(wormhmap_load(map));
      if (wormleaf_version_load(leaf) > v)
        break;
      wormhole_qsbr_update_pause(ref, v1);
    } while (true);
  } while (true);
}
// }}} jump-rw

// }}} jump

// leaf-read {{{
  static inline struct kv *
wormleaf_kv_at_ih(const struct wormleaf * const leaf, const u32 ih)
{
  return u64_to_ptr(leaf->hs[ih].e3);
}

  static inline struct kv *
wormleaf_kv_at_is(const struct wormleaf * const leaf, const u32 is)
{
  return u64_to_ptr(leaf->hs[leaf->ss[is]].e3);
}

  static inline void
wormleaf_prefetch_ss(const struct wormleaf * const leaf)
{
  for (u32 i = 0; i < WH_KPN; i+=64)
    cpu_prefetch0(&leaf->ss[i]);
}

// leaf must have been sorted
// return the key at [i] as if k1 has been inserted into leaf; i <= leaf->nr_sorted
  static const struct kv *
wormleaf_kv_at_is1(const struct wormleaf * const leaf, const u32 i, const u32 is1, const struct kv * const k1)
{
  debug_assert(leaf->nr_keys == leaf->nr_sorted);
  debug_assert(is1 <= leaf->nr_sorted);
  if (i < is1)
    return wormleaf_kv_at_is(leaf, i);
  else if (i > is1)
    return wormleaf_kv_at_is(leaf, i-1);
  else // i == is1
    return k1;
}

// fast point-lookup
// returns WH_KPN if not found
  static u32
wormleaf_match_hs(const struct wormleaf * const leaf, const struct kref * const key)
{
  const u16 pkey = wormhole_pkey(key->hash32);
  const u32 i0 = pkey / WH_HDIV;
  const struct entry13 * const hs = leaf->hs;

  if (hs[i0].e1 == pkey) {
    struct kv * const curr = u64_to_ptr(hs[i0].e3);
    if (likely(wormhole_kref_kv_match(key, curr)))
      return i0;
  }
  if (hs[i0].e1 == 0)
    return WH_KPN;

  // search left
  u32 i = i0 - 1;
  while (i < WH_KPN) {
    if (hs[i].e1 == pkey) {
      struct kv * const curr = u64_to_ptr(hs[i].e3);
      if (likely(wormhole_kref_kv_match(key, curr)))
        return i;
    } else if (hs[i].e1 < pkey) {
      break;
    }
    i--;
  }

  // search right
  i = i0 + 1;
  while (i < WH_KPN) {
    if (hs[i].e1 == pkey) {
      struct kv * const curr = u64_to_ptr(hs[i].e3);
      if (likely(wormhole_kref_kv_match(key, curr)))
        return i;
    } else if ((hs[i].e1 > pkey) || (hs[i].e1 == 0)) {
      break;
    }
    i++;
  }

  // not found
  return WH_KPN;
}

// search for an existing entry in hs
  static u32
wormleaf_search_ih(const struct wormleaf * const leaf, const struct entry13 e)
{
  const u16 pkey = e.e1;
  const u32 i0 = pkey / WH_HDIV;
  const struct entry13 * const hs = leaf->hs;
  const struct entry13 e0 = hs[i0];

  if (e0.v64 == e.v64)
    return i0;

  if (e0.e1 == 0)
    return WH_KPN;

  // search left
  u32 i = i0 - 1;
  while (i < WH_KPN) {
    const struct entry13 ei = hs[i];
    if (ei.v64 == e.v64) {
      return i;
    } else if (ei.e1 < pkey) {
      break;
    }
    i--;
  }

  // search right
  i = i0 + 1;
  while (i < WH_KPN) {
    const struct entry13 ei = hs[i];
    if (ei.v64 == e.v64) {
      return i;
    } else if ((ei.e1 > pkey) || (ei.e1 == 0)) {
      break;
    }
    i++;
  }

  // not found
  return WH_KPN;
}

// search for an existing entry in ss
  static u32
wormleaf_search_is(const struct wormleaf * const leaf, const u8 ih)
{
#if defined(__x86_64__)
  // TODO: avx512
#if defined(__AVX2__)
  const m256 i1 = _mm256_set1_epi8((char)ih);
  for (u32 i = 0; i < leaf->nr_keys; i += sizeof(m256)) {
    const m256 sv = _mm256_load_si256((m256 *)(leaf->ss+i));
    const u32 mask = (u32)_mm256_movemask_epi8(_mm256_cmpeq_epi8(sv, i1));
    if (mask)
      return i + (u32)__builtin_ctz(mask);
  }
#else // SSE4.2
  const m128 i1 = _mm_set1_epi8((char)ih);
  for (u32 i = 0; i < leaf->nr_keys; i += sizeof(m128)) {
    const m128 sv = _mm_load_si128((m128 *)(leaf->ss+i));
    const u32 mask = (u32)_mm_movemask_epi8(_mm_cmpeq_epi8(sv, i1));
    if (mask)
      return i + (u32)__builtin_ctz(mask);
  }
#endif // __AVX2__
#elif defined(__aarch64__)
  static const m128 vtbl = {0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15};
  static const uint16x8_t mbits = {0x0101, 0x0202, 0x0404, 0x0808, 0x1010, 0x2020, 0x4040, 0x8080};
  const m128 i1 = vdupq_n_u8(ih);
  for (u32 i = 0; i < leaf->nr_keys; i += sizeof(m128)) {
    const m128 cmp = vceqq_u8(vld1q_u8(leaf->ss+i), i1); // cmpeq => 0xff or 0x00
    const m128 cmp1 = vqtbl1q_u8(cmp, vtbl); // reorder
    const u32 mask = (u32)vaddvq_u16(vandq_u8(vreinterpretq_u16_u8(cmp1), mbits));
    if (mask)
      return i + (u32)__builtin_ctz(mask);
  }
#endif // __x86_64__
  debug_die();
}

// assumes there in no duplicated keys
// search the first key that is >= the given key
// return 0 .. nr_sorted
  static u32
wormleaf_search_ss(const struct wormleaf * const leaf, const struct kref * const key)
{
  u32 lo = 0;
  u32 hi = leaf->nr_sorted;
  while ((lo + 2) < hi) {
    const u32 i = (lo + hi) >> 1;
    const struct kv * const curr = wormleaf_kv_at_is(leaf, i);
    cpu_prefetch0(curr);
    cpu_prefetch0(leaf->hs + leaf->ss[(lo + i) >> 1]);
    cpu_prefetch0(leaf->hs + leaf->ss[(i + 1 + hi) >> 1]);
    const int cmp = kref_kv_compare(key, curr);
    debug_assert(cmp != 0);
    if (cmp < 0)
      hi = i;
    else
      lo = i + 1;
  }

  while (lo < hi) {
    const u32 i = (lo + hi) >> 1;
    const struct kv * const curr = wormleaf_kv_at_is(leaf, i);
    const int cmp = kref_kv_compare(key, curr);
    debug_assert(cmp != 0);
    if (cmp < 0)
      hi = i;
    else
      lo = i + 1;
  }
  return lo;
}

  static u32
wormleaf_seek(const struct wormleaf * const leaf, const struct kref * const key)
{
  debug_assert(leaf->nr_sorted == leaf->nr_keys);
  wormleaf_prefetch_ss(leaf); // effective for both hit and miss
  const u32 ih = wormleaf_match_hs(leaf, key);
  if (ih < WH_KPN) { // hit
    return wormleaf_search_is(leaf, (u8)ih);
  } else { // miss, binary search for gt
    return wormleaf_search_ss(leaf, key);
  }
}

// same to search_sorted but the target is very likely beyond the end
  static u32
wormleaf_seek_end(const struct wormleaf * const leaf, const struct kref * const key)
{
  debug_assert(leaf->nr_keys == leaf->nr_sorted);
  if (leaf->nr_sorted) {
    const int cmp = kref_kv_compare(key, wormleaf_kv_at_is(leaf, leaf->nr_sorted-1));
    if (cmp > 0)
      return leaf->nr_sorted;
    else if (cmp == 0)
      return leaf->nr_sorted - 1;
    else
      return wormleaf_seek(leaf, key);
  } else {
    return 0;
  }
}
// }}} leaf-read

// leaf-write {{{
  static void
wormleaf_sort_m2(struct wormleaf * const leaf, const u32 n1, const u32 n2)
{
  if (n1 == 0 || n2 == 0)
    return; // no need to sort

  u8 * const ss = leaf->ss;
  u8 et[WH_KPN/2]; // min(n1,n2) < KPN/2
  if (n1 <= n2) { // merge left
    memcpy(et, &(ss[0]), sizeof(ss[0]) * n1);
    u8 * eo = ss;
    u8 * e1 = et; // size == n1
    u8 * e2 = &(ss[n1]); // size == n2
    const u8 * const z1 = e1 + n1;
    const u8 * const z2 = e2 + n2;
    while ((e1 < z1) && (e2 < z2)) {
      const int cmp = kv_compare(wormleaf_kv_at_ih(leaf, *e1), wormleaf_kv_at_ih(leaf, *e2));
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
    memcpy(et, &(ss[n1]), sizeof(ss[0]) * n2);
    u8 * eo = &(ss[n1 + n2 - 1]); // merge backwards
    u8 * e1 = &(ss[n1 - 1]); // size == n1
    u8 * e2 = &(et[n2 - 1]); // size == n2
    const u8 * const z1 = e1 - n1;
    const u8 * const z2 = e2 - n2;
    while ((e1 > z1) && (e2 > z2)) {
      const int cmp = kv_compare(wormleaf_kv_at_ih(leaf, *e1), wormleaf_kv_at_ih(leaf, *e2));
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

#if defined(__linux__)
  static int
wormleaf_ss_cmp(const void * const p1, const void * const p2, void * priv)
{
  const struct kv * const k1 = wormleaf_kv_at_ih(priv, *(const u8 *)p1);
  const struct kv * const k2 = wormleaf_kv_at_ih(priv, *(const u8 *)p2);
  return kv_compare(k1, k2);
}
#else // (FreeBSD and APPLE only)
  static int
wormleaf_ss_cmp(void * priv, const void * const p1, const void * const p2)
{
  const struct kv * const k1 = wormleaf_kv_at_ih(priv, *(const u8 *)p1);
  const struct kv * const k2 = wormleaf_kv_at_ih(priv, *(const u8 *)p2);
  return kv_compare(k1, k2);
}
#endif // __linux__

  static inline void
wormleaf_sort_range(struct wormleaf * const leaf, const u32 i0, const u32 nr)
{
#if defined(__linux__)
  qsort_r(&(leaf->ss[i0]), nr, sizeof(leaf->ss[0]), wormleaf_ss_cmp, leaf);
#else // (FreeBSD and APPLE only)
  qsort_r(&(leaf->ss[i0]), nr, sizeof(leaf->ss[0]), leaf, wormleaf_ss_cmp);
#endif // __linux__
}

// make sure all keys are sorted in a leaf node
  static void
wormleaf_sync_sorted(struct wormleaf * const leaf)
{
  const u32 s = leaf->nr_sorted;
  const u32 n = leaf->nr_keys;
  if (s == n)
    return;

  wormleaf_sort_range(leaf, s, n - s);
  // merge-sort inplace
  wormleaf_sort_m2(leaf, s, n - s);
  leaf->nr_sorted = n;
}

// shift a sequence of entries on hs and update the corresponding ss values
  static void
wormleaf_shift_inc(struct wormleaf * const leaf, const u32 to, const u32 from, const u32 nr)
{
  debug_assert(to == (from+1));
  struct entry13 * const hs = leaf->hs;
  memmove(&(hs[to]), &(hs[from]), sizeof(hs[0]) * nr);

#if defined(__x86_64__)
  // TODO: avx512
#if defined(__AVX2__)
  const m256 ones = _mm256_set1_epi8(1);
  const m256 addx = _mm256_set1_epi8((char)(u8)(INT8_MAX + 1 - from - nr));
  const m256 cmpx = _mm256_set1_epi8((char)(u8)(INT8_MAX - nr));
  for (u32 i = 0; i < leaf->nr_keys; i += sizeof(m256)) {
    const m256 sv = _mm256_load_si256((m256 *)(leaf->ss+i));
    const m256 add1 = _mm256_and_si256(_mm256_cmpgt_epi8(_mm256_add_epi8(sv, addx), cmpx), ones);
    _mm256_store_si256((m256 *)(leaf->ss+i), _mm256_add_epi8(sv, add1));
  }
#else // SSE4.2
  const m128 ones = _mm_set1_epi8(1);
  const m128 addx = _mm_set1_epi8((char)(u8)(INT8_MAX + 1 - from - nr));
  const m128 cmpx = _mm_set1_epi8((char)(u8)(INT8_MAX - nr));
  for (u32 i = 0; i < leaf->nr_keys; i += sizeof(m128)) {
    const m128 sv = _mm_load_si128((m128 *)(leaf->ss+i));
    const m128 add1 = _mm_and_si128(_mm_cmpgt_epi8(_mm_add_epi8(sv, addx), cmpx), ones);
    _mm_store_si128((m128 *)(leaf->ss+i), _mm_add_epi8(sv, add1));
  }
#endif // __AVX2__
#elif defined(__aarch64__) // __x86_64__
  // aarch64
  const m128 subx = vdupq_n_u8((u8)from);
  const m128 cmpx = vdupq_n_u8((u8)nr);
  for (u32 i = 0; i < leaf->nr_keys; i += sizeof(m128)) {
    const m128 sv = vld1q_u8(leaf->ss+i);
    const m128 add1 = vshrq_n_u8(vcltq_u8(vsubq_u8(sv, subx), cmpx), 7);
    vst1q_u8(leaf->ss+i, vaddq_u8(sv, add1));
  }
#endif // __x86_64__
}

  static void
wormleaf_shift_dec(struct wormleaf * const leaf, const u32 to, const u32 from, const u32 nr)
{
  debug_assert(to == (from-1));
  struct entry13 * const hs = leaf->hs;
  memmove(&(hs[to]), &(hs[from]), sizeof(hs[0]) * nr);

#if defined(__x86_64__)
  // TODO: avx512
#if defined(__AVX2__)
  const m256 ones = _mm256_set1_epi8(1);
  const m256 addx = _mm256_set1_epi8((char)(u8)(INT8_MAX + 1 - from - nr));
  const m256 cmpx = _mm256_set1_epi8((char)(u8)(INT8_MAX - nr));
  for (u32 i = 0; i < leaf->nr_keys; i += sizeof(m256)) {
    const m256 sv = _mm256_load_si256((m256 *)(leaf->ss+i));
    const m256 add1 = _mm256_and_si256(_mm256_cmpgt_epi8(_mm256_add_epi8(sv, addx), cmpx), ones);
    _mm256_store_si256((m256 *)(leaf->ss+i), _mm256_sub_epi8(sv, add1));
  }
#else // SSE4.2
  const m128 ones = _mm_set1_epi8(1);
  const m128 addx = _mm_set1_epi8((char)(u8)(INT8_MAX + 1 - from - nr));
  const m128 cmpx = _mm_set1_epi8((char)(u8)(INT8_MAX - nr));
  for (u32 i = 0; i < leaf->nr_keys; i += 16) {
    const m128 sv = _mm_load_si128((m128 *)(leaf->ss+i));
    const m128 add1 = _mm_and_si128(_mm_cmpgt_epi8(_mm_add_epi8(sv, addx), cmpx), ones);
    _mm_store_si128((m128 *)(leaf->ss+i), _mm_sub_epi8(sv, add1));
  }
#endif // __AVX2__
#elif defined(__aarch64__) // __x86_64__
  // aarch64
  const m128 subx = vdupq_n_u8((u8)from);
  const m128 cmpx = vdupq_n_u8((u8)nr);
  for (u32 i = 0; i < leaf->nr_keys; i += sizeof(m128)) {
    const m128 sv = vld1q_u8(leaf->ss+i);
    const m128 add1 = vshrq_n_u8(vcltq_u8(vsubq_u8(sv, subx), cmpx), 7);
    vst1q_u8(leaf->ss+i, vsubq_u8(sv, add1));
  }
#endif // __x86_64__
}

// insert hs and also shift ss
  static u32
wormleaf_insert_hs(struct wormleaf * const leaf, const struct entry13 e)
{
  struct entry13 * const hs = leaf->hs;
  const u16 pkey = e.e1;
  const u32 i0 = pkey / WH_HDIV;
  if (hs[i0].e1 == 0) { // insert
    hs[i0] = e;
    return i0;
  }

  // find left-most insertion point
  u32 i = i0;
  while (i && hs[i-1].e1 && (hs[i-1].e1 >= pkey))
    i--;
  while ((i < WH_KPN) && hs[i].e1 && (hs[i].e1 < pkey)) // stop at >= or empty
    i++;
  const u32 il = --i; // i in [0, KPN]

  // find left empty slot
  if (i > (i0 - 1))
    i = i0 - 1;
  while ((i < WH_KPN) && hs[i].e1)
    i--;
  const u32 el = i; // el < i0 or el is invalid (>= KPN)

  // find right-most insertion point.
  i = il + 1;
  while ((i < WH_KPN) && hs[i].e1 && (hs[i].e1 == pkey))
    i++;
  const u32 ir = i; // ir >= il, in [0, KPN]

  // find right empty slot
  if (i < (i0 + 1))
    i = i0 + 1;
  while ((i < WH_KPN) && hs[i].e1)
    i++;
  const u32 er = i; // er > i0 or el is invalid (>= KPN)

  // el <= il < ir <= er    (if < WH_KPN)
  const u32 dl = (el < WH_KPN) ? (il - el) : WH_KPN;
  const u32 dr = (er < WH_KPN) ? (er - ir) : WH_KPN;
  if (dl <= dr) { // push left
    debug_assert(dl < WH_KPN);
    if (dl)
      wormleaf_shift_dec(leaf, el, el+1, dl);
    hs[il] = e;
    return il;
  } else {
    debug_assert(dr < WH_KPN);
    if (dr)
      wormleaf_shift_inc(leaf, ir+1, ir, dr);
    hs[ir] = e;
    return ir;
  }
}

  static void
wormleaf_insert_e13(struct wormleaf * const leaf, const struct entry13 e)
{
  // insert to hs and fix all existing is
  const u32 ih = wormleaf_insert_hs(leaf, e);
  debug_assert(ih < WH_KPN);
  // append the new is
  leaf->ss[leaf->nr_keys] = (u8)ih;
  // fix nr
  leaf->nr_keys++;
}

  static void
wormleaf_insert(struct wormleaf * const leaf, const struct kv * const new)
{
  debug_assert(new->hash == kv_crc32c_extend(kv_crc32c(new->kv, new->klen)));
  debug_assert(leaf->nr_keys < WH_KPN);

  // insert
  const struct entry13 e = entry13(wormhole_pkey(new->hashlo), ptr_to_u64(new));
  const u32 nr0 = leaf->nr_keys;
  wormleaf_insert_e13(leaf, e);

  // optimize for seq insertion
  if (nr0 == leaf->nr_sorted) {
    if (nr0) {
      const struct kv * const kvn = wormleaf_kv_at_is(leaf, nr0 - 1);
      if (kv_compare(new, kvn) > 0)
        leaf->nr_sorted = nr0 + 1;
    } else {
      leaf->nr_sorted = 1;
    }
  }
}

  static void
wormleaf_pull_ih(struct wormleaf * const leaf, const u32 ih)
{
  struct entry13 * const hs = leaf->hs;
  // try left
  u32 i = ih - 1;
  while ((i < WH_KPN) && hs[i].e1 && ((hs[i].e1 / WH_HDIV) > i))
    i--;

  if ((++i) < ih) {
    wormleaf_shift_inc(leaf, i+1, i, ih - i);
    leaf->hs[i].v64 = 0;
    return;
  }

  // try right
  i = ih + 1;
  while ((i < WH_KPN) && hs[i].e1 && ((hs[i].e1 / WH_HDIV) < i))
    i++;

  if ((--i) > ih) {
    wormleaf_shift_dec(leaf, ih, ih+1, i - ih);
    hs[i].v64 = 0;
  }
  // hs[ih] may still be 0
}

// internal only
  static struct kv *
wormleaf_remove(struct wormleaf * const leaf, const u32 ih, const u32 is)
{
  // ss
  leaf->ss[is] = leaf->ss[leaf->nr_keys - 1];
  if (leaf->nr_sorted > is)
    leaf->nr_sorted = is;

  // ret
  struct kv * const victim = wormleaf_kv_at_ih(leaf, ih);
  // hs
  leaf->hs[ih].v64 = 0;
  leaf->nr_keys--;
  // use magnet
  wormleaf_pull_ih(leaf, ih);
  return victim;
}

// remove key from leaf but do not call free
  static struct kv *
wormleaf_remove_ih(struct wormleaf * const leaf, const u32 ih)
{
  // remove from ss
  const u32 is = wormleaf_search_is(leaf, (u8)ih);
  debug_assert(is < leaf->nr_keys);
  return wormleaf_remove(leaf, ih, is);
}

  static struct kv *
wormleaf_remove_is(struct wormleaf * const leaf, const u32 is)
{
  return wormleaf_remove(leaf, leaf->ss[is], is);
}

// for delr (delete-range)
  static void
wormleaf_delete_range(struct wormhole * const map, struct wormleaf * const leaf,
    const u32 i0, const u32 end)
{
  debug_assert(leaf->nr_keys == leaf->nr_sorted);
  for (u32 i = end; i > i0; i--) {
    const u32 ir = i - 1;
    struct kv * const victim = wormleaf_remove_is(leaf, ir);
    map->mm.free(victim, map->mm.priv);
  }
}

// return the old kv; the caller should free the old kv
  static struct kv *
wormleaf_update(struct wormleaf * const leaf, const u32 ih, const struct kv * const new)
{
  debug_assert(new->hash == kv_crc32c_extend(kv_crc32c(new->kv, new->klen)));
  // search entry in ss (is)
  struct kv * const old = wormleaf_kv_at_ih(leaf, ih);
  debug_assert(old);

  entry13_update_e3(&leaf->hs[ih], (u64)new);
  return old;
}
// }}} leaf-write

// leaf-split {{{
// It only works correctly in cut_search
// quickly tell if a cut between k1 and k2 can achieve a specific anchor-key length
  static bool
wormhole_split_cut_alen_check(const u32 alen, const struct kv * const k1, const struct kv * const k2)
{
  debug_assert(k2->klen >= alen);
  return (k1->klen < alen) || (k1->kv[alen - 1] != k2->kv[alen - 1]);
}

// return the number of keys that should go to leaf1
// assert(r > 0 && r <= nr_keys)
// (1) r < is1, anchor key is ss[r-1]:ss[r]
// (2) r == is1: anchor key is ss[r-1]:new
// (3) r == is1+1: anchor key is new:ss[r-1] (ss[r-1] is the ss[r] on the logically sorted array)
// (4) r > is1+1: anchor key is ss[r-2]:ss[r-1] (ss[r-2] is the [r-1] on the logically sorted array)
// edge cases:
//   (case 2) is1 == nr_keys: r = nr_keys; ss[r-1]:new
//   (case 3) is1 == 0, r == 1; new:ss[0]
// return 1..WH_KPN
  static u32
wormhole_split_cut_search1(struct wormleaf * const leaf, u32 l, u32 h, const u32 is1, const struct kv * const new)
{
  debug_assert(leaf->nr_keys == leaf->nr_sorted);
  debug_assert(leaf->nr_keys);
  debug_assert(l < h && h <= leaf->nr_sorted);

  const struct kv * const kl0 = wormleaf_kv_at_is1(leaf, l, is1, new);
  const struct kv * const kh0 = wormleaf_kv_at_is1(leaf, h, is1, new);
  const u32 alen = kv_key_lcp(kl0, kh0) + 1;
  if (unlikely(alen > UINT16_MAX))
    return WH_KPN2;

  const u32 target = leaf->next ? WH_MID : WH_KPN_MRG;
  while ((l + 1) < h) {
    const u32 m = (l + h + 1) >> 1;
    if (m <= target) { // try right
      const struct kv * const k1 = wormleaf_kv_at_is1(leaf, m, is1, new);
      const struct kv * const k2 = wormleaf_kv_at_is1(leaf, h, is1, new);
      if (wormhole_split_cut_alen_check(alen, k1, k2))
        l = m;
      else
        h = m;
    } else { // try left
      const struct kv * const k1 = wormleaf_kv_at_is1(leaf, l, is1, new);
      const struct kv * const k2 = wormleaf_kv_at_is1(leaf, m, is1, new);
      if (wormhole_split_cut_alen_check(alen, k1, k2))
        h = m;
      else
        l = m;
    }
  }
  return h;
}

  static void
wormhole_split_leaf_move1(struct wormleaf * const leaf1, struct wormleaf * const leaf2,
    const u32 cut, const u32 is1, const struct kv * const new)
{
  const u32 nr_keys = leaf1->nr_keys;
  const struct entry13 e1 = entry13(wormhole_pkey(new->hashlo), ptr_to_u64(new));
  struct entry13 es[WH_KPN];

  if (cut <= is1) { // e1 goes to leaf2
    // leaf2
    for (u32 i = cut; i < is1; i++)
      wormleaf_insert_e13(leaf2, leaf1->hs[leaf1->ss[i]]);

    wormleaf_insert_e13(leaf2, e1);

    for (u32 i = is1; i < nr_keys; i++)
      wormleaf_insert_e13(leaf2, leaf1->hs[leaf1->ss[i]]);

    // leaf1
    for (u32 i = 0; i < cut; i++)
      es[i] = leaf1->hs[leaf1->ss[i]];

  } else { // e1 goes to leaf1
    // leaf2
    for (u32 i = cut - 1; i < nr_keys; i++)
      wormleaf_insert_e13(leaf2, leaf1->hs[leaf1->ss[i]]);

    // leaf1
    for (u32 i = 0; i < is1; i++)
      es[i] = leaf1->hs[leaf1->ss[i]];

    es[is1] = e1;

    for (u32 i = is1 + 1; i < cut; i++)
      es[i] = leaf1->hs[leaf1->ss[i - 1]];
  }

  leaf2->nr_sorted = leaf2->nr_keys;

  memset(leaf1->hs, 0, sizeof(leaf1->hs[0]) * WH_KPN);
  leaf1->nr_keys = 0;
  for (u32 i = 0; i < cut; i++)
    wormleaf_insert_e13(leaf1, es[i]);
  leaf1->nr_sorted = cut;
  debug_assert((leaf1->nr_sorted + leaf2->nr_sorted) == (nr_keys + 1));
}

// create an anchor for leaf-split
  static struct kv *
wormhole_split_alloc_anchor(const struct kv * const key1, const struct kv * const key2)
{
  const u32 alen = kv_key_lcp(key1, key2) + 1;
  debug_assert(alen <= key2->klen);

  struct kv * const anchor = wormhole_alloc_akey(alen);
  if (anchor)
    kv_refill(anchor, key2->kv, alen, NULL, 0);
  return anchor;
}

// leaf1 is locked
// split leaf1 into leaf1+leaf2; insert new into leaf1 or leaf2, return leaf2
  static struct wormleaf *
wormhole_split_leaf(struct wormhole * const map, struct wormleaf * const leaf1, struct kv * const new)
{
  wormleaf_sync_sorted(leaf1);
  struct kref kref_new;
  kref_ref_kv(&kref_new, new);
  const u32 is1 = wormleaf_search_ss(leaf1, &kref_new); // new should be inserted at [is1]
  const u32 cut = wormhole_split_cut_search1(leaf1, 0, leaf1->nr_keys, is1, new);
  if (unlikely(cut == WH_KPN2))
    return NULL;

  // anchor of leaf2
  debug_assert(cut && (cut <= leaf1->nr_keys));
  const struct kv * const key1 = wormleaf_kv_at_is1(leaf1, cut - 1, is1, new);
  const struct kv * const key2 = wormleaf_kv_at_is1(leaf1, cut, is1, new);
  struct kv * const anchor2 = wormhole_split_alloc_anchor(key1, key2);
  if (unlikely(anchor2 == NULL)) // anchor alloc failed
    return NULL;

  // create leaf2 with anchor2
  struct wormleaf * const leaf2 = wormleaf_alloc(map, leaf1, leaf1->next, anchor2);
  if (unlikely(leaf2 == NULL)) {
    wormhole_free_akey(anchor2);
    return NULL;
  }

  // split_hmap will unlock the leaf nodes; must move now
  wormhole_split_leaf_move1(leaf1, leaf2, cut, is1, new);
  // leaf1 and leaf2 should be sorted after split
  debug_assert(leaf1->nr_keys == leaf1->nr_sorted);
  debug_assert(leaf2->nr_keys == leaf2->nr_sorted);

  return leaf2;
}
// }}} leaf-split

// leaf-merge {{{
// MERGE is the only operation that deletes a leaf node (leaf2).
// It ALWAYS merges the right node into the left node even if the left is empty.
// This requires both of their writer locks to be acquired.
// This allows iterators to safely probe the next node (but not backwards).
// In other words, if either the reader or the writer lock of node X has been acquired:
// X->next (the pointer) cannot be changed by any other thread.
// X->next cannot be deleted.
// But the content in X->next can still be changed.
  static bool
wormleaf_merge(struct wormleaf * const leaf1, struct wormleaf * const leaf2)
{
  debug_assert((leaf1->nr_keys + leaf2->nr_keys) <= WH_KPN);
  const bool leaf1_sorted = leaf1->nr_keys == leaf1->nr_sorted;

  for (u32 i = 0; i < leaf2->nr_keys; i++)
    wormleaf_insert_e13(leaf1, leaf2->hs[leaf2->ss[i]]);
  if (leaf1_sorted)
    leaf1->nr_sorted += leaf2->nr_sorted;
  return true;
}

// for undoing insertion under split_meta failure; leaf2 is still local
// remove the new key; merge keys in leaf2 into leaf1; free leaf2
  static void
wormleaf_split_undo(struct wormhole * const map, struct wormleaf * const leaf1,
    struct wormleaf * const leaf2, struct kv * const new)
{
  if (new) {
    const struct entry13 e = entry13(wormhole_pkey(new->hashlo), ptr_to_u64(new));
    const u32 im1 = wormleaf_search_ih(leaf1, e);
    if (im1 < WH_KPN) {
      (void)wormleaf_remove_ih(leaf1, im1);
    } else { // not found in leaf1; search leaf2
      const u32 im2 = wormleaf_search_ih(leaf2, e);
      debug_assert(im2 < WH_KPN);
      (void)wormleaf_remove_ih(leaf2, im2);
    }
  }
  // this merge must succeed
  if (!wormleaf_merge(leaf1, leaf2))
    debug_die();
  // Keep this to avoid triggering false alarm in wormleaf_free
  leaf2->leaflock.opaque = 0;
  wormleaf_free(map->slab_leaf, leaf2);
}
// }}} leaf-merge

// get/probe {{{
  struct kv *
wormhole_get(struct wormref * const ref, const struct kref * const key, struct kv * const out)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_read(ref, key);
  const u32 i = wormleaf_match_hs(leaf, key);
  struct kv * const tmp = (i < WH_KPN) ? ref->map->mm.out(wormleaf_kv_at_ih(leaf, i), out) : NULL;
  wormleaf_unlock_read(leaf);
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
  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, key);
  const u32 i = wormleaf_match_hs(leaf, key);
  return (i < WH_KPN) ? map->mm.out(wormleaf_kv_at_ih(leaf, i), out) : NULL;
}

  bool
wormhole_probe(struct wormref * const ref, const struct kref * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_read(ref, key);
  const u32 i = wormleaf_match_hs(leaf, key);
  wormleaf_unlock_read(leaf);
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
  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, key);
  return wormleaf_match_hs(leaf, key) < WH_KPN;
}
// }}} get/probe

// meta-split {{{
// duplicate from meta1; only has one bit but will soon add a new bit
  static struct wormmeta *
wormmeta_expand(struct wormhmap * const hmap, struct wormmeta * const meta1)
{
  struct wormmeta * const meta2 = slab_alloc_unsafe(hmap->slab2);
  if (meta2 == NULL)
    return NULL;

  memcpy(meta2, meta1, sizeof(*meta1));
  for (u32 i = 0; i < WH_BMNR; i++)
    meta2->bitmap[i] = 0;
  const u32 bitmin = wormmeta_bitmin_load(meta1);
  debug_assert(bitmin == wormmeta_bitmax_load(meta1));
  debug_assert(bitmin < WH_FO);
  // set the only bit
  meta2->bitmap[bitmin >> 6u] |= (1lu << (bitmin & 0x3fu));

  wormhmap_replace(hmap, meta1, meta2);
  slab_free_unsafe(hmap->slab1, meta1);
  return meta2;
}

  static struct wormmeta *
wormmeta_bm_set_helper(struct wormhmap * const hmap, struct wormmeta * const meta, const u32 id)
{
  debug_assert(id < WH_FO);
  const u32 bitmin = wormmeta_bitmin_load(meta);
  const u32 bitmax = wormmeta_bitmax_load(meta);
  if (bitmin < bitmax) { // already in full size
    wormmeta_bm_set(meta, id);
    return meta;
  } else if (id == bitmin) { // do nothing
    return meta;
  } else if (bitmin == WH_FO) { // add the first bit
    wormmeta_bitmin_store(meta, id);
    wormmeta_bitmax_store(meta, id);
    return meta;
  } else { // need to expand
    struct wormmeta * const meta2 = wormmeta_expand(hmap, meta);
    wormmeta_bm_set(meta2, id);
    return meta2;
  }
}

// return true if a new node is created
  static void
wormmeta_split_touch(struct wormhmap * const hmap, struct kv * const mkey,
    struct wormleaf * const leaf, const u32 alen)
{
  struct wormmeta * meta = wormhmap_get(hmap, mkey);
  if (meta) {
    if (mkey->klen < alen)
      meta = wormmeta_bm_set_helper(hmap, meta, mkey->kv[mkey->klen]);
    if (wormmeta_lmost_load(meta) == leaf->next)
      wormmeta_lmost_store(meta, leaf);
    else if (wormmeta_rmost_load(meta) == leaf->prev)
      wormmeta_rmost_store(meta, leaf);
  } else { // create new node
    const u32 bit = (mkey->klen < alen) ? mkey->kv[mkey->klen] : WH_FO;
    meta = wormmeta_alloc(hmap, leaf, mkey, alen, bit);
    debug_assert(meta);
    wormhmap_set(hmap, meta);
  }
}

  static void
wormmeta_lpath_update(struct wormhmap * const hmap, const struct kv * const a1, const struct kv * const a2,
    struct wormleaf * const lpath)
{
  struct kv * const pbuf = hmap->pbuf;
  kv_dup2_key(a2, pbuf);

  // only need to update a2's own branch
  u32 i = kv_key_lcp(a1, a2) + 1;
  debug_assert(i <= pbuf->klen);
  wormhole_prefix(pbuf, i);
  while (i < a2->klen) {
    debug_assert(i <= hmap->maxplen);
    struct wormmeta * const meta = wormhmap_get(hmap, pbuf);
    debug_assert(meta);
    wormmeta_lpath_store(meta, lpath);

    i++;
    wormhole_prefix_inc1(pbuf);
  }
}

// for leaf1, a leaf2 is already linked at its right side.
// this function updates the meta-map by moving leaf1 and hooking leaf2 at correct positions
  static void
wormmeta_split(struct wormhmap * const hmap, struct wormleaf * const leaf,
    struct kv * const mkey)
{
  // left branches
  struct wormleaf * const prev = leaf->prev;
  struct wormleaf * const next = leaf->next;
  u32 i = next ? kv_key_lcp(prev->anchor, next->anchor) : 0;
  const u32 alen = leaf->anchor->klen;

  // save klen
  const u32 mklen = mkey->klen;
  wormhole_prefix(mkey, i);
  do {
    wormmeta_split_touch(hmap, mkey, leaf, alen);
    if (i >= alen)
      break;
    i++;
    wormhole_prefix_inc1(mkey);
  } while (true);

  // adjust maxplen; i is the plen of the last _touch()
  if (i > hmap->maxplen)
    hmap->maxplen = i;
  debug_assert(i <= UINT16_MAX);

  // restore klen
  mkey->klen = mklen;

  if (next)
    wormmeta_lpath_update(hmap, leaf->anchor, next->anchor, leaf);
}

// all locks will be released before returning
  static bool
wormhole_split_meta(struct wormref * const ref, struct wormleaf * const leaf2)
{
  struct kv * const mkey = wormhole_alloc_mkey(leaf2->anchor->klen);
  if (unlikely(mkey == NULL))
    return false;
  kv_dup2_key(leaf2->anchor, mkey);

  struct wormhole * const map = ref->map;
  // metalock
  wormhmap_lock(map, ref);

  // check slab reserve
  const bool sr = wormhole_slab_reserve(map, mkey->klen);
  if (unlikely(!sr)) {
    wormhmap_unlock(map);
    wormhole_free_mkey(mkey);
    return false;
  }

  struct wormhmap * const hmap0 = wormhmap_load(map);
  struct wormhmap * const hmap1 = wormhmap_switch(map, hmap0);

  // link
  struct wormleaf * const leaf1 = leaf2->prev;
  leaf1->next = leaf2;
  if (leaf2->next)
    leaf2->next->prev = leaf2;

  // update versions
  const u64 v1 = wormhmap_version_load(hmap0) + 1;
  wormleaf_version_store(leaf1, v1);
  wormleaf_version_store(leaf2, v1);
  wormhmap_version_store(hmap1, v1);

  wormmeta_split(hmap1, leaf2, mkey);

  qsbr_update(&ref->qref, v1);

  // switch hmap
  wormhmap_store(map, hmap1);

  wormleaf_unlock_write(leaf1);
  wormleaf_unlock_write(leaf2);

  qsbr_wait(map->qsbr, v1);

  wormmeta_split(hmap0, leaf2, mkey);

  wormhmap_unlock(map);

  if (mkey->refcnt == 0) // this is possible
    wormhole_free_mkey(mkey);
  return true;
}

// all locks (metalock + leaflocks) will be released before returning
// leaf1->lock (write) is already taken
  static bool
wormhole_split_insert(struct wormref * const ref, struct wormleaf * const leaf1,
    struct kv * const new)
{
  struct wormleaf * const leaf2 = wormhole_split_leaf(ref->map, leaf1, new);
  if (unlikely(leaf2 == NULL)) {
    wormleaf_unlock_write(leaf1);
    return false;
  }

  rwlock_lock_write(&(leaf2->leaflock));
  const bool rsm = wormhole_split_meta(ref, leaf2);
  if (unlikely(!rsm)) {
    // undo insertion & merge; free leaf2
    wormleaf_split_undo(ref->map, leaf1, leaf2, new);
    wormleaf_unlock_write(leaf1);
  }
  return rsm;
}

  static bool
whunsafe_split_meta(struct wormhole * const map, struct wormleaf * const leaf2)
{
  struct kv * const mkey = wormhole_alloc_mkey(leaf2->anchor->klen);
  if (unlikely(mkey == NULL))
    return false;
  kv_dup2_key(leaf2->anchor, mkey);

  const bool sr = wormhole_slab_reserve(map, mkey->klen);
  if (unlikely(!sr)) {
    wormhmap_unlock(map);
    wormhole_free_mkey(mkey);
    return false;
  }

  // link
  leaf2->prev->next = leaf2;
  if (leaf2->next)
    leaf2->next->prev = leaf2;

  for (u32 i = 0; i < 2; i++)
    if (map->hmap2[i].pmap)
      wormmeta_split(&(map->hmap2[i]), leaf2, mkey);
  if (mkey->refcnt == 0) // this is possible
    wormhole_free_mkey(mkey);
  return true;
}

  static bool
whunsafe_split_insert(struct wormhole * const map, struct wormleaf * const leaf1,
    struct kv * const new)
{
  struct wormleaf * const leaf2 = wormhole_split_leaf(map, leaf1, new);
  if (unlikely(leaf2 == NULL))
    return false;

  const bool rsm = whunsafe_split_meta(map, leaf2);
  if (unlikely(!rsm))  // undo insertion, merge, free leaf2
    wormleaf_split_undo(map, leaf1, leaf2, new);

  return rsm;
}
// }}} meta-split

// meta-merge {{{
// now it only contains one bit
  static struct wormmeta *
wormmeta_shrink(struct wormhmap * const hmap, struct wormmeta * const meta2)
{
  debug_assert(wormmeta_bitmin_load(meta2) == wormmeta_bitmax_load(meta2));
  struct wormmeta * const meta1 = slab_alloc_unsafe(hmap->slab1);
  if (meta1 == NULL)
    return NULL;

  memcpy(meta1, meta2, sizeof(*meta1));

  wormhmap_replace(hmap, meta2, meta1);
  slab_free_unsafe(hmap->slab2, meta2);
  return meta1;
}

  static void
wormmeta_bm_clear_helper(struct wormhmap * const hmap, struct wormmeta * const meta, const u32 id)
{
  if (wormmeta_bitmin_load(meta) == wormmeta_bitmax_load(meta)) {
    debug_assert(wormmeta_bitmin_load(meta) < WH_FO);
    wormmeta_bitmin_store(meta, WH_FO);
    wormmeta_bitmax_store(meta, WH_FO);
  } else { // has more than 1 bit
    wormmeta_bm_clear(meta, id);
    if (wormmeta_bitmin_load(meta) == wormmeta_bitmax_load(meta))
      wormmeta_shrink(hmap, meta);
  }
}

// all locks held
  static void
wormmeta_merge(struct wormhmap * const hmap, struct wormleaf * const leaf)
{
  // leaf->next is the new next after merge, which can be NULL
  struct wormleaf * const prev = leaf->prev;
  struct wormleaf * const next = leaf->next;
  struct kv * const pbuf = hmap->pbuf;
  kv_dup2_key(leaf->anchor, pbuf);
  u32 i = (prev && next) ? kv_key_lcp(prev->anchor, next->anchor) : 0;
  const u32 alen = leaf->anchor->klen;
  wormhole_prefix(pbuf, i);
  struct wormmeta * parent = NULL;
  do {
    debug_assert(i <= hmap->maxplen);
    struct wormmeta * meta = wormhmap_get(hmap, pbuf);
    if (wormmeta_lmost_load(meta) == wormmeta_rmost_load(meta)) { // delete single-child
      debug_assert(wormmeta_lmost_load(meta) == leaf);
      const u32 bitmin = wormmeta_bitmin_load(meta);
      wormhmap_del(hmap, meta);
      wormmeta_free(hmap, meta);
      if (parent) {
        wormmeta_bm_clear_helper(hmap, parent, pbuf->kv[i-1]);
        parent = NULL;
      }
      if (bitmin == WH_FO) // no child
        break;
    } else { // adjust lmost rmost
      if (wormmeta_lmost_load(meta) == leaf)
        wormmeta_lmost_store(meta, next);
      else if (wormmeta_rmost_load(meta) == leaf)
        wormmeta_rmost_store(meta, prev);
      parent = meta;
    }

    if (i >= alen)
      break;
    i++;
    wormhole_prefix_inc1(pbuf);
  } while (true);

  if (next)
    wormmeta_lpath_update(hmap, leaf->anchor, next->anchor, prev);
}

// all locks (metalock + two leaflock) will be released before returning
// merge leaf2 to leaf1, removing all metadata to leaf2 and leaf2 itself
  static void
wormhole_meta_merge(struct wormref * const ref, struct wormleaf * const leaf1,
    struct wormleaf * const leaf2, const bool unlock_leaf1)
{
  debug_assert(leaf1->next == leaf2);
  debug_assert(leaf2->prev == leaf1);
  struct wormhole * const map = ref->map;

  wormhmap_lock(map, ref);

  struct wormhmap * const hmap0 = wormhmap_load(map);
  struct wormhmap * const hmap1 = wormhmap_switch(map, hmap0);
  const u64 v1 = wormhmap_version_load(hmap0) + 1;

  leaf1->next = leaf2->next;
  if (leaf2->next)
    leaf2->next->prev = leaf1;

  wormleaf_version_store(leaf1, v1);
  wormleaf_version_store(leaf2, v1);
  wormhmap_version_store(hmap1, v1);

  wormmeta_merge(hmap1, leaf2);

  qsbr_update(&ref->qref, v1);

  // switch hmap
  wormhmap_store(map, hmap1);

  if (unlock_leaf1)
    wormleaf_unlock_write(leaf1);
  wormleaf_unlock_write(leaf2);

  qsbr_wait(map->qsbr, v1);

  wormmeta_merge(hmap0, leaf2);
  // leaf2 is now safe to be removed
  wormleaf_free(map->slab_leaf, leaf2);
  wormhmap_unlock(map);
}

// caller must acquire leaf->wlock and next->wlock
// all locks will be released when this function returns
  static bool
wormhole_meta_leaf_merge(struct wormref * const ref, struct wormleaf * const leaf)
{
  struct wormleaf * const next = leaf->next;
  debug_assert(next);

  // double check
  if ((leaf->nr_keys + next->nr_keys) <= WH_KPN) {
    if (wormleaf_merge(leaf, next)) {
      wormhole_meta_merge(ref, leaf, next, true);
      return true;
    }
  }
  // merge failed but it's fine
  wormleaf_unlock_write(leaf);
  wormleaf_unlock_write(next);
  return false;
}

  static void
whunsafe_meta_leaf_merge(struct wormhole * const map, struct wormleaf * const leaf1,
    struct wormleaf * const leaf2)
{
  debug_assert(leaf1->next == leaf2);
  debug_assert(leaf2->prev == leaf1);
  if (!wormleaf_merge(leaf1, leaf2))
    return;

  leaf1->next = leaf2->next;
  if (leaf2->next)
    leaf2->next->prev = leaf1;
  for (u32 i = 0; i < 2; i++)
    if (map->hmap2[i].pmap)
      wormmeta_merge(&(map->hmap2[i]), leaf2);
  wormleaf_free(map->slab_leaf, leaf2);
}
// }}} meta-merge

// put {{{
  bool
wormhole_put(struct wormref * const ref, struct kv * const kv)
{
  // we always allocate a new item on SET
  // future optimizations may perform in-place update
  struct wormhole * const map = ref->map;
  struct kv * const new = map->mm.in(kv, map->mm.priv);
  if (unlikely(new == NULL))
    return false;
  const struct kref kref = kv_kref(new);

  struct wormleaf * const leaf = wormhole_jump_leaf_write(ref, &kref);
  // update
  const u32 im = wormleaf_match_hs(leaf, &kref);
  if (im < WH_KPN) {
    struct kv * const old = wormleaf_update(leaf, im, new);
    wormleaf_unlock_write(leaf);
    map->mm.free(old, map->mm.priv);
    return true;
  }

  // insert
  if (likely(leaf->nr_keys < WH_KPN)) { // just insert
    wormleaf_insert(leaf, new);
    wormleaf_unlock_write(leaf);
    return true;
  }

  // split_insert changes hmap
  // all locks should be released in wormhole_split_insert()
  const bool rsi = wormhole_split_insert(ref, leaf, new);
  if (!rsi)
    map->mm.free(new, map->mm.priv);
  return rsi;
}

  bool
whsafe_put(struct wormref * const ref, struct kv * const kv)
{
  wormhole_resume(ref);
  const bool r = wormhole_put(ref, kv);
  wormhole_park(ref);
  return r;
}

  bool
whunsafe_put(struct wormhole * const map, struct kv * const kv)
{
  struct kv * const new = map->mm.in(kv, map->mm.priv);
  if (unlikely(new == NULL))
    return false;
  const struct kref kref = kv_kref(new);

  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, &kref);
  // update
  const u32 im = wormleaf_match_hs(leaf, &kref);
  if (im < WH_KPN) { // overwrite
    struct kv * const old = wormleaf_update(leaf, im, new);
    map->mm.free(old, map->mm.priv);
    return true;
  }

  // insert
  if (likely(leaf->nr_keys < WH_KPN)) { // just insert
    wormleaf_insert(leaf, new);
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
  const u32 im = wormleaf_match_hs(leaf, kref);
  if (im < WH_KPN) { // update
    struct kv * const kv0 = wormleaf_kv_at_ih(leaf, im);
    struct kv * const kv = uf(kv0, priv);
    if ((kv == kv0) || (kv == NULL)) { // no replacement
      wormleaf_unlock_write(leaf);
      return true;
    }

    struct kv * const new = map->mm.in(kv, map->mm.priv);
    if (unlikely(new == NULL)) { // mm error
      wormleaf_unlock_write(leaf);
      return false;
    }

    struct kv * const old = wormleaf_update(leaf, im, new);
    wormleaf_unlock_write(leaf);
    map->mm.free(old, map->mm.priv);
    return true;
  }

  struct kv * const kv = uf(NULL, priv);
  if (kv == NULL) { // nothing to be inserted
    wormleaf_unlock_write(leaf);
    return true;
  }

  struct kv * const new = map->mm.in(kv, map->mm.priv);
  if (unlikely(new == NULL)) { // mm error
    wormleaf_unlock_write(leaf);
    return false;
  }

  // insert
  if (likely(leaf->nr_keys < WH_KPN)) { // just insert
    wormleaf_insert(leaf, new);
    wormleaf_unlock_write(leaf);
    return true;
  }

  // split_insert changes hmap
  // all locks should be released in wormhole_split_insert()
  const bool rsi = wormhole_split_insert(ref, leaf, new);
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
  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, kref);
  // update
  const u32 im = wormleaf_match_hs(leaf, kref);
  if (im < WH_KPN) { // update
    struct kv * const kv0 = wormleaf_kv_at_ih(leaf, im);
    struct kv * const kv = uf(kv0, priv);
    if ((kv == kv0) || (kv == NULL))
      return true;

    struct kv * const new = map->mm.in(kv, map->mm.priv);
    if (unlikely(new == NULL))
      return false;

    struct kv * const old = wormleaf_update(leaf, im, new);
    map->mm.free(old, map->mm.priv);
    return true;
  }

  struct kv * const kv = uf(NULL, priv);
  if (kv == NULL) // nothing to be inserted
    return true;

  struct kv * const new = map->mm.in(kv, map->mm.priv);
  if (unlikely(new == NULL)) // mm error
    return false;

  // insert
  if (likely(leaf->nr_keys < WH_KPN)) { // just insert
    wormleaf_insert(leaf, new);
    return true;
  }

  // split_insert changes hmap
  const bool rsi = whunsafe_split_insert(map, leaf, new);
  if (!rsi)
    map->mm.free(new, map->mm.priv);
  return rsi;
}
// }}} put

// inplace {{{
  bool
wormhole_inpr(struct wormref * const ref, const struct kref * const key,
    kv_inp_func uf, void * const priv)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_read(ref, key);
  const u32 im = wormleaf_match_hs(leaf, key);
  if (im < WH_KPN) {
    uf(wormleaf_kv_at_ih(leaf, im), priv);
    wormleaf_unlock_read(leaf);
    return true;
  } else {
    uf(NULL, priv);
    wormleaf_unlock_read(leaf);
    return false;
  }
}

  bool
wormhole_inpw(struct wormref * const ref, const struct kref * const key,
    kv_inp_func uf, void * const priv)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_write(ref, key);
  const u32 im = wormleaf_match_hs(leaf, key);
  if (im < WH_KPN) {
    uf(wormleaf_kv_at_ih(leaf, im), priv);
    wormleaf_unlock_write(leaf);
    return true;
  } else {
    uf(NULL, priv);
    wormleaf_unlock_write(leaf);
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
  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, key);
  const u32 im = wormleaf_match_hs(leaf, key);
  if (im < WH_KPN) { // overwrite
    uf(wormleaf_kv_at_ih(leaf, im), priv);
    return true;
  } else {
    uf(NULL, priv);
    return false;
  }
}
// }}} put

// del {{{
  static void
wormhole_del_try_merge(struct wormref * const ref, struct wormleaf * const leaf)
{
  struct wormleaf * const next = leaf->next;
  if (next && ((leaf->nr_keys == 0) || ((leaf->nr_keys + next->nr_keys) < WH_KPN_MRG))) {
    // try merge, it may fail if size becomes larger after locking
    wormleaf_lock_write(next, ref);
    (void)wormhole_meta_leaf_merge(ref, leaf);
    // locks are already released; immediately return
  } else {
    wormleaf_unlock_write(leaf);
  }
}

  bool
wormhole_del(struct wormref * const ref, const struct kref * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf_write(ref, key);
  const u32 im = wormleaf_match_hs(leaf, key);
  if (im < WH_KPN) { // found
    struct kv * const kv = wormleaf_remove_ih(leaf, im);
    wormhole_del_try_merge(ref, leaf);
    debug_assert(kv);
    // free after releasing locks
    struct wormhole * const map = ref->map;
    map->mm.free(kv, map->mm.priv);
    return true;
  } else {
    wormleaf_unlock_write(leaf);
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
whunsafe_del_try_merge(struct wormhole * const map, struct wormleaf * const leaf)
{
  const u32 n0 = leaf->prev ? leaf->prev->nr_keys : WH_KPN;
  const u32 n1 = leaf->nr_keys;
  const u32 n2 = leaf->next ? leaf->next->nr_keys : WH_KPN;

  if ((leaf->prev && (n1 == 0)) || ((n0 + n1) < WH_KPN_MRG)) {
    whunsafe_meta_leaf_merge(map, leaf->prev, leaf);
  } else if ((leaf->next && (n1 == 0)) || ((n1 + n2) < WH_KPN_MRG)) {
    whunsafe_meta_leaf_merge(map, leaf, leaf->next);
  }
}

  bool
whunsafe_del(struct wormhole * const map, const struct kref * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf(map->hmap, key);
  const u32 im = wormleaf_match_hs(leaf, key);
  if (im < WH_KPN) { // found
    struct kv * const kv = wormleaf_remove_ih(leaf, im);
    debug_assert(kv);

    whunsafe_del_try_merge(map, leaf);
    map->mm.free(kv, map->mm.priv);
    return true;
  }
  return false;
}

  u64
wormhole_delr(struct wormref * const ref, const struct kref * const start,
    const struct kref * const end)
{
  struct wormleaf * const leafa = wormhole_jump_leaf_write(ref, start);
  wormleaf_sync_sorted(leafa);
  const u32 ia = wormleaf_seek(leafa, start);
  const u32 iaz = end ? wormleaf_seek_end(leafa, end) : leafa->nr_keys;
  if (iaz < ia) { // do nothing if end < start
    wormleaf_unlock_write(leafa);
    return 0;
  }
  u64 ndel = iaz - ia;
  struct wormhole * const map = ref->map;
  wormleaf_delete_range(map, leafa, ia, iaz);
  if (leafa->nr_keys > ia) { // end hit; done
    wormhole_del_try_merge(ref, leafa);
    return ndel;
  }

  while (leafa->next) {
    struct wormleaf * const leafx = leafa->next;
    wormleaf_lock_write(leafx, ref);
    // two leaf nodes locked
    wormleaf_sync_sorted(leafx);
    const u32 iz = end ? wormleaf_seek_end(leafx, end) : leafx->nr_keys;
    ndel += iz;
    wormleaf_delete_range(map, leafx, 0, iz);
    if (leafx->nr_keys == 0) { // removed all
      // must hold leaf1's lock for the next iteration
      wormhole_meta_merge(ref, leafa, leafx, false);
    } else { // partially removed; done
      (void)wormhole_meta_leaf_merge(ref, leafa);
      return ndel;
    }
  }
  wormleaf_unlock_write(leafa);
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
  struct wormhmap * const hmap = map->hmap;
  struct wormleaf * const leafa = wormhole_jump_leaf(hmap, start);
  wormleaf_sync_sorted(leafa);
  // last leaf
  struct wormleaf * const leafz = end ? wormhole_jump_leaf(hmap, end) : NULL;

  // select start/end on leafa
  const u32 ia = wormleaf_seek(leafa, start);
  const u32 iaz = end ? wormleaf_seek_end(leafa, end) : leafa->nr_keys;
  if (iaz < ia)
    return 0;

  wormleaf_delete_range(map, leafa, ia, iaz);
  u64 ndel = iaz - ia;

  if (leafa == leafz) { // one node only
    whunsafe_del_try_merge(map, leafa);
    return ndel;
  }

  // 0 or more nodes between leafa and leafz
  while (leafa->next != leafz) {
    struct wormleaf * const leafx = leafa->next;
    ndel += leafx->nr_keys;
    for (u32 i = 0; i < leafx->nr_keys; i++)
      map->mm.free(wormleaf_kv_at_is(leafx, i), map->mm.priv);
    leafx->nr_keys = 0;
    leafx->nr_sorted = 0;
    whunsafe_meta_leaf_merge(map, leafa, leafx);
  }
  // delete the smaller keys in leafz
  if (leafz) {
    wormleaf_sync_sorted(leafz);
    const u32 iz = wormleaf_seek_end(leafz, end);
    wormleaf_delete_range(map, leafz, 0, iz);
    ndel += iz;
    whunsafe_del_try_merge(map, leafa);
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
  if (unlikely(leaf->nr_keys != leaf->nr_sorted)) {
    spinlock_lock(&(leaf->sortlock));
    wormleaf_sync_sorted(leaf);
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
  iter->is = 0;
  return iter;
}

  static void
wormhole_iter_fix(struct wormhole_iter * const iter)
{
  if (!wormhole_iter_valid(iter))
    return;

  while (unlikely(iter->is >= iter->leaf->nr_sorted)) {
    struct wormleaf * const next = iter->leaf->next;
    if (likely(next != NULL)) {
      struct wormref * const ref = iter->ref;
      wormleaf_lock_read(next, ref);
      wormleaf_unlock_read(iter->leaf);

      wormhole_iter_leaf_sync_sorted(next);
    } else {
      wormleaf_unlock_read(iter->leaf);
    }
    iter->leaf = next;
    iter->is = 0;
    if (!wormhole_iter_valid(iter))
      return;
  }
}

  void
wormhole_iter_seek(struct wormhole_iter * const iter, const struct kref * const key)
{
  debug_assert(key);
  if (iter->leaf)
    wormleaf_unlock_read(iter->leaf);

  struct wormleaf * const leaf = wormhole_jump_leaf_read(iter->ref, key);
  wormhole_iter_leaf_sync_sorted(leaf);

  iter->leaf = leaf;
  iter->is = wormleaf_seek(leaf, key);
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
    debug_assert(iter->is < iter->leaf->nr_sorted);
    struct kv * const kv = wormleaf_kv_at_is(iter->leaf, iter->is);
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
wormhole_iter_skip1(struct wormhole_iter * const iter)
{
  if (wormhole_iter_valid(iter)) {
    iter->is++;
    wormhole_iter_fix(iter);
  }
}

  void
wormhole_iter_skip(struct wormhole_iter * const iter, const u32 nr)
{
  u32 todo = nr;
  while (todo && wormhole_iter_valid(iter)) {
    const u32 cap = iter->leaf->nr_sorted - iter->is;
    const u32 nskip = (cap < todo) ? cap : todo;
    iter->is += nskip;
    wormhole_iter_fix(iter);
    todo -= nskip;
  }
}

  struct kv *
wormhole_iter_next(struct wormhole_iter * const iter, struct kv * const out)
{
  struct kv * const ret = wormhole_iter_peek(iter, out);
  wormhole_iter_skip1(iter);
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
    wormleaf_unlock_read(iter->leaf);
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
    wormleaf_unlock_read(iter->leaf);
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
  iter->is = 0;
  whunsafe_iter_seek(iter, kref_null());
  return iter;
}

  static void
whunsafe_iter_fix(struct wormhole_iter * const iter)
{
  if (!wormhole_iter_valid(iter))
    return;

  while (unlikely(iter->is >= iter->leaf->nr_sorted)) {
    struct wormleaf * const next = iter->leaf->next;
    if (likely(next != NULL))
      wormhole_iter_leaf_sync_sorted(next);
    iter->leaf = next;
    iter->is = 0;
    if (!wormhole_iter_valid(iter))
      return;
  }
}

  void
whunsafe_iter_seek(struct wormhole_iter * const iter, const struct kref * const key)
{
  struct wormleaf * const leaf = wormhole_jump_leaf(iter->map->hmap, key);
  wormhole_iter_leaf_sync_sorted(leaf);

  iter->leaf = leaf;
  iter->is = wormleaf_seek(leaf, key);
  whunsafe_iter_fix(iter);
}

  void
whunsafe_iter_skip1(struct wormhole_iter * const iter)
{
  if (wormhole_iter_valid(iter)) {
    iter->is++;
    whunsafe_iter_fix(iter);
  }
}

  void
whunsafe_iter_skip(struct wormhole_iter * const iter, const u32 nr)
{
  u32 todo = nr;
  while (todo && wormhole_iter_valid(iter)) {
    const u32 cap = iter->leaf->nr_sorted - iter->is;
    const u32 nskip = (cap < todo) ? cap : todo;
    iter->is += nskip;
    whunsafe_iter_fix(iter);
    todo -= nskip;
  }
}

  struct kv *
whunsafe_iter_next(struct wormhole_iter * const iter, struct kv * const out)
{
  struct kv * const ret = wormhole_iter_peek(iter, out);
  whunsafe_iter_skip1(iter);
  return ret;
}

  void
whunsafe_iter_destroy(struct wormhole_iter * const iter)
{
  free(iter);
}
// }}} unsafe iter

// misc {{{
  struct wormref *
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

  struct wormref *
whsafe_ref(struct wormhole * const map)
{
  struct wormref * const ref = wormhole_ref(map);
  if (ref)
    wormhole_park(ref);
  return ref;
}

  struct wormhole *
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
  qsbr_update(&(ref->qref), wormhmap_version_load(wormhmap_load(ref->map)));
}

  static void
wormhole_clean_hmap(struct wormhole * const map)
{
  for (u32 x = 0; x < 2; x++) {
    if (map->hmap2[x].pmap == NULL)
      continue;
    struct wormhmap * const hmap = &(map->hmap2[x]);
    const u64 nr_slots = ((u64)(hmap->mask)) + 1;
    struct wormmbkt * const pmap = hmap->pmap;
    for (u64 s = 0; s < nr_slots; s++) {
      struct wormmbkt * const slot = &(pmap[s]);
      for (u32 i = 0; i < WH_BKT_NR; i++)
        if (slot->e[i])
          wormmeta_keyref_release(slot->e[i]);
    }

    slab_free_all(hmap->slab1);
    slab_free_all(hmap->slab2);
    memset(hmap->pmap, 0, hmap->msize);
    hmap->maxplen = 0;
  }
}

  static void
wormhole_free_leaf_keys(struct wormhole * const map, struct wormleaf * const leaf)
{
  const u32 nr = leaf->nr_keys;
  for (u32 i = 0; i < nr; i++) {
    void * const curr = wormleaf_kv_at_is(leaf, i);
    debug_assert(curr);
    map->mm.free(curr, map->mm.priv);
  }
  wormhole_free_akey(leaf->anchor);
}

  static void
wormhole_clean_helper(struct wormhole * const map)
{
  wormhole_clean_hmap(map);
  for (struct wormleaf * leaf = map->leaf0; leaf; leaf = leaf->next)
    wormhole_free_leaf_keys(map, leaf);
  slab_free_all(map->slab_leaf);
  map->leaf0 = NULL;
}

// unsafe
  void
wormhole_clean(struct wormhole * const map)
{
  wormhole_clean_helper(map);
  wormhole_create_leaf0(map);
}

  void
wormhole_destroy(struct wormhole * const map)
{
  wormhole_clean_helper(map);
  for (u32 i = 0; i < 2; i++) {
    struct wormhmap * const hmap = &map->hmap2[i];
    if (hmap->slab1)
      slab_destroy(hmap->slab1);
    if (hmap->slab2)
      slab_destroy(hmap->slab2);
    wormhmap_deinit(hmap);
  }
  qsbr_destroy(map->qsbr);
  slab_destroy(map->slab_leaf);
  free(map->pbuf);
  free(map);
}

  void
wormhole_fprint(struct wormhole * const map, FILE * const out)
{
  const u64 nr_slab_ul = slab_get_nalloc(map->slab_leaf);
  const u64 nr_slab_um11 = slab_get_nalloc(map->hmap2[0].slab1);
  const u64 nr_slab_um12 = slab_get_nalloc(map->hmap2[0].slab2);
  const u64 nr_slab_um21 = map->hmap2[1].slab1 ? slab_get_nalloc(map->hmap2[1].slab1) : 0;
  const u64 nr_slab_um22 = map->hmap2[1].slab2 ? slab_get_nalloc(map->hmap2[1].slab2) : 0;
  fprintf(out, "%s L-SLAB %lu M-SLAB [0] %lu+%lu [1] %lu+%lu\n",
      __func__, nr_slab_ul, nr_slab_um11, nr_slab_um12, nr_slab_um21, nr_slab_um22);
}
// }}} misc

// api {{{
const struct kvmap_api kvmap_api_wormhole = {
  .hashkey = true,
  .ordered = true,
  .threadsafe = true,
  .unique = true,
  .refpark = true,
  .put = (void *)wormhole_put,
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
  .iter_skip1 = (void *)wormhole_iter_skip1,
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
  .put = (void *)whsafe_put,
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
  .iter_skip1 = (void *)wormhole_iter_skip1,
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
  .put = (void *)whunsafe_put,
  .get = (void *)whunsafe_get,
  .probe = (void *)whunsafe_probe,
  .del = (void *)whunsafe_del,
  .inpr = (void *)whunsafe_inp,
  .inpw = (void *)whunsafe_inp,
  .merge = (void *)whunsafe_merge,
  .delr = (void *)whunsafe_delr,
  .iter_create = (void *)whunsafe_iter_create,
  .iter_seek = (void *)whunsafe_iter_seek,
  .iter_valid = (void *)wormhole_iter_valid,
  .iter_peek = (void *)wormhole_iter_peek,
  .iter_kref = (void *)wormhole_iter_kref,
  .iter_kvref = (void *)wormhole_iter_kvref,
  .iter_skip1 = (void *)whunsafe_iter_skip1,
  .iter_skip = (void *)whunsafe_iter_skip,
  .iter_next = (void *)whunsafe_iter_next,
  .iter_inp = (void *)wormhole_iter_inp,
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

// vim:fdm=marker
