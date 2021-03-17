/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#pragma once

// includes {{{
// C headers
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// POSIX headers
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

// Linux headers
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
// }}} includes

#ifdef __cplusplus
extern "C" {
#endif

// types {{{
typedef char            s8;
typedef short           s16;
typedef int             s32;
typedef long            s64;
typedef __int128_t      s128;
static_assert(sizeof(s8) == 1, "sizeof(s8)");
static_assert(sizeof(s16) == 2, "sizeof(s16)");
static_assert(sizeof(s32) == 4, "sizeof(s32)");
static_assert(sizeof(s64) == 8, "sizeof(s64)");
static_assert(sizeof(s128) == 16, "sizeof(s128)");

typedef unsigned char   u8;
typedef unsigned short  u16;
typedef unsigned int    u32;
typedef unsigned long   u64;
typedef __uint128_t     u128;
static_assert(sizeof(u8) == 1, "sizeof(u8)");
static_assert(sizeof(u16) == 2, "sizeof(u16)");
static_assert(sizeof(u32) == 4, "sizeof(u32)");
static_assert(sizeof(u64) == 8, "sizeof(u64)");
static_assert(sizeof(u128) == 16, "sizeof(u128)");
// }}} types

// defs {{{
#define likely(____x____)   __builtin_expect(____x____, 1)
#define unlikely(____x____) __builtin_expect(____x____, 0)

// ansi colors
// 3X:fg; 4X:bg; 9X:light fg; 10X:light bg;
// X can be one of the following colors:
// 0:black;   1:red;     2:green;  3:yellow;
// 4:blue;    5:magenta; 6:cyan;   7:white;
#define TERMCLR(____code____) "\x1b[" #____code____ "m"
// }}} defs

// const {{{
#define PGSZ ((4096lu))
// }}} const

// math {{{
  extern u64
mhash64(const u64 v);

  extern u32
mhash32(const u32 v);

  extern u64
gcd64(u64 a, u64 b);
// }}} math

// random {{{
  extern u64
random_u64(void);

  extern void
srandom_u64(const u64 seed);

  extern double
random_double(void);
// }}} random

// timing {{{
  extern u64
time_nsec(void);

  extern double
time_sec(void);

  extern u64
time_diff_nsec(const u64 last);

  extern double
time_diff_sec(const double last);

  extern void
time_stamp(char * str, const size_t size);

  extern void
time_stamp2(char * str, const size_t size);
// }}} timing

// cpucache {{{
  extern void
cpu_pause(void);

  extern void
cpu_mfence(void);

  extern void
cpu_cfence(void);

  extern void
cpu_prefetch0(const void * const ptr);

  extern void
cpu_prefetch1(const void * const ptr);

  extern void
cpu_prefetch2(const void * const ptr);

  extern void
cpu_prefetch3(const void * const ptr);

  extern void
cpu_prefetchw(const void * const ptr);
// }}} cpucache

// crc32c {{{
  extern u32
crc32c_u8(const u32 crc, const u8 v);

  extern u32
crc32c_u16(const u32 crc, const u16 v);

  extern u32
crc32c_u32(const u32 crc, const u32 v);

  extern u32
crc32c_u64(const u32 crc, const u64 v);

// 1 <= nr <= 3
  extern u32
crc32c_inc_123(const u8 * buf, u32 nr, u32 crc);

// nr % 4 == 0
  extern u32
crc32c_inc_x4(const u8 * buf, u32 nr, u32 crc);

  extern u32
crc32c_inc(const u8 * buf, u32 nr, u32 crc);
// }}} crc32c

// debug {{{
  extern void
debug_break(void);

  extern void
debug_backtrace(void);

  extern void
watch_u64_usr1(u64 * const ptr);

#ifndef NDEBUG
  extern void
debug_assert(const bool v);
#else
#define debug_assert(expr) ((void)0)
#endif

__attribute__((noreturn))
  extern void
debug_die(void);

__attribute__((noreturn))
  extern void
debug_die_perror(void);

  extern void
debug_dump_maps(FILE * const out);

  extern bool
debug_perf_switch(void);
// }}} debug

// mm {{{
#ifdef ALLOCFAIL
  extern bool
alloc_fail(void);
#endif

  extern void *
xalloc(const size_t align, const size_t size);

  extern void *
yalloc(const size_t size);

  extern void **
malloc_2d(const size_t nr, const size_t size);

  extern void **
calloc_2d(const size_t nr, const size_t size);

  extern void
pages_unmap(void * const ptr, const size_t size);

  extern void
pages_lock(void * const ptr, const size_t size);

/* hugepages */
// force posix allocators: -DVALGRIND_MEMCHECK
  extern void *
pages_alloc_4kb(const size_t nr_4kb);

  extern void *
pages_alloc_2mb(const size_t nr_2mb);

  extern void *
pages_alloc_1gb(const size_t nr_1gb);

  extern void *
pages_alloc_best(const size_t size, const bool try_1gb, u64 * const size_out);
// }}} mm

// process/thread {{{
  extern void
thread_get_name(const pthread_t pt, char * const name, const size_t len);

  extern void
thread_set_name(const pthread_t pt, const char * const name);

  extern long
process_get_rss(void);

  extern u32
process_affinity_count(void);

  extern u32
process_getaffinity_list(const u32 max, u32 * const cores);

  extern void
thread_setaffinity_list(const u32 nr, const u32 * const list);

  extern void
thread_pin(const u32 cpu);

  extern u64
process_cpu_time_usec(void);

// if args == true, argx is void **
// if args == false, argx is void *
  extern u64
thread_fork_join(u32 nr, void *(*func) (void *), const bool args, void * const argx);

  extern int
thread_create_at(const u32 cpu, pthread_t * const thread, void *(*start_routine) (void *), void * const arg);
// }}} process/thread

// locking {{{
typedef union {
  u32 opaque;
} spinlock;

  extern void
spinlock_init(spinlock * const lock);

  extern void
spinlock_lock(spinlock * const lock);

  extern bool
spinlock_trylock(spinlock * const lock);

  extern void
spinlock_unlock(spinlock * const lock);

typedef union {
  u32 opaque;
} rwlock;

  extern void
rwlock_init(rwlock * const lock);

  extern bool
rwlock_trylock_read(rwlock * const lock);

// low-priority reader-lock; use with trylock_write_hp
  extern bool
rwlock_trylock_read_lp(rwlock * const lock);

  extern bool
rwlock_trylock_read_nr(rwlock * const lock, u16 nr);

  extern void
rwlock_lock_read(rwlock * const lock);

  extern void
rwlock_unlock_read(rwlock * const lock);

  extern bool
rwlock_trylock_write(rwlock * const lock);

  extern bool
rwlock_trylock_write_nr(rwlock * const lock, u16 nr);

  extern void
rwlock_lock_write(rwlock * const lock);

// writer has higher priority; new readers are blocked
  extern bool
rwlock_trylock_write_hp(rwlock * const lock);

  extern bool
rwlock_trylock_write_hp_nr(rwlock * const lock, u16 nr);

  extern void
rwlock_lock_write_hp(rwlock * const lock);

  extern void
rwlock_unlock_write(rwlock * const lock);

  extern void
rwlock_write_to_read(rwlock * const lock);

typedef union {
  u64 opqaue[8];
} mutex;

  extern void
mutex_init(mutex * const lock);

  extern void
mutex_lock(mutex * const lock);

  extern bool
mutex_trylock(mutex * const lock);

  extern void
mutex_unlock(mutex * const lock);

  extern void
mutex_deinit(mutex * const lock);
// }}} locking

// coroutine {{{
extern u64 co_switch_stack(u64 * const saversp, const u64 newrsp, const u64 retval);

struct co;

  extern struct co *
co_create(const u64 stacksize, void * func, void * priv, u64 * const host);

  extern void
co_reuse(struct co * const co, void * func, void * priv, u64 * const host);

  extern struct co *
co_fork(void * func, void * priv);

  extern void *
co_priv(void);

  extern u64
co_enter(struct co * const to, const u64 retval);

  extern u64
co_switch_to(struct co * const to, const u64 retval);

  extern u64
co_back(const u64 retval);

  extern void
co_exit(const u64 retval);

  extern bool
co_valid(struct co * const co);

  extern struct co *
co_self(void);

  extern void
co_destroy(struct co * const co);

struct corr;

  extern struct corr *
corr_create(const u64 stacksize, void * func, void * priv, u64 * const host);

  extern struct corr *
corr_link(const u64 stacksize, void * func, void * priv, struct corr * const prev);

  extern void
corr_reuse(struct corr * const co, void * func, void * priv, u64 * const host);

  extern void
corr_relink(struct corr * const co, void * func, void * priv, struct corr * const prev);

  extern void
corr_enter(struct corr * const co);

  extern void
corr_yield(void);

  extern void
corr_exit(void);

  extern void
corr_destroy(struct corr * const co);
// }}} coroutine

// bits {{{
  extern u32
bits_reverse_u32(const u32 v);

  extern u64
bits_reverse_u64(const u64 v);

  extern u64
bits_rotl_u64(const u64 v, const u8 n);

  extern u64
bits_rotr_u64(const u64 v, const u8 n);

  extern u32
bits_rotl_u32(const u32 v, const u8 n);

  extern u32
bits_rotr_u32(const u32 v, const u8 n);

  extern u64
bits_p2_up_u64(const u64 v);

  extern u32
bits_p2_up_u32(const u32 v);

  extern u64
bits_p2_down_u64(const u64 v);

  extern u32
bits_p2_down_u32(const u32 v);

  extern u64
bits_round_up(const u64 v, const u8 power);

  extern u64
bits_round_up_a(const u64 v, const u64 a);

  extern u64
bits_round_down(const u64 v, const u8 power);

  extern u64
bits_round_down_a(const u64 v, const u64 a);
// }}} bits

// vi128 {{{
  extern u32
vi128_estimate_u32(const u32 v);

  extern u8 *
vi128_encode_u32(u8 * dst, u32 v);

  extern const u8 *
vi128_decode_u32(const u8 * src, u32 * const out);

  extern u32
vi128_estimate_u64(const u64 v);

  extern u8 *
vi128_encode_u64(u8 * dst, u64 v);

  extern const u8 *
vi128_decode_u64(const u8 * src, u64 * const out);
// }}} vi128

// misc {{{
// TODO: only works on little endian?
struct entry13 { // what a beautiful name
  union {
    u16 e1;
    struct { // easy for debugging
      u64 e1_64:16;
      u64 e3:48;
    };
    u64 v64;
    void * ptr;
  };
};

static_assert(sizeof(struct entry13) == 8, "sizeof(entry13) != 8");

// directly access read .e1 and .e3
// directly write .e1
// use entry13_update() to update the entire entry

  extern struct entry13
entry13(const u16 e1, const u64 e3);

  extern void
entry13_update_e3(struct entry13 * const e, const u64 e3);

  extern void *
u64_to_ptr(const u64 v);

  extern u64
ptr_to_u64(const void * const ptr);

  extern size_t
m_usable_size(void * const ptr);

  extern size_t
fdsize(const int fd);

  extern u32
memlcp(const u8 * const p1, const u8 * const p2, const u32 max);

__attribute__ ((format (printf, 2, 3)))
  extern void
logger_printf(const int fd, const char * const fmt, ...);
// }}} misc

// bitmap {{{
struct bitmap;

  extern struct bitmap *
bitmap_create(const u64 nbits);

  extern void
bitmap_init(struct bitmap * const bm, const u64 nbits);

  extern bool
bitmap_test(const struct bitmap * const bm, const u64 idx);

  extern bool
bitmap_test_all1(struct bitmap * const bm);

  extern bool
bitmap_test_all0(struct bitmap * const bm);

  extern void
bitmap_set1(struct bitmap * const bm, const u64 idx);

  extern void
bitmap_set0(struct bitmap * const bm, const u64 idx);

  extern void
bitmap_set1_safe64(struct bitmap * const bm, const u64 idx);

  extern void
bitmap_set0_safe64(struct bitmap * const bm, const u64 idx);

  extern u64
bitmap_count(struct bitmap * const bm);

  extern u64
bitmap_first(struct bitmap * const bm);

  extern void
bitmap_set_all1(struct bitmap * const bm);

  extern void
bitmap_set_all0(struct bitmap * const bm);
// }}} bitmap

// slab {{{
struct slab;

  extern struct slab *
slab_create(const u64 obj_size, const u64 blk_size);

  extern bool
slab_reserve_unsafe(struct slab * const slab, const u64 nr);

  extern void *
slab_alloc_unsafe(struct slab * const slab);

  extern void *
slab_alloc_safe(struct slab * const slab);

  extern void
slab_free_unsafe(struct slab * const slab, void * const ptr);

  extern void
slab_free_safe(struct slab * const slab, void * const ptr);

  extern void
slab_free_all(struct slab * const slab);

  extern u64
slab_get_nalloc(struct slab * const slab);

  extern void
slab_destroy(struct slab * const slab);
// }}}  slab

// qsort {{{
  extern int
compare_u16(const void * const p1, const void * const p2);

  extern void
qsort_u16(u16 * const array, const size_t nr);

  extern u16 *
bsearch_u16(const u16 v, const u16 * const array, const size_t nr);

  extern void
shuffle_u16(u16 * const array, const u64 nr);

  extern int
compare_u32(const void * const p1, const void * const p2);

  extern void
qsort_u32(u32 * const array, const size_t nr);

  extern u32 *
bsearch_u32(const u32 v, const u32 * const array, const size_t nr);

  extern void
shuffle_u32(u32 * const array, const u64 nr);

  extern int
compare_u64(const void * const p1, const void * const p2);

  extern void
qsort_u64(u64 * const array, const size_t nr);

  extern u64 *
bsearch_u64(const u64 v, const u64 * const array, const size_t nr);

  extern void
shuffle_u64(u64 * const array, const u64 nr);

  extern int
compare_double(const void * const p1, const void * const p2);

  extern void
qsort_double(double * const array, const size_t nr);

  extern void
qsort_u64_sample(const u64 * const array0, const u64 nr, const u64 res, FILE * const out);

  extern void
qsort_double_sample(const double * const array0, const u64 nr, const u64 res, FILE * const out);
// }}} qsort

// xlog {{{
struct xlog;

  extern struct xlog *
xlog_create(const u64 nr_init, const u64 unit_size);

  extern void
xlog_append(struct xlog * const xlog, const void * const rec);

  extern void
xlog_append_cycle(struct xlog * const xlog, const void * const rec);

  extern void
xlog_reset(struct xlog * const xlog);

  extern u64
xlog_read(struct xlog * const xlog, void * const buf, const u64 nr_max);

  extern void
xlog_dump(struct xlog * const xlog, FILE * const out);

  extern void
xlog_destroy(struct xlog * const xlog);

struct xlog_iter;

  extern struct xlog_iter *
xlog_iter_create(const struct xlog * const xlog);

  extern bool
xlog_iter_next(struct xlog_iter * const iter, void * const out);
// free iter after use
// }}} xlog

// string {{{
// XXX strdec_ and strhex_ functions does not append the trailing '\0' to the output string
// size of out should be >= 10
  extern void
strdec_32(void * const out, const u32 v);

// size of out should be >= 20
  extern void
strdec_64(void * const out, const u64 v);

// size of out should be >= 8
  extern void
strhex_32(void * const out, const u32 v);

// size of out should be >= 16
  extern void
strhex_64(void * const out, const u64 v);

  extern u64
a2u64(const void * const str);

  extern u32
a2u32(const void * const str);

  extern s64
a2s64(const void * const str);

  extern s32
a2s32(const void * const str);

  extern void
str_print_hex(FILE * const out, const void * const data, const u32 len);

  extern void
str_print_dec(FILE * const out, const void * const data, const u32 len);

// user should free returned ptr (and nothing else) after use
  extern char **
strtoks(const char * const str, const char * const delim);

  extern u32
strtoks_count(const char * const * const toks);
// }}} string

// qsbr {{{
struct qsbr;
struct qsbr_ref {
#ifdef QSBR_DEBUG
  u64 debug[16];
#endif
  u64 opaque[3];
};

  extern struct qsbr *
qsbr_create(void);

  extern bool
qsbr_register(struct qsbr * const q, struct qsbr_ref * const qref);

  extern void
qsbr_unregister(struct qsbr * const q, struct qsbr_ref * const qref);

  extern void
qsbr_update(struct qsbr_ref * const qref, const u64 v);

  extern void
qsbr_park(struct qsbr_ref * const qref);

  extern void
qsbr_resume(struct qsbr_ref * const qref);

  extern void
qsbr_wait(struct qsbr * const q, const u64 target);

  extern void
qsbr_destroy(struct qsbr * const q);
// }}} qsbr

#ifdef __cplusplus
}
#endif
// vim:fdm=marker
