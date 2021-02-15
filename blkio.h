/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include "lib.h"

// wring {{{
struct wring;

// iosz: fixed write size; must be a multiple of PGSZ
  extern struct wring *
wring_create(const int fd, const size_t iosz, const u32 depth);

  extern void
wring_update_fd(struct wring * const wring, const int fd);

  extern void
wring_destroy(struct wring * const wring);

  extern void *
wring_acquire(struct wring * const wring);

// write part of the buf
  extern void
wring_write_partial(struct wring * const wring, const size_t off,
    void * const buf, const size_t buf_off, const size_t size);

  extern void
wring_write(struct wring * const wring, const size_t off, void * const buf);

// flush the queue and wait for completion
  extern void
wring_flush(struct wring * const wring);

// send an fsync but does not wait for completion
  extern void
wring_fsync(struct wring * const wring);
// }}} wring

// coq {{{

struct coq;
typedef bool (*cowq_func) (void * priv);

  extern struct coq *
coq_create(void);

  extern void
coq_destroy(struct coq * const coq);

  extern u32
corq_enqueue(struct coq * const q, struct co * const co);

  extern u32
cowq_enqueue(struct coq * const q, cowq_func exec, void * const priv);

  extern void
coq_yield(struct coq * const q);

  extern void
coq_idle(struct coq * const q);

  extern void
coq_run(struct coq * const q);

  extern ssize_t
coq_pread_aio(struct coq * const q, const int fd, void * const buf, const size_t count, const off_t offset);

  extern ssize_t
coq_pwrite_aio(struct coq * const q, const int fd, const void * const buf, const size_t count, const off_t offset);

#if defined(__linux__)
// io_uring-specific
  extern struct io_uring *
coq_uring_create(const u32 depth);

// use ring==NULL in pread_uring and pwrite_uring
  extern struct coq *
coq_uring_create_pair(const u32 depth);

  extern void
coq_uring_destroy(struct io_uring * const ring);

  extern void
coq_uring_destroy_pair(struct coq * const coq);

  extern ssize_t
coq_pread_uring(struct coq * const q, struct io_uring * const ring,
    const int fd, void * const buf, const size_t count, const off_t offset);

  extern ssize_t
coq_pwrite_uring(struct coq * const q, struct io_uring * const ring,
    const int fd, const void * const buf, const size_t count, const off_t offset);
#endif // __linux__

  extern void
coq_install(struct coq * const q);

  extern void
coq_uninstall(void);

  extern struct coq *
coq_current(void);
// }}} coq

// rcache {{{
  extern struct rcache *
rcache_create(const u64 size_mb, const u32 fd_bits);

  extern void
rcache_destroy(struct rcache * const c);

  extern struct coq *
rcache_coq_create(const u32 depth);

  extern void
rcache_coq_destroy(struct coq * const coq);

  extern void
rcache_close_lazy(struct rcache * const c, const int fd);

  extern u64
rcache_close_flush(struct rcache * const c);

  extern void
rcache_close(struct rcache * const c, const int fd);

  extern void *
rcache_acquire(struct rcache * const c, const int fd, const u32 pageid);

  extern void
rcache_retain(struct rcache * const c, const void * const buf);

  extern void
rcache_release(struct rcache * const c, const void * const buf);

  extern u64
rcache_thread_stat_reads(void);
// }}} rcache

#ifdef __cplusplus
}
#endif
// vim:fdm=marker
