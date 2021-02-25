/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

// headers {{{
#include "lib.h"
#include "ctypes.h"
#include <assert.h>
#include <execinfo.h>
#include <math.h>
#include <netdb.h>
#include <sched.h>
#include <signal.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <time.h>
#include <malloc.h>  // malloc_usable_size

#if defined(__linux__)
#include <linux/fs.h>
#elif defined(__APPLE__) && defined(__MACH__)
#include <sys/disk.h>
#elif defined(__FreeBSD__)
#include <sys/disk.h>
#endif

#if defined(__FreeBSD__)
#include <pthread_np.h>
#endif
// }}} headers

// math {{{
  inline u64
mhash64(const u64 v)
{
  return v * 11400714819323198485lu;
}

  inline u32
mhash32(const u32 v)
{
  return v * 2654435761u;
}

// From Daniel Lemire's blog (2013, lemire.me)
  u64
gcd64(u64 a, u64 b)
{
  if (a == 0)
    return b;
  if (b == 0)
    return a;

  const u32 shift = (u32)__builtin_ctzl(a | b);
  a >>= __builtin_ctzl(a);
  do {
    b >>= __builtin_ctzl(b);
    if (a > b) {
      const u64 t = b;
      b = a;
      a = t;
    }
    b = b - a;
  } while (b);
  return a << shift;
}
// }}} math

// timing {{{
  inline u64
time_nsec(void)
{
  struct timespec ts;
  // MONO_RAW is 5x to 10x slower than MONO
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ((u64)ts.tv_sec) * 1000000000lu + ((u64)ts.tv_nsec);
}

  inline double
time_sec(void)
{
  const u64 nsec = time_nsec();
  return ((double)nsec) * 1.0e-9;
}

  inline u64
time_diff_nsec(const u64 last)
{
  return time_nsec() - last;
}

  inline double
time_diff_sec(const double last)
{
  return time_sec() - last;
}

// need char str[64]
  inline void
time_stamp(char * str, const size_t size)
{
  time_t now;
  struct tm nowtm;
  time(&now);
  localtime_r(&now, &nowtm);
  strftime(str, size, "%F %T %z", &nowtm);
}

  inline void
time_stamp2(char * str, const size_t size)
{
  time_t now;
  struct tm nowtm;
  time(&now);
  localtime_r(&now, &nowtm);
  strftime(str, size, "%F-%H-%M-%S%z", &nowtm);
}
// }}} timing

// cpucache {{{
  inline void
cpu_pause(void)
{
#if defined(__x86_64__)
  _mm_pause();
#elif defined(__aarch64__)
  // nop
#endif
}

  inline void
cpu_mfence(void)
{
  atomic_thread_fence(MO_SEQ_CST);
}

// compiler fence
  inline void
cpu_cfence(void)
{
  atomic_thread_fence(MO_ACQ_REL);
}

  inline void
cpu_prefetch0(const void * const ptr)
{
  __builtin_prefetch(ptr, 0, 0);
}

  inline void
cpu_prefetch1(const void * const ptr)
{
  __builtin_prefetch(ptr, 0, 1);
}

  inline void
cpu_prefetch2(const void * const ptr)
{
  __builtin_prefetch(ptr, 0, 2);
}

  inline void
cpu_prefetch3(const void * const ptr)
{
  __builtin_prefetch(ptr, 0, 3);
}

  inline void
cpu_prefetchw(const void * const ptr)
{
  __builtin_prefetch(ptr, 1, 0);
}
// }}} cpucache

// crc32c {{{
  inline u32
crc32c_u8(const u32 crc, const u8 v)
{
#if defined(__x86_64__)
  return _mm_crc32_u8(crc, v);
#elif defined(__aarch64__)
  return __crc32cb(crc, v);
#endif
}

  inline u32
crc32c_u16(const u32 crc, const u16 v)
{
#if defined(__x86_64__)
  return _mm_crc32_u16(crc, v);
#elif defined(__aarch64__)
  return __crc32ch(crc, v);
#endif
}

  inline u32
crc32c_u32(const u32 crc, const u32 v)
{
#if defined(__x86_64__)
  return _mm_crc32_u32(crc, v);
#elif defined(__aarch64__)
  return __crc32cw(crc, v);
#endif
}

  inline u32
crc32c_u64(const u32 crc, const u64 v)
{
#if defined(__x86_64__)
  return (u32)_mm_crc32_u64(crc, v);
#elif defined(__aarch64__)
  return (u32)__crc32cd(crc, v);
#endif
}

  inline u32
crc32c_inc_123(const u8 * buf, u32 nr, u32 crc)
{
  if (nr == 1)
    return crc32c_u8(crc, buf[0]);

  crc = crc32c_u16(crc, *(u16 *)buf);
  return (nr == 2) ? crc : crc32c_u8(crc, buf[2]);
}

  inline u32
crc32c_inc_x4(const u8 * buf, u32 nr, u32 crc)
{
  debug_assert((nr & 3) == 0);
#pragma nounroll
  while (nr >= sizeof(u64)) {
    crc = crc32c_u64(crc, *((u64*)buf));
    nr -= sizeof(u64);
    buf += sizeof(u64);
  }
  if (nr)
    crc = crc32c_u32(crc, *((u32*)buf));
  return crc;
}

  inline u32
crc32c_inc(const u8 * buf, u32 nr, u32 crc)
{
#pragma nounroll
  while (nr >= sizeof(u64)) {
    crc = crc32c_u64(crc, *((u64*)buf));
    nr -= sizeof(u64);
    buf += sizeof(u64);
  }
  if (nr >= sizeof(u32)) {
    crc = crc32c_u32(crc, *((u32*)buf));
    nr -= sizeof(u32);
    buf += sizeof(u32);
  }
  return nr ? crc32c_inc_123(buf, nr, crc) : crc;
}
// }}} crc32c

// debug {{{
  void
debug_break(void)
{
  usleep(100);
}

static u64 * debug_watch_u64 = NULL;

  static void
watch_u64_handler(const int sig)
{
  (void)sig;
  const u64 v = debug_watch_u64 ? (*debug_watch_u64) : 0;
  fprintf(stderr, "[USR1] %lu (0x%lx)\n", v, v);
}

  void
watch_u64_usr1(u64 * const ptr)
{
  debug_watch_u64 = ptr;
  struct sigaction sa = {};
  sa.sa_handler = watch_u64_handler;
  sigemptyset(&(sa.sa_mask));
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGUSR1, &sa, NULL) == -1) {
    fprintf(stderr, "Failed to set signal handler for SIGUSR1\n");
  } else {
    fprintf(stderr, "to watch> kill -s SIGUSR1 %d\n", getpid());
  }
}

static void * debug_bt_state = NULL;
#if defined(BACKTRACE) && defined(__linux__)
// TODO: get exec path on MacOS and FreeBSD

#include <backtrace.h>
static char debug_filepath[1024] = {};

  static void
debug_bt_error_cb(void * const data, const char * const msg, const int errnum)
{
  (void)data;
  dprintf(2, "libbacktrace: %s %s\n", msg, strerror(errnum));
}

  static int
debug_bt_print_cb(void * const data, const uintptr_t pc,
    const char * const file, const int lineno, const char * const func)
{
  u32 * const plevel = (typeof(plevel))data;
  if (file || func || lineno) {
    dprintf(2, "[%u]0x%012lx " TERMCLR(35) "%s" TERMCLR(31) ":" TERMCLR(34) "%d" TERMCLR(0)" %s\n",
        *plevel, pc, file ? file : "???", lineno, func ? func : "???");
  } else if (pc) {
    dprintf(2, "[%u]0x%012lx\n", *plevel, pc);
  }
  (*plevel)++;
  return strcmp(func, "main") == 0;
}

__attribute__((constructor))
  static void
debug_backtrace_init(void)
{
  const ssize_t len = readlink("/proc/self/exe", debug_filepath, 1023);
  // disable backtrace
  if (len < 0 || len >= 1023)
    return;

  debug_filepath[len] = '\0';
  debug_bt_state = backtrace_create_state(debug_filepath, 1, debug_bt_error_cb, NULL);
}
#endif // BACKTRACE

  static void
debug_wait_gdb(void * const bt_state)
{
  if (bt_state) {
#if defined(BACKTRACE)
    dprintf(2, "Backtrace :\n");
    u32 level = 0;
    backtrace_full(debug_bt_state, 1, debug_bt_print_cb, debug_bt_error_cb, &level);
#endif // BACKTRACE
  } else { // fallback to execinfo if no backtrace or initialization failed
    void *array[64];
    const int size = backtrace(array, 64);
    dprintf(2, "Backtrace (%d):\n", size - 1);
    backtrace_symbols_fd(array + 1, size - 1, 2);
  }

  abool v = true;
  char timestamp[32];
  time_stamp(timestamp, 32);
  char threadname[32] = {};
  thread_get_name(pthread_self(), threadname, 32);
  strcat(threadname, "(!!)");
  thread_set_name(pthread_self(), threadname);
  char hostname[32];
  gethostname(hostname, 32);

  const char * const pattern = "[Waiting GDB] %1$s %2$s @ %3$s\n"
    "    Attach me: " TERMCLR(31) "sudo -Hi gdb -p %4$d" TERMCLR(0) "\n";
  char buf[256];
  sprintf(buf, pattern, timestamp, threadname, hostname, getpid());
  write(2, buf, strlen(buf));

  // to continue: gdb> set var v = 0
  // to kill from shell: $ kill %pid; kill -CONT %pid

  // uncomment this line to surrender the shell on error
  // kill(getpid(), SIGSTOP); // stop burning cpu, once

#pragma nounroll
  while (atomic_load_explicit(&v, MO_CONSUME))
    sleep(1);
}

#ifndef NDEBUG
  inline void
debug_assert(const bool v)
{
  if (!v)
    debug_wait_gdb(debug_bt_state);
}
#endif

__attribute__((noreturn))
  inline void
debug_die(void)
{
  debug_wait_gdb(debug_bt_state);
  exit(0);
}

__attribute__((noreturn))
  inline void
debug_die_perror(void)
{
  perror(NULL);
  debug_die();
}

#if !defined(NOSIGNAL)
// signal handler for wait_gdb on fatal errors
  static void
wait_gdb_handler(const int sig, siginfo_t * const info, void * const context)
{
  (void)info;
  (void)context;
  char buf[64] = "[SIGNAL] ";
  strcat(buf, strsignal(sig));
  write(2, buf, strlen(buf));
  debug_wait_gdb(NULL);
}

// setup hooks for catching fatal errors
__attribute__((constructor))
  static void
debug_init(void)
{
  void * stack = pages_alloc_4kb(16);
  //fprintf(stderr, "altstack %p\n", stack);
  stack_t ss = {.ss_sp = stack, .ss_flags = 0, .ss_size = PGSZ*16};
  if (sigaltstack(&ss, NULL))
    fprintf(stderr, "sigaltstack failed\n");

  struct sigaction sa = {.sa_sigaction = wait_gdb_handler, .sa_flags = SA_SIGINFO | SA_ONSTACK};
  sigemptyset(&(sa.sa_mask));
  const int fatals[] = {SIGSEGV, SIGFPE, SIGILL, SIGBUS, 0};
  for (int i = 0; fatals[i]; i++) {
    if (sigaction(fatals[i], &sa, NULL) == -1) {
      fprintf(stderr, "Failed to set signal handler for %s\n", strsignal(fatals[i]));
      fflush(stderr);
    }
  }
}

__attribute__((destructor))
  static void
debug_exit(void)
{
  // to get rid of valgrind warnings
  stack_t ss = {.ss_flags = SS_DISABLE};
  stack_t oss = {};
  sigaltstack(&ss, &oss);
  if (oss.ss_sp)
    pages_unmap(oss.ss_sp, PGSZ * 16);
}
#endif // !defined(NOSIGNAL)

  void
debug_dump_maps(FILE * const out)
{
  FILE * const in = fopen("/proc/self/smaps", "r");
  char * line0 = yalloc(1024);
  size_t size0 = 1024;
  while (!feof(in)) {
    const ssize_t r1 = getline(&line0, &size0, in);
    if (r1 < 0) break;
    fprintf(out, "%s", line0);
  }
  fflush(out);
  fclose(in);
}

static pid_t perf_pid = 0;

#if defined(__linux__)
__attribute__((constructor))
  static void
debug_perf_init(void)
{
  const pid_t ppid = getppid();
  char tmp[256] = {};
  sprintf(tmp, "/proc/%d/cmdline", ppid);
  FILE * const fc = fopen(tmp, "r");
  const size_t nr = fread(tmp, 1, sizeof(tmp) - 1, fc);
  fclose(fc);
  // look for "perf record"
  if (nr < 12)
    return;
  tmp[nr] = '\0';
  for (u64 i = 0; i < nr; i++)
    if (tmp[i] == 0)
      tmp[i] = ' ';

  char * const perf = strstr(tmp, "perf record");
  if (perf) {
    fprintf(stderr, "%s: perf detected\n", __func__);
    perf_pid = ppid;
  }
}
#endif

  bool
debug_perf_switch(void)
{
  if (perf_pid > 0) {
    kill(perf_pid, SIGUSR2);
    return true;
  } else {
    return false;
  }
}
// }}} debug

// mm {{{
#ifdef ALLOCFAIL
  bool
alloc_fail(void)
{
#define ALLOCFAIL_RECP ((64lu))
#define ALLOCFAIL_MAGIC ((ALLOCFAIL_RECP / 3lu))
  return ((random_u64() % ALLOCFAIL_RECP) == ALLOCFAIL_MAGIC);
}

#ifdef MALLOCFAIL
extern void * __libc_malloc(size_t size);
  void *
malloc(size_t size)
{
  if (alloc_fail())
    return NULL;
  return __libc_malloc(size);
}

extern void * __libc_calloc(size_t nmemb, size_t size);
  void *
calloc(size_t nmemb, size_t size)
{
  if (alloc_fail())
    return NULL;
  return __libc_calloc(nmemb, size);
}

extern void *__libc_realloc(void *ptr, size_t size);

  void *
realloc(void *ptr, size_t size)
{
  if (alloc_fail())
    return NULL;
  return __libc_realloc(ptr, size);
}
#endif // MALLOC_FAIL
#endif // ALLOC_FAIL

  inline void *
xalloc(const size_t align, const size_t size)
{
#ifdef ALLOCFAIL
  if (alloc_fail())
    return NULL;
#endif
  void * p;
  const int r = posix_memalign(&p, align, size);
  if (r == 0)
    return p;
  else
    return NULL;
}

// alloc cache-line aligned address
  inline void *
yalloc(const size_t size)
{
  return xalloc(64, size);
}

  void **
malloc_2d(const size_t nr, const size_t size)
{
  const size_t size1 = nr * sizeof(void *);
  const size_t size2 = nr * size;
  void ** const mem = malloc(size1 + size2);
  u8 * const mem2 = ((u8 *)mem) + size1;
  for (size_t i = 0; i < nr; i++)
    mem[i] = mem2 + (i * size);
  return mem;
}

  inline void **
calloc_2d(const size_t nr, const size_t size)
{
  void ** const ret = malloc_2d(nr, size);
  memset(ret[0], 0, nr * size);
  return ret;
}

  inline void
pages_unmap(void * const ptr, const size_t size)
{
#ifndef HEAPCHECKING
  munmap(ptr, size);
#else
  (void)size;
  free(ptr);
#endif
}

  void
pages_lock(void * const ptr, const size_t size)
{
  static bool use_mlock = true;
  if (use_mlock) {
    const int ret = mlock(ptr, size);
    if (ret != 0) {
      use_mlock = false;
      fprintf(stderr, "%s: mlock disabled\n", __func__);
    }
  }
}

#ifndef HEAPCHECKING
  static void *
pages_do_alloc(const size_t size, const int flags)
{
  // vi /etc/security/limits.conf
  // * - memlock unlimited
  void * const p = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);
  if (p == MAP_FAILED)
    return NULL;

  pages_lock(p, size);
  return p;
}

#if defined(__linux__)
#define PAGES_FLAGS_1G ((MAP_HUGETLB | (30 << MAP_HUGE_SHIFT)))
#define PAGES_FLAGS_2M ((MAP_HUGETLB | (21 << MAP_HUGE_SHIFT)))
#else
#define PAGES_FLAGS_1G ((0))
#define PAGES_FLAGS_2M ((0))
#endif // __linux__

#endif // HEAPCHECKING

  inline void *
pages_alloc_1gb(const size_t nr_1gb)
{
  const u64 sz = nr_1gb << 30;
#ifndef HEAPCHECKING
  return pages_do_alloc(sz, MAP_PRIVATE | MAP_ANONYMOUS | PAGES_FLAGS_1G);
#else
  void * const p = xalloc(1lu << 21, sz); // Warning: valgrind fails with 30
  if (p)
    memset(p, 0, sz);
  return p;
#endif
}

  inline void *
pages_alloc_2mb(const size_t nr_2mb)
{
  const u64 sz = nr_2mb << 21;
#ifndef HEAPCHECKING
  return pages_do_alloc(sz, MAP_PRIVATE | MAP_ANONYMOUS | PAGES_FLAGS_2M);
#else
  void * const p = xalloc(1lu << 21, sz);
  if (p)
    memset(p, 0, sz);
  return p;
#endif
}

  inline void *
pages_alloc_4kb(const size_t nr_4kb)
{
  const size_t sz = nr_4kb << 12;
#ifndef HEAPCHECKING
  return pages_do_alloc(sz, MAP_PRIVATE | MAP_ANONYMOUS);
#else
  void * const p = xalloc(1lu << 12, sz);
  if (p)
    memset(p, 0, sz);
  return p;
#endif
}

  void *
pages_alloc_best(const size_t size, const bool try_1gb, u64 * const size_out)
{
#ifdef ALLOCFAIL
  if (alloc_fail())
    return NULL;
#endif
  // 1gb huge page: at least 0.25GB
  if (try_1gb) {
    if (size >= (1lu << 28)) {
      const size_t nr_1gb = bits_round_up(size, 30) >> 30;
      void * const p1 = pages_alloc_1gb(nr_1gb);
      if (p1) {
        *size_out = nr_1gb << 30;
        return p1;
      }
    }
  }

  // 2mb huge page: at least 0.5MB
  if (size >= (1lu << 19)) {
    const size_t nr_2mb = bits_round_up(size, 21) >> 21;
    void * const p2 = pages_alloc_2mb(nr_2mb);
    if (p2) {
      *size_out = nr_2mb << 21;
      return p2;
    }
  }

  const size_t nr_4kb = bits_round_up(size, 12) >> 12;
  void * const p3 = pages_alloc_4kb(nr_4kb);
  if (p3)
    *size_out = nr_4kb << 12;
  return p3;
}
// }}} mm

// process/thread {{{
static u32 process_ncpu;
#if defined(__FreeBSD__)
typedef cpuset_t cpu_set_t;
#elif defined(__APPLE__) && defined(__MACH__)
typedef u64 cpu_set_t;
#define CPU_SETSIZE ((64))
#define CPU_COUNT(__cpu_ptr__) (__builtin_popcount(*__cpu_ptr__))
#define CPU_ISSET(__cpu_idx__, __cpu_ptr__) (((*__cpu_ptr__) >> __cpu_idx__) & 1lu)
#define CPU_ZERO(__cpu_ptr__) ((*__cpu_ptr__) = 0)
#define CPU_SET(__cpu_idx__, __cpu_ptr__) ((*__cpu_ptr__) |= (1lu << __cpu_idx__))
#define CPU_CLR(__cpu_idx__, __cpu_ptr__) ((*__cpu_ptr__) &= ~(1lu << __cpu_idx__))
#define pthread_attr_setaffinity_np(...) ((void)0)
#endif

__attribute__((constructor))
  static void
process_init(void)
{
  // Linux's default is 1024 cpus
  process_ncpu = (u32)sysconf(_SC_NPROCESSORS_CONF);
  if (process_ncpu > CPU_SETSIZE) {
    fprintf(stderr, "%s: can use only %zu cores\n",
        __func__, (size_t)CPU_SETSIZE);
    process_ncpu = CPU_SETSIZE;
  }
  thread_set_name(pthread_self(), "main");
}

  static inline int
thread_getaffinity_set(cpu_set_t * const cpuset)
{
#if defined(__linux__)
  return sched_getaffinity(0, sizeof(*cpuset), cpuset);
#elif defined(__FreeBSD__)
  return cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(*cpuset), cpuset);
#elif defined(__APPLE__) && defined(__MACH__)
  *cpuset = (1lu << process_ncpu) - 1;
  return (int)process_ncpu; // TODO
#endif
}

  static inline int
thread_setaffinity_set(const cpu_set_t * const cpuset)
{
#if defined(__linux__)
  return sched_setaffinity(0, sizeof(*cpuset), cpuset);
#elif defined(__FreeBSD__)
  return cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(*cpuset), cpuset);
#elif defined(__APPLE__) && defined(__MACH__)
  (void)cpuset; // TODO
  return 0;
#endif
}

  void
thread_get_name(const pthread_t pt, char * const name, const size_t len)
{
#if defined(__linux__)
  pthread_getname_np(pt, name, len);
#elif defined(__FreeBSD__)
  pthread_get_name_np(pt, name, len);
#elif defined(__APPLE__) && defined(__MACH__)
  (void)pt;
  (void)len;
  strcpy(name, "unknown"); // TODO
#endif
}

  void
thread_set_name(const pthread_t pt, const char * const name)
{
#if defined(__linux__)
  pthread_setname_np(pt, name);
#elif defined(__FreeBSD__)
  pthread_set_name_np(pt, name);
#elif defined(__APPLE__) && defined(__MACH__)
  (void)pt;
  (void)name; // TODO
#endif
}

// kB
  long
process_get_rss(void)
{
  struct rusage rs;
  getrusage(RUSAGE_SELF, &rs);
  return rs.ru_maxrss;
}

  u32
process_affinity_count(void)
{
  cpu_set_t set;
  if (thread_getaffinity_set(&set) != 0)
    return process_ncpu;

  const u32 nr = (u32)CPU_COUNT(&set);
  return nr ? nr : process_ncpu;
}

  u32
process_getaffinity_list(const u32 max, u32 * const cores)
{
  memset(cores, 0, max * sizeof(cores[0]));
  cpu_set_t set;
  if (thread_getaffinity_set(&set) != 0)
    return 0;

  const u32 nr_affinity = (u32)CPU_COUNT(&set);
  const u32 nr = nr_affinity < max ? nr_affinity : max;
  u32 j = 0;
  for (u32 i = 0; i < process_ncpu; i++) {
    if (CPU_ISSET((int)i, &set))
      cores[j++] = i;

    if (j >= nr)
      break;
  }
  return j;
}

  void
thread_setaffinity_list(const u32 nr, const u32 * const list)
{
  cpu_set_t set;
  CPU_ZERO(&set);
  for (u32 i = 0; i < nr; i++)
    if (list[i] < process_ncpu)
      CPU_SET(list[i], &set);
  thread_setaffinity_set(&set);
}

  void
thread_pin(const u32 cpu)
{
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu % process_ncpu, &set);
  thread_setaffinity_set(&set);
}

  u64
process_cpu_time_usec(void)
{
  struct rusage rs;
  getrusage(RUSAGE_SELF, &rs);
  const u64 usr = (((u64)rs.ru_utime.tv_sec) * 1000000lu) + ((u64)rs.ru_utime.tv_usec);
  const u64 sys = (((u64)rs.ru_stime.tv_sec) * 1000000lu) + ((u64)rs.ru_stime.tv_usec);
  return usr + sys;
}

struct fork_join_info {
  u32 total;
  u32 ncores;
  u32 * cores;
  void *(*func)(void *);
  bool args;
  union {
    void * arg1;
    void ** argn;
  };
  au64 ferr;
  au64 jerr;
};

// DON'T CHANGE!
#define FORK_JOIN_RANK_BITS ((16)) // 16
#define FORK_JOIN_MAX ((1u << FORK_JOIN_RANK_BITS))
#define FORK_JOIN_FJI_BITS ((64 - FORK_JOIN_RANK_BITS)) // 48
struct fork_join_priv {
  union {
    struct {
      u64 rank : FORK_JOIN_RANK_BITS; // 16
      u64 fji : FORK_JOIN_FJI_BITS; // 48
    };
    void * ptr;
  };
};
static_assert(sizeof(struct fork_join_priv) == sizeof(void *), "fork_join_priv");

/*
 * fj(6):     T0
 *         /      \
 *       T0        T4
 *     /   \      /
 *    T0   T2    T4
 *   / \   / \   / \
 *  t0 t1 t2 t3 t4 t5
 */

// recursive tree fork-join
  static void *
thread_do_fork_join_worker(void * const ptr)
{
  struct fork_join_priv fjp = {.ptr = ptr};
  // GCC: Without explicitly casting from fjp.fji (a 45-bit u64 value),
  // the high bits will get truncated, which is always CORRECT in gcc.
  // Don't use gcc.
  struct fork_join_info * const fji = (typeof(fji))((u64)(fjp.fji));
  const u32 rank = fjp.rank;

  const u32 nchild = (u32)__builtin_ctz(rank ? rank : bits_p2_up_u32(fji->total));
  debug_assert(nchild <= FORK_JOIN_RANK_BITS);
  pthread_t tids[FORK_JOIN_RANK_BITS];
  if (nchild) {
    cpu_set_t set;
    CPU_ZERO(&set);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    //pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE); // Joinable by default
    // fork top-down
    for (u32 i = nchild - 1; i < nchild; i--) {
      const u32 cr = rank + (1u << i); // child's rank
      if (cr >= fji->total)
        continue; // should not break
      const u32 core = fji->cores[(cr < fji->ncores) ? cr : (cr % fji->ncores)];
      CPU_SET(core, &set);
      pthread_attr_setaffinity_np(&attr, sizeof(set), &set);
      fjp.rank = cr;
      const int r = pthread_create(&tids[i], &attr, thread_do_fork_join_worker, fjp.ptr);
      CPU_CLR(core, &set);
      if (unlikely(r)) { // fork failed
        memset(&tids[0], 0, sizeof(tids[0]) * (i+1));
        u32 nmiss = (1u << (i + 1)) - 1;
        if ((rank + nmiss) >= fji->total)
          nmiss = fji->total - 1 - rank;
        fji->ferr += nmiss;
        break;
      }
    }
    pthread_attr_destroy(&attr);
  }

  char thname0[16];
  char thname1[16];
  thread_get_name(pthread_self(), thname0, 16);
  snprintf(thname1, 16, "%.8s_%u", thname0, rank);
  thread_set_name(pthread_self(), thname1);

  void * const ret = fji->func(fji->args ? fji->argn[rank] : fji->arg1);

  thread_set_name(pthread_self(), thname0);
  // join bottom-up
  for (u32 i = 0; i < nchild; i++) {
    const u32 cr = rank + (1u << i); // child rank
    if (cr >= fji->total)
      break; // safe to break
    if (tids[i]) {
      const int r = pthread_join(tids[i], NULL);
      if (unlikely(r)) { // error
        //fprintf(stderr, "pthread_join %u..%u = %d: %s\n", rank, cr, r, strerror(r));
        fji->jerr++;
      }
    }
  }
  return ret;
}

  u64
thread_fork_join(u32 nr, void *(*func) (void *), const bool args, void * const argx)
{
  if (unlikely(nr > FORK_JOIN_MAX)) {
    fprintf(stderr, "%s reduce nr to %u\n", __func__, FORK_JOIN_MAX);
    nr = FORK_JOIN_MAX;
  }

  u32 cores[CPU_SETSIZE];
  u32 ncores = process_getaffinity_list(process_ncpu, cores);
  if (unlikely(ncores == 0)) { // force to use all cores
    ncores = process_ncpu;
    for (u32 i = 0; i < process_ncpu; i++)
      cores[i] = i;
  }
  if (nr == 0)
    nr = ncores;

  volatile struct fork_join_info fji;
  fji.total = nr;
  fji.cores = cores;
  fji.ncores = ncores;
  fji.func = func;
  fji.args = args;
  fji.arg1 = argx;
  fji.ferr = 0;
  fji.jerr = 0;
  struct fork_join_priv fjp = {.fji = (u64)(&fji), .rank = 0};

  // save current affinity
  cpu_set_t set0;
  thread_getaffinity_set(&set0);

  // master thread shares thread0's core
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(fji.cores[0], &set);
  thread_setaffinity_set(&set);

  const u64 t0 = time_nsec();
  thread_do_fork_join_worker(fjp.ptr);
  const u64 dt = time_diff_nsec(t0);

  // restore original affinity
  thread_setaffinity_set(&set0);
  if (fji.ferr || fji.jerr)
    fprintf(stderr, "%s errors: fork %lu join %lu\n", __func__, fji.ferr, fji.jerr);
  return dt;
}

  int
thread_create_at(const u32 cpu, pthread_t * const thread, void *(*start_routine) (void *), void * const arg)
{
  const u32 cpu_id = cpu % process_ncpu;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  //pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
  cpu_set_t set;

  CPU_ZERO(&set);
  CPU_SET(cpu_id, &set);
  pthread_attr_setaffinity_np(&attr, sizeof(set), &set);
  const int r = pthread_create(thread, &attr, start_routine, arg);
  pthread_attr_destroy(&attr);
  return r;
}
// }}} process/thread

// locking {{{

// spinlock {{{
#if defined(__linux__)
#define SPINLOCK_PTHREAD
#endif // __linux__

#if defined(SPINLOCK_PTHREAD)
static_assert(sizeof(pthread_spinlock_t) <= sizeof(spinlock), "spinlock size");
#else // SPINLOCK_PTHREAD
static_assert(sizeof(au32) <= sizeof(spinlock), "spinlock size");
#endif // SPINLOCK_PTHREAD

  void
spinlock_init(spinlock * const lock)
{
#if defined(SPINLOCK_PTHREAD)
  pthread_spinlock_t * const p = (typeof(p))lock;
  pthread_spin_init(p, PTHREAD_PROCESS_PRIVATE);
#else // SPINLOCK_PTHREAD
  au32 * const p = (typeof(p))lock;
  atomic_store_explicit(p, 0, MO_RELEASE);
#endif // SPINLOCK_PTHREAD
}

  inline void
spinlock_lock(spinlock * const lock)
{
#if defined(CORR)
#pragma nounroll
  while (!spinlock_trylock(lock))
    corr_yield();
#else // CORR
#if defined(SPINLOCK_PTHREAD)
  pthread_spinlock_t * const p = (typeof(p))lock;
  pthread_spin_lock(p); // return value ignored
#else // SPINLOCK_PTHREAD
  au32 * const p = (typeof(p))lock;
#pragma nounroll
  do {
    if (atomic_fetch_sub_explicit(p, 1, MO_ACQUIRE) == 0)
      return;
#pragma nounroll
    do {
      cpu_pause();
    } while (atomic_load_explicit(p, MO_CONSUME));
  } while (true);
#endif // SPINLOCK_PTHREAD
#endif // CORR
}

  inline bool
spinlock_trylock(spinlock * const lock)
{
#if defined(SPINLOCK_PTHREAD)
  pthread_spinlock_t * const p = (typeof(p))lock;
  return !pthread_spin_trylock(p);
#else // SPINLOCK_PTHREAD
  au32 * const p = (typeof(p))lock;
  return atomic_fetch_sub_explicit(p, 1, MO_ACQUIRE) == 0;
#endif // SPINLOCK_PTHREAD
}

  inline void
spinlock_unlock(spinlock * const lock)
{
#if defined(SPINLOCK_PTHREAD)
  pthread_spinlock_t * const p = (typeof(p))lock;
  pthread_spin_unlock(p); // return value ignored
#else // SPINLOCK_PTHREAD
  au32 * const p = (typeof(p))lock;
  atomic_store_explicit(p, 0, MO_RELEASE);
#endif // SPINLOCK_PTHREAD
}
// }}} spinlock

// pthread mutex {{{
static_assert(sizeof(pthread_mutex_t) <= sizeof(mutex), "mutexlock size");
  inline void
mutex_init(mutex * const lock)
{
  pthread_mutex_t * const p = (typeof(p))lock;
  pthread_mutex_init(p, NULL);
}

  inline void
mutex_lock(mutex * const lock)
{
#if defined(CORR)
#pragma nounroll
  while (!mutex_trylock(lock))
    corr_yield();
#else
  pthread_mutex_t * const p = (typeof(p))lock;
  pthread_mutex_lock(p); // return value ignored
#endif
}

  inline bool
mutex_trylock(mutex * const lock)
{
  pthread_mutex_t * const p = (typeof(p))lock;
  return !pthread_mutex_trylock(p); // return value ignored
}

  inline void
mutex_unlock(mutex * const lock)
{
  pthread_mutex_t * const p = (typeof(p))lock;
  pthread_mutex_unlock(p); // return value ignored
}

  inline void
mutex_deinit(mutex * const lock)
{
  pthread_mutex_t * const p = (typeof(p))lock;
  pthread_mutex_destroy(p);
}
// }}} pthread mutex

// rwdep {{{
// poor man's lockdep for rwlock
// per-thread lock list
#ifdef RWDEP
#define RWDEP_NR ((16))
__thread const rwlock * rwdep_readers[RWDEP_NR] = {};
__thread const rwlock * rwdep_writers[RWDEP_NR] = {};

  static void
rwdep_check(const rwlock * const lock)
{
  debug_assert(lock);
  for (u64 i = 0; i < RWDEP_NR; i++) {
    if (rwdep_readers[i] == lock)
      debug_die();
    if (rwdep_writers[i] == lock)
      debug_die();
  }
}
#endif // RWDEP

  static void
rwdep_lock_read(const rwlock * const lock)
{
#ifdef RWDEP
  rwdep_check(lock);
  for (u64 i = 0; i < RWDEP_NR; i++) {
    if (rwdep_readers[i] == NULL) {
      rwdep_readers[i] = lock;
      return;
    }
  }
#else
  (void)lock;
#endif // RWDEP
}

  static void
rwdep_unlock_read(const rwlock * const lock)
{
#ifdef RWDEP
  for (u64 i = 0; i < RWDEP_NR; i++) {
    if (rwdep_readers[i] == lock) {
      rwdep_readers[i] = NULL;
      return;
    }
  }
  debug_die();
#else
  (void)lock;
#endif // RWDEP
}

  static void
rwdep_lock_write(const rwlock * const lock)
{
#ifdef RWDEP
  rwdep_check(lock);
  for (u64 i = 0; i < RWDEP_NR; i++) {
    if (rwdep_writers[i] == NULL) {
      rwdep_writers[i] = lock;
      return;
    }
  }
#else
  (void)lock;
#endif // RWDEP
}

  static void
rwdep_unlock_write(const rwlock * const lock)
{
#ifdef RWDEP
  for (u64 i = 0; i < RWDEP_NR; i++) {
    if (rwdep_writers[i] == lock) {
      rwdep_writers[i] = NULL;
      return;
    }
  }
  debug_die();
#else
  (void)lock;
#endif // RWDEP
}
// }}} rwlockdep

// rwlock {{{
typedef au32 lock_t;
typedef u32 lock_v;
static_assert(sizeof(lock_t) == sizeof(lock_v), "lock size");
static_assert(sizeof(lock_t) <= sizeof(rwlock), "lock size");

#define RWLOCK_WSHIFT ((sizeof(lock_t) * 8 - 1))
#define RWLOCK_WBIT ((((lock_v)1) << RWLOCK_WSHIFT))

  inline void
rwlock_init(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  atomic_store_explicit(pvar, 0, MO_RELEASE);
}

  inline bool
rwlock_trylock_read(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  if ((atomic_fetch_add_explicit(pvar, 1, MO_ACQUIRE) >> RWLOCK_WSHIFT) == 0) {
    rwdep_lock_read(lock);
    return true;
  } else {
    atomic_fetch_sub_explicit(pvar, 1, MO_RELEASE);
    return false;
  }
}

  inline bool
rwlock_trylock_read_lp(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  if (atomic_load_explicit(pvar, MO_CONSUME) >> RWLOCK_WSHIFT) {
    cpu_pause();
    return false;
  }
  return rwlock_trylock_read(lock);
}

// actually nr + 1
  inline bool
rwlock_trylock_read_nr(rwlock * const lock, u16 nr)
{
  lock_t * const pvar = (typeof(pvar))lock;
  if ((atomic_fetch_add_explicit(pvar, 1, MO_ACQUIRE) >> RWLOCK_WSHIFT) == 0) {
    rwdep_lock_read(lock);
    return true;
  }

#pragma nounroll
  do { // someone already locked; wait for a little while
    cpu_pause();
    if ((atomic_load_explicit(pvar, MO_CONSUME) >> RWLOCK_WSHIFT) == 0) {
      rwdep_lock_read(lock);
      return true;
    }
  } while (nr--);

  atomic_fetch_sub_explicit(pvar, 1, MO_RELEASE);
  return false;
}

  inline void
rwlock_lock_read(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
#pragma nounroll
  do {
    if (rwlock_trylock_read(lock))
      return;
#pragma nounroll
    do {
#if defined(CORR)
      corr_yield();
#else
      cpu_pause();
#endif
    } while (atomic_load_explicit(pvar, MO_CONSUME) >> RWLOCK_WSHIFT);
  } while (true);
}

  inline void
rwlock_unlock_read(rwlock * const lock)
{
  rwdep_unlock_read(lock);
  lock_t * const pvar = (typeof(pvar))lock;
  atomic_fetch_sub_explicit(pvar, 1, MO_RELEASE);
}

  inline bool
rwlock_trylock_write(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  lock_v v0 = atomic_load_explicit(pvar, MO_CONSUME);
  if ((v0 == 0) && atomic_compare_exchange_weak_explicit(pvar, &v0, RWLOCK_WBIT, MO_ACQUIRE, MO_RELAXED)) {
    rwdep_lock_write(lock);
    return true;
  } else {
    return false;
  }
}

// actually nr + 1
  inline bool
rwlock_trylock_write_nr(rwlock * const lock, u16 nr)
{
#pragma nounroll
  do {
    if (rwlock_trylock_write(lock))
      return true;
    cpu_pause();
  } while (nr--);
  return false;
}

  inline void
rwlock_lock_write(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
#pragma nounroll
  do {
    if (rwlock_trylock_write(lock))
      return;
#pragma nounroll
    do {
#if defined(CORR)
      corr_yield();
#else
      cpu_pause();
#endif
    } while (atomic_load_explicit(pvar, MO_CONSUME));
  } while (true);
}

  inline bool
rwlock_trylock_write_hp(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  lock_v v0 = atomic_load_explicit(pvar, MO_CONSUME);
  if (v0 >> RWLOCK_WSHIFT)
    return false;

  if (atomic_compare_exchange_weak_explicit(pvar, &v0, v0|RWLOCK_WBIT, MO_ACQUIRE, MO_RELAXED)) {
    rwdep_lock_write(lock);
    // WBIT successfully marked; must wait for readers to leave
    if (v0) { // saw active readers
#pragma nounroll
      while (atomic_load_explicit(pvar, MO_CONSUME) != RWLOCK_WBIT) {
#if defined(CORR)
        corr_yield();
#else
        cpu_pause();
#endif
      }
    }
    return true;
  } else {
    return false;
  }
}

  inline bool
rwlock_trylock_write_hp_nr(rwlock * const lock, u16 nr)
{
#pragma nounroll
  do {
    if (rwlock_trylock_write_hp(lock))
      return true;
    cpu_pause();
  } while (nr--);
  return false;
}

  inline void
rwlock_lock_write_hp(rwlock * const lock)
{
#pragma nounroll
  while (!rwlock_trylock_write_hp(lock)) {
#if defined(CORR)
    corr_yield();
#else
    cpu_pause();
#endif
  }
}

  inline void
rwlock_unlock_write(rwlock * const lock)
{
  rwdep_unlock_write(lock);
  lock_t * const pvar = (typeof(pvar))lock;
  atomic_fetch_sub_explicit(pvar, RWLOCK_WBIT, MO_RELEASE);
}

  inline void
rwlock_write_to_read(rwlock * const lock)
{
  rwdep_unlock_write(lock);
  rwdep_lock_read(lock);
  lock_t * const pvar = (typeof(pvar))lock;
  // +R -W
  atomic_fetch_add_explicit(pvar, ((lock_v)1) - RWLOCK_WBIT, MO_ACQ_REL);
}

#undef RWLOCK_WSHIFT
#undef RWLOCK_WBIT
// }}} rwlock

// }}} locking

// coroutine {{{

// asm {{{
#if defined(__x86_64__)
// number pushes in co_switch_stack
#define CO_CONTEXT_SIZE ((6))

// for switch/exit: pass a return value to the target
asm (
    ".align 16;"
#if defined(__linux__) || defined(__FreeBSD__)
    ".global co_switch_stack;"
    ".type co_switch_stack, @function;"
    "co_switch_stack:"
#elif defined(__APPLE__) && defined(__MACH__)
    ".global _co_switch_stack;"
    "_co_switch_stack:"
#else
#error Supported platforms: Linux/FreeBSD/Apple
#endif // OS
    "push %rbp; push %rbx; push %r12;"
    "push %r13; push %r14; push %r15;"
    "mov  %rsp, (%rdi);"
    "mov  %rsi, %rsp;"
    "pop  %r15; pop  %r14; pop  %r13;"
    "pop  %r12; pop  %rbx; pop  %rbp;"
    "mov  %rdx, %rax;"
    "retq;"
    );

#elif defined(__aarch64__)
// number pushes in co_switch_stack
#define CO_CONTEXT_SIZE ((20))
asm (
    ".align 16;"
#if defined(__linux__) || defined(__FreeBSD__)
    ".global co_switch_stack;"
    ".type co_switch_stack, @function;"
    "co_switch_stack:"
#elif defined(__APPLE__) && defined(__MACH__)
    ".global _co_switch_stack;"
    "_co_switch_stack:"
#else
#error supported platforms: Linux/FreeBSD/Apple
#endif // OS
    "sub  x8, sp, 160;"
    "str  x8, [x0];"
    "stp x30, x19, [x8];      ldp x30, x19, [x1];"
    "stp x20, x21, [x8, 16];  ldp x20, x21, [x1, 16];"
    "stp x22, x23, [x8, 32];  ldp x22, x23, [x1, 32];"
    "stp x24, x25, [x8, 48];  ldp x24, x25, [x1, 48];"
    "stp x26, x27, [x8, 64];  ldp x26, x27, [x1, 64];"
    "stp x28, x29, [x8, 80];  ldp x28, x29, [x1, 80];"
    "stp  d8,  d9, [x8, 96];  ldp  d8,  d9, [x1, 96];"
    "stp d10, d11, [x8, 112]; ldp d10, d11, [x1, 112];"
    "stp d12, d13, [x8, 128]; ldp d12, d13, [x1, 128];"
    "stp d14, d15, [x8, 144]; ldp d14, d15, [x1, 144];"
    "add  sp, x1, 160;"
    "mov  x0, x2;"
    "br  x30;"
    );

extern void co_entry_aarch64(void);
asm (
    ".align 16;"
#if defined(__linux__) || defined(__FreeBSD__)
    ".global co_entry_aarch64;"
    ".type co_entry_aarch64, @function;"
    "co_entry_aarch64:"
#elif defined(__APPLE__) && defined(__MACH__)
    ".global _co_entry_aarch64;"
    "_co_entry_aarch64:"
#else
#error supported platforms: Linux/FreeBSD/Apple
#endif // OS
    "ldr x8, [sp, 0];"
    "blr x8;"
    "ldr x8, [sp, 8];"
    "blr x8;"
    "ldr x8, [sp, 16];"
    "blr x8;"
    );
#else
#error supported CPUs: x86_64 or AArch64
#endif // co_switch_stack x86_64 and aarch64
// }}} asm

// co {{{
struct co {
  u64 rsp;
  void * priv;
  u64 * host; // set host to NULL to exit
  size_t stksz;
};

static __thread struct co * volatile co_curr = NULL; // NULL in host

// the stack sits under the struct co
  static void
co_init(struct co * const co, void * func, void * priv, u64 * const host,
    const u64 stksz, void * func_exit)
{
  debug_assert((stksz & 0x3f) == 0); // a multiple of 64 bytes
  u64 * rsp = ((u64 *)co) - 4;
  rsp[0] = (u64)func;
  rsp[1] = (u64)func_exit;
  rsp[2] = (u64)debug_die;
  rsp[3] = 0;

  rsp -= CO_CONTEXT_SIZE;

#if defined(__aarch64__)
  rsp[0] = (u64)co_entry_aarch64;
#endif

  co->rsp = (u64)rsp;
  co->priv = priv;
  co->host = host;
  co->stksz = stksz;
}

  static void
co_exit0(void)
{
  co_exit(0);
}

  struct co *
co_create(const u64 stacksize, void * func, void * priv, u64 * const host)
{
  const u64 stksz = bits_round_up(stacksize, 6);
  const size_t alloc_size = stksz + sizeof(struct co);
  u8 * const mem = yalloc(alloc_size);
  if (mem == NULL)
    return NULL;

#ifdef CO_STACK_CHECK
  memset(mem, 0x5c, stksz);
#endif // CO_STACK_CHECK

  struct co * const co = (typeof(co))(mem + stksz);
  co_init(co, func, priv, host, stksz, co_exit0);
  return co;
}

  inline void
co_reuse(struct co * const co, void * func, void * priv, u64 * const host)
{
  co_init(co, func, priv, host, co->stksz, co_exit0);
}

  inline struct co *
co_fork(void * func, void * priv)
{
  return co_curr ? co_create(co_curr->stksz, func, priv, co_curr->host) : NULL;
}

  inline void *
co_priv(void)
{
  return co_curr ? co_curr->priv : NULL;
}

// the host calls this to enter a coroutine.
  inline u64
co_enter(struct co * const to, const u64 retval)
{
  debug_assert(co_curr == NULL); // must entry from the host
  debug_assert(to && to->host);
  u64 * const save = to->host;
  co_curr = to;
  const u64 ret = co_switch_stack(save, to->rsp, retval);
  co_curr = NULL;
  return ret;
}

// switch from a coroutine to another coroutine
// co_curr must be valid
// the target will resume and receive the retval
  inline u64
co_switch_to(struct co * const to, const u64 retval)
{
  debug_assert(co_curr);
  debug_assert(co_curr != to);
  debug_assert(to && to->host);
  struct co * const save = co_curr;
  co_curr = to;
  return co_switch_stack(&(save->rsp), to->rsp, retval);
}

// switch from a coroutine to the host routine
// co_yield is now a c++ keyword...
  inline u64
co_back(const u64 retval)
{
  debug_assert(co_curr);
  struct co * const save = co_curr;
  co_curr = NULL;
  return co_switch_stack(&(save->rsp), *(save->host), retval);
}

#ifdef CO_STACK_CHECK
  static void
co_stack_check(const u8 * const mem, const u64 stksz)
{
  const u64 * const mem64 = (typeof(mem64))mem;
  const u64 size64 = stksz / sizeof(u64);
  for (u64 i = 0; i < size64; i++) {
    if (mem64[i] != 0x5c5c5c5c5c5c5c5clu) {
      fprintf(stderr, "%s co stack usage: %lu/%lu\n", __func__, stksz - (i * sizeof(u64)), stksz);
      break;
    }
  }
}
#endif // CO_STACK_CHECK

// return to host and set host to NULL
__attribute__((noreturn))
  void
co_exit(const u64 retval)
{
  debug_assert(co_curr);
#ifdef CO_STACK_CHECK
  const u64 stksz = co_curr->stksz;
  u8 * const mem = ((u8 *)co_curr) - stksz;
  co_stack_check(mem, stksz);
#endif // CO_STACK_CHECK
  const u64 hostrsp = *(co_curr->host);
  co_curr->host = NULL;
  struct co * const save = co_curr;
  co_curr = NULL;
  (void)co_switch_stack(&(save->rsp), hostrsp, retval);
  // return to co_enter
  debug_die();
}

// host is set to NULL on exit
  inline bool
co_valid(struct co * const co)
{
  return co->host != NULL;
}

// return NULL on host
  inline struct co *
co_self(void)
{
  return co_curr;
}

  inline void
co_destroy(struct co * const co)
{
  u8 * const mem = ((u8 *)co) - co->stksz;
  free(mem);
}
// }}} co

// corr {{{
struct corr {
  struct co co;
  struct corr * next;
  struct corr * prev;
};

// initial and link guest to the run-queue
  struct corr *
corr_create(const u64 stacksize, void * func, void * priv, u64 * const host)
{
  const u64 stksz = bits_round_up(stacksize, 6);
  const size_t alloc_size = stksz + sizeof(struct corr);
  u8 * const mem = yalloc(alloc_size);
  if (mem == NULL)
    return NULL;

#ifdef CO_STACK_CHECK
  memset(mem, 0x5c, stksz);
#endif // CO_STACK_CHECK

  struct corr * const co = (typeof(co))(mem + stksz);
  co_init(&(co->co), func, priv, host, stksz, corr_exit);
  co->next = co;
  co->prev = co;
  return co;
}

  struct corr *
corr_link(const u64 stacksize, void * func, void * priv, struct corr * const prev)
{
  const u64 stksz = bits_round_up(stacksize, 6);
  const size_t alloc_size = stksz + sizeof(struct corr);
  u8 * const mem = yalloc(alloc_size);
  if (mem == NULL)
    return NULL;

#ifdef CO_STACK_CHECK
  memset(mem, 0x5c, stksz);
#endif // CO_STACK_CHECK

  struct corr * const co = (typeof(co))(mem + stksz);
  co_init(&(co->co), func, priv, prev->co.host, stksz, corr_exit);
  co->next = prev->next;
  co->prev = prev;
  co->prev->next = co;
  co->next->prev = co;
  return co;
}

  inline void
corr_reuse(struct corr * const co, void * func, void * priv, u64 * const host)
{
  co_init(&(co->co), func, priv, host, co->co.stksz, corr_exit);
  co->next = co;
  co->prev = co;
}

  inline void
corr_relink(struct corr * const co, void * func, void * priv, struct corr * const prev)
{
  co_init(&(co->co), func, priv, prev->co.host, co->co.stksz, corr_exit);
  co->next = prev->next;
  co->prev = prev;
  co->prev->next = co;
  co->next->prev = co;
}

  inline void
corr_enter(struct corr * const co)
{
  (void)co_enter(&(co->co), 0);
}

  inline void
corr_yield(void)
{
  struct corr * const curr = (typeof(curr))co_curr;
  if (curr && (curr->next != curr))
    (void)co_switch_to(&(curr->next->co), 0);
}

__attribute__((noreturn))
  inline void
corr_exit(void)
{
  debug_assert(co_curr);
#ifdef CO_STACK_CHECK
  const u64 stksz = co_curr->stksz;
  const u8 * const mem = ((u8 *)(co_curr)) - stksz;
  co_stack_check(mem, stksz);
#endif // CO_STACK_CHECK

  struct corr * const curr = (typeof(curr))co_curr;
  if (curr->next != curr) { // have more corr
    struct corr * const next = curr->next;
    struct corr * const prev = curr->prev;
    next->prev = prev;
    prev->next = next;
    curr->next = NULL;
    curr->prev = NULL;
    curr->co.host = NULL; // invalidate
    (void)co_switch_to(&(next->co), 0);
  } else { // the last corr
    co_exit0();
  }
  debug_die();
}

  inline void
corr_destroy(struct corr * const co)
{
  co_destroy(&(co->co));
}
// }}} corr

// }}} co

// bits {{{
  inline u32
bits_reverse_u32(const u32 v)
{
  const u32 v2 = __builtin_bswap32(v);
  const u32 v3 = ((v2 & 0xf0f0f0f0u) >> 4) | ((v2 & 0x0f0f0f0fu) << 4);
  const u32 v4 = ((v3 & 0xccccccccu) >> 2) | ((v3 & 0x33333333u) << 2);
  const u32 v5 = ((v4 & 0xaaaaaaaau) >> 1) | ((v4 & 0x55555555u) << 1);
  return v5;
}

  inline u64
bits_reverse_u64(const u64 v)
{
  const u64 v2 = __builtin_bswap64(v);
  const u64 v3 = ((v2 & 0xf0f0f0f0f0f0f0f0lu) >>  4) | ((v2 & 0x0f0f0f0f0f0f0f0flu) <<  4);
  const u64 v4 = ((v3 & 0xcccccccccccccccclu) >>  2) | ((v3 & 0x3333333333333333lu) <<  2);
  const u64 v5 = ((v4 & 0xaaaaaaaaaaaaaaaalu) >>  1) | ((v4 & 0x5555555555555555lu) <<  1);
  return v5;
}

  inline u64
bits_rotl_u64(const u64 v, const u8 n)
{
  const u8 sh = n & 0x3f;
  return (v << sh) | (v >> (64 - sh));
}

  inline u64
bits_rotr_u64(const u64 v, const u8 n)
{
  const u8 sh = n & 0x3f;
  return (v >> sh) | (v << (64 - sh));
}

  inline u32
bits_rotl_u32(const u32 v, const u8 n)
{
  const u8 sh = n & 0x1f;
  return (v << sh) | (v >> (32 - sh));
}

  inline u32
bits_rotr_u32(const u32 v, const u8 n)
{
  const u8 sh = n & 0x1f;
  return (v >> sh) | (v << (32 - sh));
}

  inline u64
bits_p2_up_u64(const u64 v)
{
  // clz(0) is undefined
  return (v > 1) ? (1lu << (64 - __builtin_clzl(v - 1lu))) : v;
}

  inline u32
bits_p2_up_u32(const u32 v)
{
  // clz(0) is undefined
  return (v > 1) ? (1u << (32 - __builtin_clz(v - 1u))) : v;
}

  inline u64
bits_p2_down_u64(const u64 v)
{
  return v ? (1lu << (63 - __builtin_clzl(v))) : v;
}

  inline u32
bits_p2_down_u32(const u32 v)
{
  return v ? (1u << (31 - __builtin_clz(v))) : v;
}

  inline u64
bits_round_up(const u64 v, const u8 power)
{
  return (v + (1lu << power) - 1lu) >> power << power;
}

  inline u64
bits_round_up_a(const u64 v, const u64 a)
{
  return (v + a - 1) / a * a;
}

  inline u64
bits_round_down(const u64 v, const u8 power)
{
  return v >> power << power;
}

  inline u64
bits_round_down_a(const u64 v, const u64 a)
{
  return v / a * a;
}
// }}} bits

// vi128 {{{
#if defined(__GNUC__) && __GNUC__ >= 7
#define FALLTHROUGH __attribute__ ((fallthrough))
#else
#define FALLTHROUGH ((void)0)
#endif /* __GNUC__ >= 7 */

  inline u32
vi128_estimate_u32(const u32 v)
{
  static const u8 t[] = {5,5,5,5,
    4,4,4,4,4,4,4, 3,3,3,3,3,3,3,
    2,2,2,2,2,2,2, 1,1,1,1,1,1,1};
  return v ? t[__builtin_clz(v)] : 2;
  // 0 -> [0x80 0x00] the first byte is non-zero

  // nz bit range -> enc length    offset in t[]
  // 0 -> 2          special case
  // 1 to 7 -> 1     31 to 25
  // 8 to 14 -> 2    24 to 18
  // 15 to 21 -> 3   17 to 11
  // 22 to 28 -> 4   10 to 4
  // 29 to 32 -> 5    3 to 0
}

  u8 *
vi128_encode_u32(u8 * dst, u32 v)
{
  switch (vi128_estimate_u32(v)) {
  case 5:
    *(dst++) = (u8)(v | 0x80); v >>= 7; FALLTHROUGH;
  case 4:
    *(dst++) = (u8)(v | 0x80); v >>= 7; FALLTHROUGH;
  case 3:
    *(dst++) = (u8)(v | 0x80); v >>= 7; FALLTHROUGH;
  case 2:
    *(dst++) = (u8)(v | 0x80); v >>= 7; FALLTHROUGH;
  case 1:
    *(dst++) = (u8)v;
    break;
  default:
    debug_die();
    break;
  }
  return dst;
}

  const u8 *
vi128_decode_u32(const u8 * src, u32 * const out)
{
  debug_assert(*src);
  u32 r = 0;
  for (u32 shift = 0; shift < 32; shift += 7) {
    const u8 byte = *(src++);
    r |= (((u32)(byte & 0x7f)) << shift);
    if ((byte & 0x80) == 0) { // No more bytes to consume
      *out = r;
      return src;
    }
  }
  *out = 0;
  return NULL; // invalid
}

  inline u32
vi128_estimate_u64(const u64 v)
{
  static const u8 t[] = {10,
    9,9,9,9,9,9,9, 8,8,8,8,8,8,8, 7,7,7,7,7,7,7,
    6,6,6,6,6,6,6, 5,5,5,5,5,5,5, 4,4,4,4,4,4,4,
    3,3,3,3,3,3,3, 2,2,2,2,2,2,2, 1,1,1,1,1,1,1};
  return v ? t[__builtin_clzl(v)] : 2;
}

// return ptr after the generated bytes
  u8 *
vi128_encode_u64(u8 * dst, u64 v)
{
  switch (vi128_estimate_u64(v)) {
  case 10:
    *(dst++) = (u8)(v | 0x80); v >>= 7; FALLTHROUGH;
  case 9:
    *(dst++) = (u8)(v | 0x80); v >>= 7; FALLTHROUGH;
  case 8:
    *(dst++) = (u8)(v | 0x80); v >>= 7; FALLTHROUGH;
  case 7:
    *(dst++) = (u8)(v | 0x80); v >>= 7; FALLTHROUGH;
  case 6:
    *(dst++) = (u8)(v | 0x80); v >>= 7; FALLTHROUGH;
  case 5:
    *(dst++) = (u8)(v | 0x80); v >>= 7; FALLTHROUGH;
  case 4:
    *(dst++) = (u8)(v | 0x80); v >>= 7; FALLTHROUGH;
  case 3:
    *(dst++) = (u8)(v | 0x80); v >>= 7; FALLTHROUGH;
  case 2:
    *(dst++) = (u8)(v | 0x80); v >>= 7; FALLTHROUGH;
  case 1:
    *(dst++) = (u8)v;
    break;
  default:
    debug_die();
    break;
  }
  return dst;
}

// return ptr after the consumed bytes
  const u8 *
vi128_decode_u64(const u8 * src, u64 * const out)
{
  u64 r = 0;
  for (u32 shift = 0; shift < 64; shift += 7) {
    const u8 byte = *(src++);
    r |= (((u64)(byte & 0x7f)) << shift);
    if ((byte & 0x80) == 0) { // No more bytes to consume
      *out = r;
      return src;
    }
  }
  *out = 0;
  return NULL; // invalid
}

#undef FALLTHROUGH
// }}} vi128

// misc {{{
  inline void *
u64_to_ptr(const u64 v)
{
  return (void *)v;
}

  inline u64
ptr_to_u64(const void * const ptr)
{
  return (u64)ptr;
}

  inline size_t
fdsize(const int fd)
{
  struct stat st;
  st.st_size = 0;
  if (fstat(fd, &st) != 0)
    return 0;

  if (S_ISBLK(st.st_mode)) {
#if defined(__linux__)
    ioctl(fd, BLKGETSIZE64, &st.st_size);
#elif defined(__APPLE__) && defined(__MACH__)
    u64 blksz = 0;
    u64 nblks = 0;
    ioctl(fd, DKIOCGETBLOCKSIZE, &blksz);
    ioctl(fd, DKIOCGETBLOCKCOUNT, &nblks);
    st.st_size = blksz * nblks;
#elif defined(__FreeBSD__)
    ioctl(fd, DIOCGMEDIASIZE, &st.st_size);
#endif
  }

  return st.st_size;
}

  u32
memlcp(const u8 * p1, const u8 * p2, const u32 max)
{
  const u32 max64 = max >> 3 << 3;
  u32 clen = 0;
  while (clen < max64) {
    const u64 v1 = *(const u64 *)p1;
    const u64 v2 = *(const u64 *)p2;
    if (v1 != v2)
      return clen + (u32)(__builtin_ctzl(v1 ^ v2) >> 3);

    clen += sizeof(u64);
    p1 += sizeof(u64);
    p2 += sizeof(u64);
  }

  if ((clen + sizeof(u32)) <= max) {
    const u32 v1 = *(const u32 *)p1;
    const u32 v2 = *(const u32 *)p2;
    if (v1 != v2)
      return clen + (u32)(__builtin_ctz(v1 ^ v2) >> 3);

    clen += sizeof(u32);
    p1 += sizeof(u32);
    p2 += sizeof(u32);
  }

  while ((clen < max) && (*p1 == *p2)) {
    clen++;
    p1++;
    p2++;
  }
  return clen;
}
// }}} misc

// bitmap {{{
// Partially thread-safe bitmap; call it Eventual Consistency?
struct bitmap {
  u64 nbits;
  u64 nbytes; // must be a multiple of 8
  union {
    u64 ones;
    au64 ones_a;
  };
  u64 bm[0];
};

  inline void
bitmap_init(struct bitmap * const bm, const u64 nbits)
{
  bm->nbits = nbits;
  bm->nbytes = bits_round_up(nbits, 6) >> 3;
  bm->ones = 0;
  bitmap_set_all0(bm);
}

  inline struct bitmap *
bitmap_create(const u64 nbits)
{
  const u64 nbytes = bits_round_up(nbits, 6) >> 3;
  struct bitmap * const bm = malloc(sizeof(*bm) + nbytes);
  bitmap_init(bm, nbits);
  return bm;
}

  static inline bool
bitmap_test_internal(const struct bitmap * const bm, const u64 idx)
{
  return (bm->bm[idx >> 6] & (1lu << (idx & 0x3flu))) != 0;
}

  inline bool
bitmap_test(const struct bitmap * const bm, const u64 idx)
{
  return (idx < bm->nbits) && bitmap_test_internal(bm, idx);
}

  inline bool
bitmap_test_all1(struct bitmap * const bm)
{
  return bm->ones == bm->nbits;
}

  inline bool
bitmap_test_all0(struct bitmap * const bm)
{
  return bm->ones == 0;
}

  inline void
bitmap_set1(struct bitmap * const bm, const u64 idx)
{
  if ((idx < bm->nbits) && !bitmap_test_internal(bm, idx)) {
    debug_assert(bm->ones < bm->nbits);
    bm->bm[idx >> 6] |= (1lu << (idx & 0x3flu));
    bm->ones++;
  }
}

  inline void
bitmap_set0(struct bitmap * const bm, const u64 idx)
{
  if ((idx < bm->nbits) && bitmap_test_internal(bm, idx)) {
    debug_assert(bm->ones && (bm->ones <= bm->nbits));
    bm->bm[idx >> 6] &= ~(1lu << (idx & 0x3flu));
    bm->ones--;
  }
}

// for ht: each thread has exclusive access to a 64-bit range but updates concurrently
// use atomic +/- to update bm->ones_a
  inline void
bitmap_set1_safe64(struct bitmap * const bm, const u64 idx)
{
  if ((idx < bm->nbits) && !bitmap_test_internal(bm, idx)) {
    debug_assert(bm->ones < bm->nbits);
    bm->bm[idx >> 6] |= (1lu << (idx & 0x3flu));
    (void)atomic_fetch_add_explicit(&bm->ones_a, 1, MO_RELAXED);
  }
}

  inline void
bitmap_set0_safe64(struct bitmap * const bm, const u64 idx)
{
  if ((idx < bm->nbits) && bitmap_test_internal(bm, idx)) {
    debug_assert(bm->ones && (bm->ones <= bm->nbits));
    bm->bm[idx >> 6] &= ~(1lu << (idx & 0x3flu));
    (void)atomic_fetch_sub_explicit(&bm->ones_a, 1, MO_RELAXED);
  }
}

  inline u64
bitmap_count(struct bitmap * const bm)
{
  return bm->ones;
}

  inline u64
bitmap_first(struct bitmap * const bm)
{
  for (u64 i = 0; (i << 6) < bm->nbits; i++) {
    if (bm->bm[i])
      return (i << 6) + __builtin_ctzl(bm->bm[i]);
  }
  debug_die();
}

  inline void
bitmap_set_all1(struct bitmap * const bm)
{
  memset(bm->bm, 0xff, bm->nbytes);
  bm->ones = bm->nbits;
}

  inline void
bitmap_set_all0(struct bitmap * const bm)
{
  memset(bm->bm, 0, bm->nbytes);
  bm->ones = 0;
}
// }}} bitmap

// bloom filter {{{
struct bf {
  u64 nr_probe;
  struct bitmap bitmap;
};

  struct bf *
bf_create(const u64 bpk, const u64 nkeys)
{
  const u64 nbits = bpk * nkeys;
  struct bf * const bf = malloc(sizeof(*bf) + (bits_round_up(nbits, 6) >> 3));
  bf->nr_probe = (u64)(log(2.0) * (double)bpk);
  bitmap_init(&(bf->bitmap), nbits);
  return bf;
}

  static inline u64
bf_inc(const u64 hash)
{
  return bits_rotl_u64(hash, 17);
}

  void
bf_add(struct bf * const bf, u64 hash64)
{
  u64 t = hash64;
  const u64 inc = bf_inc(hash64);
  const u64 bits = bf->bitmap.nbits;
  for (u64 i = 0; i < bf->nr_probe; i++) {
    bitmap_set1(&(bf->bitmap), t % bits);
    t += inc;
  }
}

  bool
bf_test(const struct bf * const bf, u64 hash64)
{
  u64 t = hash64;
  const u64 inc = bf_inc(hash64);
  const u64 bits = bf->bitmap.nbits;
  for (u64 i = 0; i < bf->nr_probe; i++) {
    if (!bitmap_test(&(bf->bitmap), t % bits))
      return false;
    t += inc;
  }
  return true;
}

  void
bf_clean(struct bf * const bf)
{
  bitmap_set_all0(&(bf->bitmap));
}

  void
bf_destroy(struct bf * const bf)
{
  free(bf);
}
// }}} bloom filter

// oalloc {{{
struct oalloc {
  union {
    void * mem;
    void ** ptr;
  };
  size_t blksz;
  size_t curr;
};

  struct oalloc *
oalloc_create(const size_t blksz)
{
  struct oalloc * const o = malloc(sizeof(*o));
  o->mem = malloc(blksz);
  o->blksz = blksz;
  *(o->ptr) = NULL;
  o->curr = sizeof(void *);
  return o;
}

  void *
oalloc_alloc(struct oalloc * const o, const size_t size)
{
  if ((o->curr + size) <= o->blksz) {
    void * ret = ((u8 *)o->mem) + o->curr;
    o->curr += size;
    return ret;
  }

  // too large
  if ((size + sizeof(void *)) > o->blksz)
    return NULL;

  // need more core
  void ** const newmem = malloc(o->blksz);
  *newmem = o->mem;
  o->ptr = newmem;
  o->curr = sizeof(void *);
  return oalloc_alloc(o, size);
}

  void
oalloc_destroy(struct oalloc * const o)
{
  while (o->mem) {
    void * const next = *(o->ptr);
    free(o->mem);
    o->mem = next;
  }
  free(o);
}
// }}} oalloc

// astk {{{
// atomic stack
struct acell { struct acell * next; };

// extract ptr from m value
  static inline struct acell *
astk_ptr(const u64 m)
{
  return (struct acell *)(m >> 16);
}

// calculate the new magic
  static inline u64
astk_m1(const u64 m0, struct acell * const ptr)
{
  return ((m0 + 1) & 0xfffflu) | (((u64)ptr) << 16);
}

// calculate the new magic
  static inline u64
astk_m1_unsafe(struct acell * const ptr)
{
  return ((u64)ptr) << 16;
}

  static bool
astk_try_push(au64 * const pmagic, struct acell * const first, struct acell * const last)
{
  u64 m0 = atomic_load_explicit(pmagic, MO_CONSUME);
  last->next = astk_ptr(m0);
  const u64 m1 = astk_m1(m0, first);
  return atomic_compare_exchange_weak_explicit(pmagic, &m0, m1, MO_RELEASE, MO_RELAXED);
}

  static void
astk_push_safe(au64 * const pmagic, struct acell * const first, struct acell * const last)
{
  while (!astk_try_push(pmagic, first, last));
}

  static void
astk_push_unsafe(au64 * const pmagic, struct acell * const first,
    struct acell * const last)
{
  const u64 m0 = atomic_load_explicit(pmagic, MO_CONSUME);
  last->next = astk_ptr(m0);
  const u64 m1 = astk_m1_unsafe(first);
  atomic_store_explicit(pmagic, m1, MO_RELAXED);
}

// can fail for two reasons: (1) NULL: no available object; (2) ~0lu: contention
  static void *
astk_try_pop(au64 * const pmagic)
{
  u64 m0 = atomic_load_explicit(pmagic, MO_CONSUME);
  struct acell * const ret = astk_ptr(m0);
  if (ret == NULL)
    return NULL;

  const u64 m1 = astk_m1(m0, ret->next);
  if (atomic_compare_exchange_weak_explicit(pmagic, &m0, m1, MO_ACQUIRE, MO_RELAXED))
    return ret;
  else
    return (void *)(~0lu);
}

  static void *
astk_pop_safe(au64 * const pmagic)
{
  do {
    u64 m0 = atomic_load_explicit(pmagic, MO_CONSUME);
    struct acell * const ret = astk_ptr(m0);
    if (ret == NULL)
      return NULL;

    const u64 m1 = astk_m1(m0, ret->next);
    if (atomic_compare_exchange_weak_explicit(pmagic, &m0, m1, MO_ACQUIRE, MO_RELAXED))
      return ret;
  } while (true);
}

  static void *
astk_pop_unsafe(au64 * const pmagic)
{
  const u64 m0 = atomic_load_explicit(pmagic, MO_CONSUME);
  struct acell * const ret = astk_ptr(m0);
  if (ret == NULL)
    return NULL;

  const u64 m1 = astk_m1_unsafe(ret->next);
  atomic_store_explicit(pmagic, m1, MO_RELAXED);
  return (void *)ret;
}
// }}} astk

// slab {{{
#define SLAB_OBJ0_OFFSET ((64))
struct slab {
  au64 magic; // hi 48: ptr, lo 16: seq
  u64 padding1[7];

  // 2nd line
  struct acell * blk_head; // list of all blocks
  u64 nalloc; // UNSAFE!
  u64 nready; // UNSAFE!
  u64 obj_size; // const: aligned size of each object
  u64 blk_size; // const: size of each memory block
  u64 objs_per_slab; // const: number of objects in a slab
  u64 obj0_offset; // offset of the first object in a block
  u64 padding;

  // 3rd line
  mutex lock;
};

  static void
slab_add_block(struct slab * const slab, struct acell * const blk, const bool safe)
{
  blk->next = slab->blk_head;
  slab->blk_head = blk;

  u8 * const base = ((u8 *)blk) + slab->obj0_offset;
  struct acell * iter = (typeof(iter))base; // [0]
  for (u64 i = 1; i < slab->objs_per_slab; i++) {
    struct acell * const next = (typeof(next))(base + (i * slab->obj_size));
    iter->next = next;
    iter = next;
  }
  // base points to the first block; iter points to the last block
  if (safe) {
    astk_push_safe(&slab->magic, (struct acell *)base, iter);
  } else { // unsafe
    astk_push_unsafe(&slab->magic, (struct acell *)base, iter);
    slab->nready += slab->objs_per_slab;
  }
}

  static bool
slab_expand(struct slab * const slab, const bool safe)
{
  size_t blk_size;
  struct acell * const blk = pages_alloc_best(slab->blk_size, true, &blk_size);
  (void)blk_size;
  if (blk == NULL)
    return false;

  slab_add_block(slab, blk, safe);
  return true;
}

  struct slab *
slab_create(const u64 obj_size, const u64 blk_size)
{
  // obj must be non-zero and 8-byte aligned
  // blk must be at least of page size and power of 2
  if ((!obj_size) || (obj_size % 8lu) || (blk_size < 4096lu) || (blk_size & (blk_size - 1)))
    return NULL;

  // each slab should have at least one object
  const u64 obj0_offset = (obj_size & (obj_size - 1)) ? SLAB_OBJ0_OFFSET : obj_size;
  if (obj0_offset >= blk_size || (blk_size - obj0_offset) < obj_size)
    return NULL;

  struct slab * const slab = yalloc(sizeof(*slab));
  if (slab == NULL)
    return NULL;

  slab->magic = 0;
  slab->blk_head = NULL;
  slab->nalloc = 0;
  slab->nready = 0;

  // const
  slab->obj_size = obj_size;
  slab->blk_size = blk_size;
  slab->objs_per_slab = (blk_size - obj0_offset) / obj_size;
  debug_assert(slab->objs_per_slab); // >= 1
  slab->obj0_offset = obj0_offset;

  mutex_init(&(slab->lock));
  return slab;
}

// unsafe
  bool
slab_reserve_unsafe(struct slab * const slab, const u64 nr)
{
  while (slab->nready < nr)
    if (!slab_expand(slab, false))
      return false;
  return true;
}

  void *
slab_alloc_unsafe(struct slab * const slab)
{
  void * ret = astk_pop_unsafe(&slab->magic);
  if (ret == NULL) {
    if (!slab_expand(slab, false))
      return NULL;
    ret = astk_pop_unsafe(&slab->magic);
  }
  debug_assert(ret);
  slab->nready--;
  slab->nalloc++;
  return ret;
}

  void *
slab_alloc_safe(struct slab * const slab)
{
  void * ret = astk_pop_safe(&slab->magic);
  if (ret)
    return ret;

  mutex_lock(&slab->lock);
  do {
    ret = astk_pop_safe(&slab->magic); // may already have new objs
    if (ret)
      break;
    if (!slab_expand(slab, true))
      break;
  } while (true);
  mutex_unlock(&slab->lock);
  return ret;
}

  void
slab_free_unsafe(struct slab * const slab, void * const ptr)
{
  debug_assert(ptr);
  astk_push_unsafe(&slab->magic, ptr, ptr);
  slab->nready++;
  slab->nalloc--;
}

  void
slab_free_safe(struct slab * const slab, void * const ptr)
{
  astk_push_safe(&slab->magic, ptr, ptr);
}

// unsafe
  void
slab_free_all(struct slab * const slab)
{
  struct acell * iter = slab->blk_head;
  slab->magic = 0;
  slab->blk_head = NULL;
  slab->nalloc = 0;
  slab->nready = 0;
  while (iter) {
    struct acell * const next = iter->next;
    slab_add_block(slab, iter, false);
    iter = next;
  }
}

// unsafe
  inline u64
slab_get_nalloc(struct slab * const slab)
{
  return slab->nalloc;
}

// unsafe
  inline u64
slab_get_nready(struct slab * const slab)
{
  return slab->nready;
}

  void
slab_destroy(struct slab * const slab)
{
  if (slab == NULL)
    return;
  struct acell * iter = slab->blk_head;
  while (iter) {
    struct acell * const next = iter->next;
    pages_unmap(iter, slab->blk_size);
    iter = next;
  }
  free(slab);
}
// }}} slab

// mpool {{{
#define MPOOL_RANKS ((128lu))
#define MPOOL_SHARDS ((8lu))
#define MPOOL_SHARD_MASK ((MPOOL_SHARDS - 1lu))

struct mpool {
  au64 vec[MPOOL_RANKS][MPOOL_SHARDS][8]; // only use vec[x][y][0]
};

static __thread u64 mpool_seq = 0;

  struct mpool *
mpool_create(void)
{
  size_t memsz;
  struct mpool * const ret = pages_alloc_best(sizeof(*ret), false, &memsz);
  if (ret == NULL)
    return NULL;

  debug_assert(memsz == sizeof(*ret));
  return ret;
}

  void
mpool_destroy(struct mpool * const mp)
{
  for (u64 i = 0; i < MPOOL_RANKS; i++) {
    for (u64 j = 0; j < MPOOL_SHARDS; j++) {
      au64 * const pmagic = mp->vec[i][j];
      for (void * ptr = astk_pop_unsafe(pmagic); ptr; ptr = astk_pop_unsafe(pmagic))
        free(ptr);
    }
  }
  pages_unmap(mp, sizeof(*mp));
}

  static size_t
mpool_rank(const size_t sz)
{
  // 0 -> large number
  // 1..8 -> 0
  // 9..16 -> 1
  // 1017..1024 -> 127
  // 1025..1032 -> 128
  return (sz - 1) >> 3;
}

  void *
mpool_alloc(struct mpool * const mp, const size_t sz)
{
  const size_t rank = mpool_rank(sz);
  if (rank < MPOOL_RANKS) {
    void * const ret = astk_try_pop(mp->vec[rank][mpool_seq]);
    if (ret) {
      if (~(u64)ret) { // success
        return ret;
      } else { // contention
        mpool_seq = (mpool_seq + 1) & MPOOL_SHARD_MASK;
      }
    }
  }
  return malloc(sz);
}

  static size_t
mpool_usize(void * const ptr)
{
  const size_t sz = malloc_usable_size(ptr);
#ifdef HEAPCHECKING
  // valgrind and asan may return unaligned usable size
  const size_t rsz = sz & (~7lu);
#else // HEAPCHECKING
  const size_t rsz = sz;
#endif // HEAPCHECKING

  debug_assert((rsz & 0x7lu) == 0);
  return rsz;
}

  void
mpool_free(struct mpool * const mp, void * const ptr)
{
  const size_t rsz = mpool_usize(ptr);
  const size_t rank = mpool_rank(rsz);

  if (rank < MPOOL_RANKS) {
    if (astk_try_push(mp->vec[rank][mpool_seq], ptr, ptr))
      return;
    else
      mpool_seq = (mpool_seq + 1) & MPOOL_SHARD_MASK;
  }
  free(ptr);
}
// }}} mpool

// qsort {{{
  int
compare_u16(const void * const p1, const void * const p2)
{
  const u16 v1 = *((const u16 *)p1);
  const u16 v2 = *((const u16 *)p2);
  return (int)((s16)(v1 - v2));
}

  inline void
qsort_u16(u16 * const array, const size_t nr)
{
  qsort(array, nr, sizeof(array[0]), compare_u16);
}

  inline u16 *
bsearch_u16(const u16 v, const u16 * const array, const size_t nr)
{
  return (u16 *)bsearch(&v, array, nr, sizeof(u16), compare_u16);
}

  void
shuffle_u16(u16 * const array, const u64 nr)
{
  u64 i = nr - 1; // i from nr-1 to 1
  do {
    const u64 j = random_u64() % i; // j < i
    const u16 t = array[j];
    array[j] = array[i];
    array[i] = t;
  } while (--i);
}

  int
compare_u32(const void * const p1, const void * const p2)
{
  const u32 v1 = *((const u32 *)p1);
  const u32 v2 = *((const u32 *)p2);
  return (int)(v1 - v2);
}

  inline void
qsort_u32(u32 * const array, const size_t nr)
{
  qsort(array, nr, sizeof(array[0]), compare_u32);
}

  inline u32 *
bsearch_u32(const u32 v, const u32 * const array, const size_t nr)
{
  return (u32 *)bsearch(&v, array, nr, sizeof(u32), compare_u32);
}

  void
shuffle_u32(u32 * const array, const u64 nr)
{
  u64 i = nr - 1; // i from nr-1 to 1
  do {
    const u64 j = random_u64() % i; // j < i
    const u32 t = array[j];
    array[j] = array[i];
    array[i] = t;
  } while (--i);
}

  int
compare_u64(const void * const p1, const void * const p2)
{
  const u64 v1 = *((const u64 *)p1);
  const u64 v2 = *((const u64 *)p2);
  const u64 diff = v1 - v2;
  const int ret = ((int)(diff >> 32)) | __builtin_popcountl(diff);
  return ret;
}

  inline void
qsort_u64(u64 * const array, const size_t nr)
{
  qsort(array, nr, sizeof(array[0]), compare_u64);
}

  inline u64 *
bsearch_u64(const u64 v, const u64 * const array, const size_t nr)
{
  return (u64 *)bsearch(&v, array, nr, sizeof(u64), compare_u64);
}

  void
shuffle_u64(u64 * const array, const u64 nr)
{
  u64 i = nr - 1; // i from nr-1 to 1
  do {
    const u64 j = random_u64() % i; // j < i
    const u64 t = array[j];
    array[j] = array[i];
    array[i] = t;
  } while (--i);
}

  int
compare_double(const void * const p1, const void * const p2)
{
  const double v1 = *((const double *)p1);
  const double v2 = *((const double *)p2);
  if (v1 < v2)
    return -1;
  else if (v1 > v2)
    return 1;
  else
    return 0;
}

  inline void
qsort_double(double * const array, const size_t nr)
{
  qsort(array, nr, sizeof(array[0]), compare_double);
}

  void
qsort_u64_sample(const u64 * const array0, const u64 nr, const u64 res, FILE * const out)
{
  const u64 datasize = nr * sizeof(array0[0]);
  u64 * const array = malloc(datasize);
  debug_assert(array);
  memcpy(array, array0, datasize);
  qsort_u64(array, nr);

  const double sized = (double)nr;
  const u64 srate = res ? res : 64;
  const u64 xstep = ({u64 step = nr / srate; step ? step : 1; });
  const u64 ystep = ({u64 step = (array[nr - 1] - array[0]) / srate; step ? step : 1; });
  u64 i = 0;
  fprintf(out, "%lu %06.2lf %lu\n", i, ((double)(i + 1)) * 100.0 / sized, array[i]);
  for (u64 j = 1; j < nr; j++) {
    if (((j - i) >= xstep) || (array[j] - array[i]) >= ystep) {
      i = j;
      fprintf(out, "%lu %06.2lf %lu\n", i, ((double)(i + 1)) * 100.0 / sized, array[i]);
    }
  }
  if (i != (nr - 1)) {
    i = nr - 1;
    fprintf(out, "%lu %06.2lf %lu\n", i, ((double)(i + 1)) * 100.0 / sized, array[i]);
  }
  free(array);
}

  void
qsort_double_sample(const double * const array0, const u64 nr, const u64 res, FILE * const out)
{
  const u64 datasize = nr * sizeof(double);
  double * const array = malloc(datasize);
  debug_assert(array);
  memcpy(array, array0, datasize);
  qsort_double(array, nr);

  const u64 srate = res ? res : 64;
  const double srate_d = (double)srate;
  const double sized = (double)nr;
  const u64 xstep = ({u64 step = nr / srate; step ? step : 1; });
  const double ystep = ({ double step = fabs((array[nr - 1] - array[0]) / srate_d); step != 0.0 ? step : 1.0; });
  u64 i = 0;
  fprintf(out, "%lu %06.2lf %020.9lf\n", i, ((double)(i + 1)) * 100.0 / sized, array[i]);
  for (u64 j = 1; j < nr; j++) {
    if (((j - i) >= xstep) || (array[j] - array[i]) >= ystep) {
      i = j;
      fprintf(out, "%lu %06.2lf %020.9lf\n", i, ((double)(i + 1)) * 100.0 / sized, array[i]);
    }
  }
  if (i != (nr - 1)) {
    i = nr - 1;
    fprintf(out, "%lu %06.2lf %020.9lf\n", i, ((double)(i + 1)) * 100.0 / sized, array[i]);
  }
  free(array);
}
// }}} qsort

// string {{{
static union { u16 v16; u8 v8[2]; } strdec_table[100];

__attribute__((constructor))
  static void
strdec_init(void)
{
  for (u8 i = 0; i < 100; i++) {
    const u8 hi = (typeof(hi))('0' + (i / 10));
    const u8 lo = (typeof(lo))('0' + (i % 10));
    strdec_table[i].v8[0] = hi;
    strdec_table[i].v8[1] = lo;
  }
}

// output 10 bytes
  void
strdec_32(void * const out, const u32 v)
{
  u32 vv = v;
  u16 * const ptr = (typeof(ptr))out;
  for (u64 i = 4; i <= 4; i--) { // x5
    ptr[i] = strdec_table[vv % 100].v16;
    vv /= 100u;
  }
}

// output 20 bytes
  void
strdec_64(void * const out, const u64 v)
{
  u64 vv = v;
  u16 * const ptr = (typeof(ptr))out;
  for (u64 i = 9; i <= 9; i--) { // x10
    ptr[i] = strdec_table[vv % 100].v16;
    vv /= 100;
  }
}

#if defined(__x86_64__)
  static inline m128
strhex_helper(const u64 v)
{
  static const u8 mask1[16] = {15,7,14,6,13,5,12,4,11,3,10,2,9,1,8,0};
  static const u8 ascii[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

  const m128 tmp = _mm_set_epi64x((s64)(v>>4), (s64)v); // mm want s64
  const m128 hilo = _mm_and_si128(tmp, _mm_set1_epi8(0xf));
  const m128 bin = _mm_shuffle_epi8(hilo, _mm_load_si128((void *)mask1));
  const m128 str = _mm_shuffle_epi8(_mm_load_si128((void *)ascii), bin);
  return str;
}
#elif defined(__aarch64__)
  static inline m128
strhex_helper(const u64 v)
{
  static const u8 mask1[16] = {15,7,14,6,13,5,12,4,11,3,10,2,9,1,8,0};
  static const u8 ascii[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
  u64 v2[2] = {v, v>>4};
  const m128 tmp = vld1q_u8((u8 *)v2);
  const m128 hilo = vandq_u8(tmp, vdupq_n_u8(0xf));
  const m128 bin = vqtbl1q_u8(hilo, vld1q_u8(mask1));
  const m128 str = vqtbl1q_u8(vld1q_u8(ascii), bin);
  return str;
}
#else
static u16 strhex_table[256];

__attribute__((constructor))
  static void
strhex_init(void)
{
  const u8 hex[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
  for (u64 i = 0; i < 256; i++)
    strhex_table[i] = (((u16)hex[i & 0xf]) << 8) | (hex[i>>4]);
}
#endif // __x86_64__

// output 8 bytes
  void
strhex_32(void * const out, u32 v)
{
#if defined(__x86_64__)
  const m128 str = strhex_helper((u64)v);
  _mm_storel_epi64(out, _mm_srli_si128(str, 8));
#elif defined(__aarch64__)
  const m128 str = strhex_helper((u64)v);
  vst1q_lane_u64(out, vreinterpretq_u64_u8(str), 1);
#else
  u16 * const ptr = (typeof(ptr))out;
  for (u64 i = 0; i < 4; i++) {
    ptr[3-i] = strhex_table[v & 0xff];
    v >>= 8;
  }
#endif
}

// output 16 bytes // buffer must be aligned by 16B
  void
strhex_64(void * const out, u64 v)
{
#if defined(__x86_64__)
  const m128 str = strhex_helper(v);
  _mm_store_si128(out, str);
#elif defined(__aarch64__)
  const m128 str = strhex_helper(v);
  vst1q_u8(out, str);
#else
  u16 * const ptr = (typeof(ptr))out;
  for (u64 i = 0; i < 8; i++) {
    ptr[7-i] = strhex_table[v & 0xff];
    v >>= 8;
  }
#endif
}

// string to u64
  inline u64
a2u64(const void * const str)
{
  return strtoull(str, NULL, 10);
}

  inline u32
a2u32(const void * const str)
{
  return (u32)strtoull(str, NULL, 10);
}

  inline s64
a2s64(const void * const str)
{
  return strtoll(str, NULL, 10);
}

  inline s32
a2s32(const void * const str)
{
  return (s32)strtoll(str, NULL, 10);
}

// returns a NULL-terminated list of string tokens.
// After use you only need to free the returned pointer (char **).
  char **
string_tokens(const char * const str, const char * const delim)
{
  if (str == NULL)
    return NULL;
  size_t nptr_alloc = 32;
  char ** tokens = malloc(sizeof(tokens[0]) * nptr_alloc);
  if (tokens == NULL)
    return NULL;
  const size_t bufsize = strlen(str) + 1;
  char * const buf = malloc(bufsize);
  if (buf == NULL)
    goto fail_buf;

  memcpy(buf, str, bufsize);
  char * saveptr = NULL;
  char * tok = strtok_r(buf, delim, &saveptr);
  size_t ntoks = 0;
  while (tok) {
    if (ntoks >= nptr_alloc) {
      nptr_alloc += 32;
      char ** const r = realloc(tokens, sizeof(tokens[0]) * nptr_alloc);
      if (r == NULL)
        goto fail_realloc;

      tokens = r;
    }
    tokens[ntoks] = tok;
    ntoks++;
    tok = strtok_r(NULL, delim, &saveptr);
  }
  tokens[ntoks] = NULL;
  const size_t nptr = ntoks + 1; // append a NULL
  const size_t rsize = (sizeof(tokens[0]) * nptr) + bufsize;
  char ** const r = realloc(tokens, rsize);
  if (r == NULL)
    goto fail_realloc;

  tokens = r;
  char * const dest = (char *)(&(tokens[nptr]));
  memcpy(dest, buf, bufsize);
  for (u64 i = 0; i < ntoks; i++)
    tokens[i] += (dest - buf);

  free(buf);
  return tokens;

fail_realloc:
  free(buf);
fail_buf:
  free(tokens);
  return NULL;
}
// }}} string

// damp {{{
struct damp {
  u64 cap;
  u64 nr; // <= cap
  u64 nr_added; // +1 every time
  double sum;
  double dshort;
  double dlong;
  double hist[];
};

  struct damp *
damp_create(const u64 cap, const double dshort, const double dlong)
{
  struct damp * const d = malloc(sizeof(*d) + (sizeof(d->hist[0]) * cap));
  d->cap = cap;
  d->nr = 0;
  d->nr_added = 0;
  d->sum = 0.0;
  d->dshort = dshort;
  d->dlong = dlong;
  return d;
}

  double
damp_avg(const struct damp * const d)
{
  return d->nr_added ? (d->sum / (double)d->nr_added) : 0.0;
}

// recent avg
  double
damp_ravg(const struct damp * const d)
{
  double sum = 0.0;
  for (u64 i = 0; i < d->nr; i++)
    sum += d->hist[i];
  const double avg = sum / ((double)d->nr);
  return avg;
}

  double
damp_min(const struct damp * const d)
{
  if (d->nr == 0)
    return 0.0;
  double min = d->hist[0];
  for (u64 i = 1; i < d->nr; i++)
    if (d->hist[i] < min)
      min = d->hist[i];
  return min;
}

  double
damp_max(const struct damp * const d)
{
  if (d->nr == 0)
    return 0.0;
  double max = d->hist[0];
  for (u64 i = 1; i < d->nr; i++)
    if (d->hist[i] > max)
      max = d->hist[i];
  return max;
}

  void
damp_add(struct damp * const d, const double v)
{
  if (d->nr < d->cap) {
    d->hist[d->nr] = v;
    d->nr++;
  } else { // already full
    memmove(d->hist, d->hist+1, sizeof(d->hist[0]) * (d->nr-1));
    d->hist[d->nr-1] = v;
  }
  d->nr_added++;
  d->sum += v;
}

  bool
damp_test(struct damp * const d)
{
  // short-distance history
  if (d->nr >= 3) { // at least three times
    const double v0 = d->hist[d->nr - 1];
    const double v1 = d->hist[d->nr - 2];
    const double v2 = d->hist[d->nr - 3];
    const double dd = v0 * d->dshort;
    const double d01 = fabs(v1 - v0);
    const double d02 = fabs(v2 - v0);
    if (d01 < dd && d02 < dd)
      return true;
  }

  // full-distance history
  if (d->nr == d->cap) {
    const double avg = damp_ravg(d);
    const double dev = avg * d->dlong;
    if (fabs(damp_max(d) - damp_min(d)) < dev)
      return true;
  }

  // not too many times
  return d->nr_added >= (d->cap * 2);
}

  bool
damp_add_test(struct damp * const d, const double v)
{
  damp_add(d, v);
  return damp_test(d);
}

  void
damp_clean(struct damp * const d)
{
  d->nr = 0;
  d->nr_added = 0;
  d->sum = 0;
}

  void
damp_destroy(struct damp * const d)
{
  free(d);
}
// }}} damp

// vctr {{{
struct vctr {
  size_t nr;
  union {
    size_t v;
    atomic_size_t av;
  } u[];
};

  struct vctr *
vctr_create(const size_t nr)
{
  struct vctr * const v = calloc(1, sizeof(*v) + (sizeof(v->u[0]) * nr));
  v->nr = nr;
  return v;
}

  inline size_t
vctr_size(const struct vctr * const v)
{
  return v->nr;
}

  inline void
vctr_add(struct vctr * const v, const u64 i, const size_t n)
{
  if (i < v->nr)
    v->u[i].v += n;
}

  inline void
vctr_add1(struct vctr * const v, const u64 i)
{
  if (i < v->nr)
    v->u[i].v++;
}

  inline void
vctr_add_atomic(struct vctr * const v, const u64 i, const size_t n)
{
  if (i < v->nr)
    (void)atomic_fetch_add_explicit(&(v->u[i].av), n, MO_RELAXED);
}

  inline void
vctr_add1_atomic(struct vctr * const v, const u64 i)
{
  if (i < v->nr)
    (void)atomic_fetch_add_explicit(&(v->u[i].av), 1, MO_RELAXED);
}

  inline void
vctr_set(struct vctr * const v, const u64 i, const size_t n)
{
  if (i < v->nr)
    v->u[i].v = n;
}

  size_t
vctr_get(const struct vctr * const v, const u64 i)
{
  return (i < v->nr) ?  v->u[i].v : 0;
}

  void
vctr_merge(struct vctr * const to, const struct vctr * const from)
{
  const size_t nr = to->nr < from->nr ? to->nr : from->nr;
  for (u64 i = 0; i < nr; i++)
    to->u[i].v += from->u[i].v;
}

  void
vctr_reset(struct vctr * const v)
{
  memset(v->u, 0, sizeof(v->u[0]) * v->nr);
}

  void
vctr_destroy(struct vctr * const v)
{
  free(v);
}
// }}} vctr

// rgen {{{

// struct {{{
#define GEN_CONST    ((1))
#define GEN_INCS     ((2))
#define GEN_INCU     ((3))      // +1
#define GEN_SKIPS    ((4))
#define GEN_SKIPU    ((5))      // +n
#define GEN_DECS     ((6))
#define GEN_DECU     ((7))      // -1
#define GEN_EXPO     ((8))      // exponential
#define GEN_ZIPF     ((9))      // Zipfian, 0 is the most popular.
#define GEN_XZIPF   ((10))      // ScrambledZipfian. scatters the "popular" items across the itemspace.
#define GEN_UNIZIPF ((11))      // Uniform + Zipfian (multiple hills)
#define GEN_ZIPFUNI ((12))      // Zipfian + Uniform (one hill)
#define GEN_UNIFORM ((13))      // Uniformly distributed in an interval [a,b]
#define GEN_TRACE32 ((14))      // Read from a trace file with unit of u32.
#define GEN_LATEST  ((15))      // latest (moving head - zipfian)

#define GEN_ASYNC  ((255))      // async gen

struct rgen_linear { // 8x4
  union { au64 ac; u64 uc; };
  u64 base;
  u64 mod;
  union { s64 inc; u64 inc_u64; };
};

struct rgen_expo { // 8
  double gamma;
};

struct rgen_trace32 { // 8x5
  FILE * fin;
  u64 idx;
  u64 avail;
  u64 bufnr;
  u32 * buf;
};

struct rgen_zipfian { // 8x9
  u64 mod;
  u64 base;
  double quick1;
  double mod_d;
  double zetan;
  double alpha;
  double quick2;
  double eta;
  double theta;
};

struct rgen_uniform { // 8x3
  u64 base;
  u64 mod;
  double mul;
};

struct rgen_unizipf { // 8x12
  struct rgen_zipfian zipfian;
  u64 usize;
  u64 zsize;
  u64 base;
};

struct rgen_xzipfian { // 8x10
  struct rgen_zipfian zipfian;
  u64 mul;
};

struct rgen_latest {
  struct rgen_zipfian zipfian;
  au64 head; // ever increasing
};

#define RGEN_ABUF_NR ((4))
#define RGEN_ABUF_SZ ((1lu << 30))
#define RGEN_ABUF_SZ1 ((RGEN_ABUF_SZ / RGEN_ABUF_NR))
#define RGEN_ABUF_NR1_32 ((RGEN_ABUF_SZ1 / sizeof(u32)))
#define RGEN_ABUF_NR1_64 ((RGEN_ABUF_SZ1 / sizeof(u64)))
struct rgen_async {
  union {
    u8 * curr;
    u64 * curr64;
    u32 * curr32;
  };
  union {
    u8 * guard;
    u64 * guard64;
    u32 * guard32;
  };
  struct rgen * real_gen;
  u8 * mem;
  abool running;
  u8 reader_id;
  u8 padding2[2];
  abool avail[RGEN_ABUF_NR];
  pthread_t pt;
};

typedef u64 (*rgen_next_func)(struct rgen * const);

struct rgen {
  union {
    struct rgen_linear       linear;
    struct rgen_expo         expo;
    struct rgen_trace32      trace32;
    struct rgen_zipfian      zipfian;
    struct rgen_uniform      uniform;
    struct rgen_unizipf      unizipf;
    struct rgen_xzipfian     xzipfian;
    struct rgen_latest       latest;
    struct rgen_async        async;
  };
  rgen_next_func next;
  union {
    rgen_next_func next_nowait; // async only
    rgen_next_func next_write; // latest only
  };
  u64 min;
  u64 max;
  u8 type; // use to be a enum
  bool unit_u64;
  bool async_worker; // has an async worker running
  bool shared; // don't copy in rgen_fork()
};

  static void
rgen_set_next(struct rgen * const gen, rgen_next_func next)
{
  gen->next = next;
  gen->next_nowait = NULL;
}
// }}} struct

// random {{{
// Lehmer's generator is 2x faster than xorshift
/**
 * D. H. Lehmer, Mathematical methods in large-scale computing units.
 * Proceedings of a Second Symposium on Large Scale Digital Calculating
 * Machinery;
 * Annals of the Computation Laboratory, Harvard Univ. 26 (1951), pp. 141-146.
 *
 * P L'Ecuyer,  Tables of linear congruential generators of different sizes and
 * good lattice structure. Mathematics of Computation of the American
 * Mathematical
 * Society 68.225 (1999): 249-260.
 */
static __thread union {
  u128 v128;
  u64 v64[2];
} rseed_u128 = {.v64 = {4294967291, 1549556881}};

  inline u64
random_u64(void)
{
  const u64 r = rseed_u128.v64[1];
  rseed_u128.v128 *= 0xda942042e4dd58b5lu;
  return r;
}

  inline void
srandom_u64(const u64 seed)
{
  rseed_u128.v128 = (((u128)(~seed)) << 64) | (seed | 1);
  (void)random_u64();
}

  inline double
random_double(void)
{
  // random between [0.0 - 1.0]
  const u64 r = random_u64();
  return ((double)r) * (1.0 / ((double)(~0lu)));
}
// }}} random

// genenators {{{

// simple ones {{{
  static u64
gen_constant(struct rgen * const gi)
{
  return gi->linear.base;
}

  struct rgen *
rgen_new_const(const u64 c)
{
  struct rgen * const gi = calloc(1, sizeof(*gi));
  gi->unit_u64 = c > UINT32_MAX;
  gi->linear.base = c;
  gi->type = GEN_CONST;
  gi->min = gi->max = c;
  rgen_set_next(gi, gen_constant);
  gi->shared = true;
  return gi;
}

  static u64
gen_expo(struct rgen * const gi)
{
  const double d = - log(random_double()) / gi->expo.gamma;
  return (u64)d;
}

  struct rgen *
rgen_new_expo(const double percentile, const double range)
{
  struct rgen * const gi = calloc(1, sizeof(*gi));
  gi->unit_u64 = true;
  gi->expo.gamma = - log(1.0 - (percentile/100.0)) / range;
  gi->type = GEN_EXPO;
  gi->max = ~0lu;
  rgen_set_next(gi, gen_expo);
  gi->shared = true;
  return gi;
}
// }}} simple ones

// linear {{{
  static struct rgen *
rgen_new_linear(const u64 min, const u64 max, const s64 inc,
    const u8 type, rgen_next_func func)
{
  if (min > max || inc == INT64_MIN)
    return NULL;
  const u64 mod = max - min + 1; // mod == 0 with min=0,max=UINT64_MAX
  const u64 incu = (u64)((inc >= 0) ? inc : -inc);
  // incu cannot be too large
  if (mod && (incu >= mod))
    return NULL;

  struct rgen * const gi = calloc(1, sizeof(*gi));
  gi->unit_u64 = max > UINT32_MAX;
  gi->linear.uc = 0;
  gi->linear.base = inc >= 0 ? min : max;
  gi->linear.mod = mod;
  gi->linear.inc = inc;
  gi->type = type;
  gi->min = min;
  gi->max = max;
  rgen_set_next(gi, func);
  return gi;
}

  static u64
gen_linear_incs_helper(struct rgen * const gi)
{
  u64 v = atomic_fetch_add_explicit(&(gi->linear.ac), 1, MO_RELAXED);
  const u64 mod = gi->linear.mod;
  if (mod && (v >= mod)) {
    do {
      v -= mod;
    } while (v >= mod);
    if (v == 0)
      atomic_fetch_sub_explicit(&(gi->linear.ac), mod, MO_RELAXED);
  }
  return v;
}

  static u64
gen_linear_incu_helper(struct rgen * const gi)
{
  u64 v = gi->linear.uc++;
  const u64 mod = gi->linear.mod;
  if (mod && (v == mod)) {
    gi->linear.uc -= mod;
    v = 0;
  }
  return v;
}

  static u64
gen_incs(struct rgen * const gi)
{
  return gi->linear.base + gen_linear_incs_helper(gi);
}

  struct rgen *
rgen_new_incs(const u64 min, const u64 max)
{
  struct rgen * const gen = rgen_new_linear(min, max, 1, GEN_INCS, gen_incs);
  gen->shared = true;
  return gen;
}

  static u64
gen_incu(struct rgen * const gi)
{
  return gi->linear.base + gen_linear_incu_helper(gi);
}

  struct rgen *
rgen_new_incu(const u64 min, const u64 max)
{
  return rgen_new_linear(min, max, 1, GEN_INCU, gen_incu);
}

// skips will produce wrong results when mod is not a power of two and ac overflows
  static u64
gen_skips_up(struct rgen * const gi)
{
  const u64 v = atomic_fetch_add_explicit(&(gi->linear.ac), gi->linear.inc_u64, MO_RELAXED);
  const u64 mod = gi->linear.mod;
  return gi->linear.base + (mod ? (v % mod) : v);
}

  static u64
gen_skips_down(struct rgen * const gi)
{
  const u64 v = atomic_fetch_sub_explicit(&(gi->linear.ac), gi->linear.inc_u64, MO_RELAXED);
  const u64 mod = gi->linear.mod;
  return gi->linear.base - (mod ? (v % mod) : v);
}

  struct rgen *
rgen_new_skips(const u64 min, const u64 max, const s64 inc)
{
  struct rgen * const gen = rgen_new_linear(min, max, inc, GEN_SKIPS, (inc >= 0) ? gen_skips_up : gen_skips_down);
  gen->shared = true;
  return gen;
}

  static u64
gen_skipu_up(struct rgen * const gi)
{
  const u64 v = gi->linear.uc;
  const u64 mod = gi->linear.mod;
  debug_assert((mod == 0) | (v < mod));
  const u64 v1 = v + gi->linear.inc_u64;
  gi->linear.uc = (v1 >= mod) ? (v1 - mod) : v1;
  return gi->linear.base + v;
}

  static u64
gen_skipu_down(struct rgen * const gi)
{
  const u64 v = gi->linear.uc;
  const u64 mod = gi->linear.mod;
  debug_assert((mod == 0) | (v < mod));
  const u64 v1 = v - gi->linear.inc_u64; // actually +
  gi->linear.uc = (v1 >= mod) ? (v1 - mod) : v1;
  return gi->linear.base - v;
}

  struct rgen *
rgen_new_skipu(const u64 min, const u64 max, const s64 inc)
{
  return rgen_new_linear(min, max, inc, GEN_SKIPU, (inc >= 0) ? gen_skipu_up : gen_skipu_down);
}

  static u64
gen_decs(struct rgen * const gi)
{
  return gi->linear.base - gen_linear_incs_helper(gi);
}

  struct rgen *
rgen_new_decs(const u64 min, const u64 max)
{
  struct rgen * const gen = rgen_new_linear(min, max, -1, GEN_DECS, gen_decs);
  gen->shared = true;
  return gen;
}

  static u64
gen_decu(struct rgen * const gi)
{
  return gi->linear.base - gen_linear_incu_helper(gi);
}

  struct rgen *
rgen_new_decu(const u64 min, const u64 max)
{
  return rgen_new_linear(min, max, -1, GEN_DECU, gen_decu);
}
// }}} linear

// uniform {{{
  static u64
gen_uniform(struct rgen * const gi)
{
  return gi->uniform.base + (u64)(((double)random_u64()) * gi->uniform.mul);
}

  struct rgen *
rgen_new_uniform(const u64 min, const u64 max)
{
  struct rgen * const gi = calloc(1, sizeof(*gi));
  gi->unit_u64 = max > UINT32_MAX;
  gi->uniform.base = min;
  const u64 mod = max - min + 1;
  gi->uniform.mod = mod;
  // 5.4..e-20 * (1 << 64) == 1 - epsilon
  gi->uniform.mul = ((double)mod) * 5.421010862427521e-20;

  gi->type = GEN_UNIFORM;
  gi->min = min;
  gi->max = max;
  rgen_set_next(gi, gen_uniform);
  gi->shared = true;
  return gi;
}
// }}} uniform

// zipf {{{
  static u64
gen_zipfian(struct rgen * const gi)
{
  // simplified: no increamental update
  const struct rgen_zipfian * const gz = &(gi->zipfian);
  const double u = random_double();
  const double uz = u * gz->zetan;
  if (uz < 1.0)
    return gz->base;
  else if (uz < gz->quick1)
    return gz->base + 1;

  const double x = gz->mod_d * pow((gz->eta * u) + gz->quick2, gz->alpha);
  const u64 ret = gz->base + (u64)x;
  return ret;
}

struct zeta_range_info {
  au64 seq;
  u64 nth;
  u64 start;
  u64 count;
  double theta;
  double sums[0];
};

  static void *
zeta_range_worker(void * const ptr)
{
  struct zeta_range_info * const zi = (typeof(zi))ptr;
  const u64 seq = atomic_fetch_add_explicit(&(zi->seq), 1, MO_RELAXED);
  const u64 start = zi->start;
  const double theta = zi->theta;
  const u64 count = zi->count;
  const u64 nth = zi->nth;
  double local_sum = 0.0;
  for (u64 i = seq; i < count; i += nth)
    local_sum += (1.0 / pow((double)(start + i + 1), theta));

  zi->sums[seq] = local_sum;
  return NULL;
}

  static double
zeta_range(const u64 start, const u64 count, const double theta)
{
  const u32 ncores = process_affinity_count();
  const u32 needed = (u32)((count >> 20) + 1); // 1m per core
  const u32 nth = needed < ncores ? needed : ncores;
  double sum = 0.0;
  debug_assert(nth > 0);
  const size_t zisize = sizeof(struct zeta_range_info) + (sizeof(double) * nth);
  struct zeta_range_info * const zi = malloc(zisize);
  if (zi == NULL) { // fallback
    for (u64 i = 0; i < count; i++)
      sum += (1.0 / pow((double)(start + i + 1), theta));
    return sum;
  }
  zi->seq = 0;
  zi->nth = nth;
  zi->start = start;
  zi->count = count;
  zi->theta = theta;
  // workers fill sums
  thread_fork_join(nth, zeta_range_worker, false, zi);
  for (u64 i = 0; i < nth; i++)
    sum += zi->sums[i];
  free(zi);
  return sum;
}

static const u64 zetalist_u64[] = {0,
  0x4040437dd948c1d9lu, 0x4040b8f8009bce85lu, 0x4040fe1121e564d6lu, 0x40412f435698cdf5lu,
  0x404155852507a510lu, 0x404174d7818477a7lu, 0x40418f5e593bd5a9lu, 0x4041a6614fb930fdlu,
  0x4041bab40ad5ec98lu, 0x4041cce73d363e24lu, 0x4041dd6239ebabc3lu, 0x4041ec715f5c47belu,
  0x4041fa4eba083897lu, 0x4042072772fe12bdlu, 0x4042131f5e380b72lu, 0x40421e53630da013lu,
};

static const double * zetalist_double = (typeof(zetalist_double))zetalist_u64;
static const u64 zetalist_step = 0x10000000000lu;
static const u64 zetalist_count = 16;

  static double
zeta(const u64 n, const double theta)
{
  //assert(theta == 0.99);
  const u64 zlid0 = n / zetalist_step;
  const u64 zlid = (zlid0 > zetalist_count) ? zetalist_count : zlid0;
  const double sum0 = zetalist_double[zlid];
  const u64 start = zlid * zetalist_step;
  const u64 count = n - start;
  const double sum1 = zeta_range(start, count, theta);
  return sum0 + sum1;
}

  struct rgen *
rgen_new_zipfian(const u64 min, const u64 max)
{
#define ZIPFIAN_CONSTANT ((0.99))  // DONT change this number
  struct rgen * const gi = calloc(1, sizeof(*gi));
  gi->unit_u64 = max > UINT32_MAX;
  struct rgen_zipfian * const gz = &(gi->zipfian);

  const u64 mod = max - min + 1;
  gz->mod = mod;
  gz->mod_d = (double)mod;
  gz->base = min;
  gz->theta = ZIPFIAN_CONSTANT;
  gz->quick1 = 1.0 + pow(0.5, gz->theta);
  const double zeta2theta = zeta(2, ZIPFIAN_CONSTANT);
  gz->alpha = 1.0 / (1.0 - ZIPFIAN_CONSTANT);
  const double zetan = zeta(mod, ZIPFIAN_CONSTANT);
  gz->zetan = zetan;
  gz->eta = (1.0 - pow(2.0 / (double)mod, 1.0 - ZIPFIAN_CONSTANT)) / (1.0 - (zeta2theta / zetan));
  gz->quick2 = 1.0 - gz->eta;

  gi->type = GEN_ZIPF;
  gi->min = min;
  gi->max = max;
  rgen_set_next(gi, gen_zipfian);
  gi->shared = true;
  return gi;
#undef ZIPFIAN_CONSTANT
}

  static u64
gen_xzipfian(struct rgen * const gi)
{
  const u64 z = gen_zipfian(gi);
  const u64 xz = z * gi->xzipfian.mul;
  return gi->zipfian.base + (xz % gi->zipfian.mod);
}

  struct rgen *
rgen_new_xzipfian(const u64 min, const u64 max)
{
  struct rgen * gi = rgen_new_zipfian(min, max);
  const u64 gold = (gi->zipfian.mod / 21 * 13) | 1;
  for (u64 mul = gold;; mul += 2) {
    if (gcd64(mul, gi->zipfian.mod) == 1) {
      gi->xzipfian.mul = mul;
      break;
    }
  }
  gi->unit_u64 = max > UINT32_MAX;
  gi->type = GEN_XZIPF;
  rgen_set_next(gi, gen_xzipfian);
  return gi;
}

  static u64
gen_unizipf(struct rgen * const gi)
{
  // scattered hot spots
  const u64 z = gen_zipfian(gi);
  const u64 u = (random_u64() % gi->unizipf.usize) * gi->unizipf.zsize;
  return gi->unizipf.base + z + u;
}

  static u64
gen_zipfuni(struct rgen * const gi)
{
  // aggregated hot spots
  const u64 z = gen_zipfian(gi) * gi->unizipf.usize;
  const u64 u = random_u64() % gi->unizipf.usize;
  return gi->unizipf.base + z + u;
}

  struct rgen *
rgen_new_unizipf(const u64 min, const u64 max, const u64 ufactor)
{
  const u64 nr = max - min + 1;
  if (ufactor == 1) // covers both special gens
    return rgen_new_zipfian(min, max);
  else if ((ufactor == 0) || ((nr / ufactor) <= 1))
    return rgen_new_uniform(min, max);

  const u64 znr = nr / ufactor;
  struct rgen * gi = rgen_new_zipfian(0, znr - 1);
  gi->unit_u64 = max > UINT32_MAX;
  gi->unizipf.usize = ufactor;
  gi->unizipf.zsize = nr / ufactor;
  gi->unizipf.base = min;
  gi->min = min;
  gi->max = max;
  gi->type = GEN_UNIZIPF;
  rgen_set_next(gi, gen_unizipf);
  return gi;
}

  struct rgen *
rgen_new_zipfuni(const u64 min, const u64 max, const u64 ufactor)
{
  struct rgen * const gi = rgen_new_unizipf(min, max, ufactor);
  gi->type = GEN_ZIPFUNI;
  rgen_set_next(gi, gen_zipfuni);
  return gi;
}
// }}} zipf

// latest {{{
  static u64
gen_latest_read(struct rgen * const gi)
{
  const u64 z = gen_zipfian(gi);
  const u64 head = gi->latest.head;
  return (head > z) ? (head - z) : 0;
}

  static u64
gen_latest_write(struct rgen * const gi)
{
  return atomic_fetch_add_explicit(&(gi->latest.head), 1, MO_RELAXED);
}

  struct rgen *
rgen_new_latest(const u64 zipf_range)
{
  struct rgen * const gen = rgen_new_zipfian(1, zipf_range?(zipf_range):1);
  gen->type = GEN_LATEST;
  gen->next = gen_latest_read;
  gen->next_write = gen_latest_write;
  gen->min = 0;
  gen->max = UINT64_MAX;
  return gen;
}
// }}} latest

// trace {{{
  static u64
gen_trace32(struct rgen * const gi)
{
  struct rgen_trace32 * const pt = &(gi->trace32);
  if (pt->idx >= pt->avail) {
    if (feof(pt->fin))
      rewind(pt->fin);
    pt->idx = 0;
    pt->avail = fread(pt->buf, sizeof(u32), pt->bufnr, pt->fin);
    debug_assert(pt->avail);
  }
  const u64 r = pt->buf[pt->idx];
  pt->idx++;
  return r;
}

  struct rgen *
rgen_new_trace32(const char * const filename, const u64 bufsize)
{
  struct rgen * const gi = calloc(1, sizeof(*gi));
  struct rgen_trace32 * const pt = &(gi->trace32);
  pt->fin = fopen(filename, "rb");
  if (pt->fin == NULL) {
    free(gi);
    return NULL;
  }
  pt->idx = 0;
  pt->bufnr = bits_round_up(bufsize, 4) / sizeof(u32);
  pt->buf = malloc(pt->bufnr * sizeof(u32));
  debug_assert(pt->buf);
  pt->avail = fread(pt->buf, sizeof(u32), pt->bufnr, pt->fin);
  if (pt->avail == 0) {
    free(gi);
    return NULL;
  }
  gi->type = GEN_TRACE32;
  gi->max = ~0lu;
  rgen_set_next(gi, gen_trace32);
  return gi;
}
// }}} others

// }}} generators

// rgen helper {{{
  inline u64
rgen_min(struct rgen * const gen)
{
  return gen->min;
}

  inline u64
rgen_max(struct rgen * const gen)
{
  return gen->max;
}

  inline u64
rgen_next(struct rgen * const gen)
{
  return gen->next(gen);
}

  inline u64
rgen_next_nowait(struct rgen * const gen)
{
  return gen->next_nowait(gen);
}

  inline u64
rgen_next_write(struct rgen * const gen)
{
  return gen->next_write(gen);
}

  static void
rgen_async_clean_buffers(struct rgen_async * const as)
{
  if (as->mem) {
    pages_unmap(as->mem, RGEN_ABUF_SZ);
    as->mem = NULL;
  }
}

  void
rgen_destroy(struct rgen * const gen)
{
  if (gen->type == GEN_ASYNC) {
    gen->async.running = false;
    pthread_join(gen->async.pt, NULL);
    rgen_async_clean_buffers(&gen->async);
  } else if (gen->type == GEN_TRACE32) {
    fclose(gen->trace32.fin);
    free(gen->trace32.buf);
  }
  free(gen);
}

  void
rgen_helper_message(void)
{
  fprintf(stderr, "%s Usage: rgen <type> ...\n", __func__);
  fprintf(stderr, "%s example: rgen const <value>\n", __func__);
  fprintf(stderr, "%s example: rgen expo <perc> <range>\n", __func__);
  fprintf(stderr, "%s example: rgen uniform <min> <max>\n", __func__);
  fprintf(stderr, "%s example: rgen zipfian <min> <max>\n", __func__);
  fprintf(stderr, "%s example: rgen xzipfian <min> <max>\n", __func__);
  fprintf(stderr, "%s example: rgen unizipf <min> <max> <ufactor>\n", __func__);
  fprintf(stderr, "%s example: rgen zipfuni <min> <max> <ufactor>\n", __func__);
  fprintf(stderr, "%s example: rgen latest <zipf-range>\n", __func__);
  fprintf(stderr, "%s example: rgen incs <min> <max>\n", __func__);
  fprintf(stderr, "%s example: rgen incu <min> <max>\n", __func__);
  fprintf(stderr, "%s example: rgen decs <min> <max>\n", __func__);
  fprintf(stderr, "%s example: rgen decu <min> <max>\n", __func__);
  fprintf(stderr, "%s example: rgen skips <min> <max> <inc>\n", __func__);
  fprintf(stderr, "%s example: rgen skipu <min> <max> <inc>\n", __func__);
  fprintf(stderr, "%s example: rgen trace32 <filename> <bufsize>\n", __func__);
}

  int
rgen_helper(const int argc, char ** const argv, struct rgen ** const gen_out)
{
  if ((argc < 1) || (strcmp("rgen", argv[0]) != 0))
    return -1;

  if ((0 == strcmp(argv[1], "const")) && (argc >= 3)) {
    *gen_out = rgen_new_const(a2u64(argv[2]));
    return 3;
  } else if ((0 == strcmp(argv[1], "expo")) && (argc >= 4)) {
    *gen_out = rgen_new_expo(atof(argv[2]), atof(argv[3]));
    return 4;
  } else if ((0 == strcmp(argv[1], "uniform")) && (argc >= 4)) {
    *gen_out = rgen_new_uniform(a2u64(argv[2]), a2u64(argv[3]));
    return 4;
  } else if ((0 == strcmp(argv[1], "zipfian")) && (argc >= 4)) {
    *gen_out = rgen_new_zipfian(a2u64(argv[2]), a2u64(argv[3]));
    return 4;
  } else if ((0 == strcmp(argv[1], "xzipfian")) && (argc >= 4)) {
    *gen_out = rgen_new_xzipfian(a2u64(argv[2]), a2u64(argv[3]));
    return 4;
  } else if ((0 == strcmp(argv[1], "unizipf")) && (argc >= 5)) {
    *gen_out = rgen_new_unizipf(a2u64(argv[2]), a2u64(argv[3]), a2u64(argv[4]));
    return 5;
  } else if ((0 == strcmp(argv[1], "zipfuni")) && (argc >= 5)) {
    *gen_out = rgen_new_zipfuni(a2u64(argv[2]), a2u64(argv[3]), a2u64(argv[4]));
    return 5;
  } else if ((0 == strcmp(argv[1], "latest")) && (argc >= 3)) {
    *gen_out = rgen_new_latest(a2u64(argv[2]));
    return 3;
  } else if ((0 == strcmp(argv[1], "incs")) && (argc >= 4)) {
    *gen_out = rgen_new_incs(a2u64(argv[2]), a2u64(argv[3]));
    return 4;
  } else if ((0 == strcmp(argv[1], "incu")) && (argc >= 4)) {
    *gen_out = rgen_new_incu(a2u64(argv[2]), a2u64(argv[3]));
    return 4;
  } else if ((0 == strcmp(argv[1], "decs")) && (argc >= 4)) {
    *gen_out = rgen_new_decs(a2u64(argv[2]), a2u64(argv[3]));
    return 4;
  } else if ((0 == strcmp(argv[1], "decu")) && (argc >= 4)) {
    *gen_out = rgen_new_decu(a2u64(argv[2]), a2u64(argv[3]));
    return 4;
  } else if ((0 == strcmp(argv[1], "skips")) && (argc >= 5)) {
    *gen_out = rgen_new_skips(a2u64(argv[2]), a2u64(argv[3]), a2s64(argv[4]));
    return 5;
  } else if ((0 == strcmp(argv[1], "skipu")) && (argc >= 5)) {
    *gen_out = rgen_new_skipu(a2u64(argv[2]), a2u64(argv[3]), a2s64(argv[4]));
    return 5;
  } else if ((0 == strcmp(argv[1], "trace32")) && (argc >= 4)) {
    *gen_out = rgen_new_trace32(argv[2], a2u64(argv[3]));
    return 4;
  }
  return -1;
}
// }}} rgen helper

// async {{{
  static void *
rgen_async_worker(void * const ptr)
{
  struct rgen * const agen = (typeof(agen))ptr;
  struct rgen_async * const as = &(agen->async);
  struct rgen * const real_gen = as->real_gen;
  rgen_next_func real_next = real_gen->next;
  srandom_u64(time_nsec());
#pragma nounroll
  while (true) {
    for (u64 i = 0; i < RGEN_ABUF_NR; i++) {
#pragma nounroll
      while (as->avail[i]) {
        usleep(1);
        if (!as->running)
          return NULL;
      }
      if (agen->unit_u64) {
        u64 * const buf64 = (u64 *)(as->mem + (i * RGEN_ABUF_SZ1));
        for (u64 j = 0; j < RGEN_ABUF_NR1_64; j++)
          buf64[j] = real_next(real_gen);
      } else {
        u32 * const buf32 = (u32 *)(as->mem + (i * RGEN_ABUF_SZ1));
        for (u64 j = 0; j < RGEN_ABUF_NR1_32; j++)
          buf32[j] = (u32)real_next(real_gen);
      }
      as->avail[i] = true;
    }
  }
}

  static void
rgen_async_wait_at(struct rgen * const gen, const u8 id)
{
  debug_assert(gen->type == GEN_ASYNC);
#pragma nounroll
  while (!gen->async.avail[id])
    cpu_pause();
}

  void
rgen_async_wait(struct rgen * const gen)
{
  if (gen->type == GEN_ASYNC)
    rgen_async_wait_at(gen, gen->async.reader_id);
}

  void
rgen_async_wait_all(struct rgen * const gen)
{
  if (gen->type == GEN_ASYNC) {
    for (u32 i = 0; i < 4; i++)
      rgen_async_wait_at(gen, i);
  }
}

  static inline void
rgen_async_switch(struct rgen * const gen)
{
  struct rgen_async * const as = &(gen->async);
  as->avail[as->reader_id] = false;
  as->reader_id = (as->reader_id + 1) % RGEN_ABUF_NR;
  as->curr = as->mem + (as->reader_id * RGEN_ABUF_SZ1);
  as->guard = as->curr + RGEN_ABUF_SZ1;
}

  static u64
rgen_async_next_32(struct rgen * const gen)
{
  struct rgen_async * const as = &(gen->async);
  const u64 r = (u64)(*as->curr32);
  as->curr32++;
  if (unlikely(as->curr32 == as->guard32)) {
    rgen_async_switch(gen);
    rgen_async_wait(gen);
  }
  return r;
}

  static u64
rgen_async_next_64(struct rgen * const gen)
{
  struct rgen_async * const as = &(gen->async);
  const u64 r = *as->curr64;
  as->curr64++;
  if (unlikely(as->curr64 == as->guard64)) {
    rgen_async_switch(gen);
    rgen_async_wait(gen);
  }
  return r;
}

  static u64
rgen_async_next_32_nowait(struct rgen * const gen)
{
  struct rgen_async * const as = &(gen->async);
  const u64 r = (u64)(*as->curr32);
  as->curr32++;
  if (unlikely(as->curr32 == as->guard32)) {
    rgen_async_switch(gen);
  }
  return r;
}

  static u64
rgen_async_next_64_nowait(struct rgen * const gen)
{
  struct rgen_async * const as = &(gen->async);
  const u64 r = *as->curr64;
  as->curr64++;
  if (unlikely(as->curr64 == as->guard64)) {
    rgen_async_switch(gen);
  }
  return r;
}

  struct rgen *
rgen_fork(struct rgen * const gen0)
{
  if (gen0->type == GEN_ASYNC)
    return NULL;
  if (gen0->shared)
    return gen0;

  struct rgen * const gen = malloc(sizeof(*gen));
  memcpy(gen, gen0, sizeof(*gen));
  if (gen->type == GEN_TRACE32) {
    FILE * const f2 = fdopen(dup(fileno(gen0->trace32.fin)), "rb");
    gen->trace32.fin = f2;
    gen->trace32.idx = 0;
    gen->trace32.avail = 0;
  }
  return gen;
}

  void
rgen_join(struct rgen * const gen)
{
  if (!gen->shared)
    rgen_destroy(gen);
}

  static void *
rgen_async_create_mem_worker(void * const ptr)
{
  struct rgen_async * const as = (typeof(as))ptr;
  size_t sz = 0;
  as->mem = pages_alloc_best(RGEN_ABUF_SZ, true, &sz);
  debug_assert(sz == RGEN_ABUF_SZ);
  return NULL;
}

  struct rgen *
rgen_async_create(struct rgen * const gen0, const u32 cpu)
{
  if (gen0 == NULL || gen0->type == GEN_ASYNC)
    return NULL;

  struct rgen * const agen = calloc(1, sizeof(*agen));
  struct rgen_async * const as = &(agen->async);

  as->real_gen = gen0;
  pthread_t pt_mem;
  thread_create_at(cpu, &pt_mem, rgen_async_create_mem_worker, as);
  pthread_join(pt_mem, NULL);
  if (as->mem == NULL) {
    fprintf(stderr, "%s: cannot allocate memory for the async worker\n", __func__);
    free(agen);
    return NULL; // insufficient memory
  }

  as->running = true; // create thread below
  as->curr = as->mem;
  as->guard = as->mem + RGEN_ABUF_SZ1;
  // gen
  agen->next = gen0->unit_u64 ? rgen_async_next_64 : rgen_async_next_32;
  agen->next_nowait = gen0->unit_u64 ? rgen_async_next_64_nowait : rgen_async_next_32_nowait;
  agen->type = GEN_ASYNC;
  agen->unit_u64 = gen0->unit_u64;
  agen->min = gen0->min;
  agen->max = gen0->max;

  // start worker
  if (thread_create_at(cpu, &(as->pt), rgen_async_worker, agen) == 0) {
    char thname[32];
    sprintf(thname, "agen_%u", cpu);
    thread_set_name(as->pt, thname);
    gen0->async_worker = true; // deprecated
    return agen;
  } else {
    rgen_async_clean_buffers(as);
    free(agen);
    return NULL;
  }
}
// }}} async

// }}} rgen

// multi-rcu {{{

// bits 63 -- 16 value (pointer)
// bits 15       valid
// bits 14 -- 0  count (refcount)
#define RCU_COUNT_MASK   ((0x0000000000007ffflu))
#define RCU_VALID_MASK   ((0x0000000000008000lu))
#define RCU_VALUE_MASK   ((0xffffffffffff0000lu))
#define RCU_VALUE_SHIFT  ((16))

// node {{{
struct rcu_node {
  au64 x[8];
};

  void
rcu_node_init(struct rcu_node * const node)
{
  atomic_store(&(node->x[0]), RCU_VALID_MASK); // valid null pointer
  atomic_store(&(node->x[1]), RCU_VALUE_MASK); // invalid non-null pointer
}

  struct rcu_node *
rcu_node_create(void)
{
  struct rcu_node * const node = malloc(sizeof(*node));
  rcu_node_init(node);
  return node;
}

  void *
rcu_node_ref(struct rcu_node * const node)
{
  do {
    for (u64 i = 0; i < 2; i++) {
      u64 x = node->x[i];
      if (x & RCU_VALID_MASK) {
        if (atomic_compare_exchange_weak(&(node->x[i]), &x, x + 1))
          return (void *)(x >> RCU_VALUE_SHIFT);
      }
    }
  } while (true);
}

  void
rcu_node_unref(struct rcu_node * const node, void * const ptr)
{
  for (u64 i = 0; i < 2; i++) {
    const u64 x = node->x[i];
    if ((x >> RCU_VALUE_SHIFT) == ((u64)ptr)) {
      (void)atomic_fetch_sub(&(node->x[i]), 1);
      return;
    }
  }
  debug_die();
}

  void
rcu_node_update(struct rcu_node * const node, void * const ptr)
{
  const u64 xx = (((u64)ptr) << RCU_VALUE_SHIFT) | RCU_VALID_MASK;
  for (u64 i = 0; i < 2; i++) {
    if ((node->x[i] & RCU_VALID_MASK) == 0) {
      atomic_store(&(node->x[i]), xx);
      au64 * const v = &(node->x[1-i]);
      debug_assert(((*v) >> RCU_VALUE_SHIFT) != ((u64)ptr));
      (void)atomic_fetch_sub(v, RCU_VALID_MASK);
#pragma nounroll
      while (atomic_load(v) & RCU_COUNT_MASK)
        cpu_pause();
      return;
    }
  }
  debug_die();
}
// }}} node

struct rcu {
  u64 nr;
  u64 mask;
  u64 padding[6];
  struct rcu_node nodes[];
};

  void
rcu_init(struct rcu * const rcu, const u64 nr)
{
  rcu->nr = nr;
  rcu->mask = nr - 1;
  for (u64 i = 0; i < nr; i++)
    rcu_node_init(&(rcu->nodes[i]));
}

  struct rcu *
rcu_create(const u64 nr)
{
  struct rcu * const rcu = yalloc(sizeof(*rcu) + (nr * sizeof(rcu->nodes[0])));
  rcu_init(rcu, nr);
  return rcu;
}

  void *
rcu_ref(struct rcu * const rcu, const u64 magic)
{
  struct rcu_node * const node = &(rcu->nodes[magic & rcu->mask]);
  return rcu_node_ref(node);
}

  void
rcu_unref(struct rcu * const rcu, void * const ptr, const u64 magic)
{
  struct rcu_node * const node = &(rcu->nodes[magic & rcu->mask]);
  rcu_node_unref(node, ptr);
}

  void
rcu_update(struct rcu * const rcu, void * const ptr)
{
  const u64 xx = (((u64)ptr) << RCU_VALUE_SHIFT) | RCU_VALID_MASK;
  const u64 nr = rcu->nr;
  for (u64 i = 0; i < nr; i++) {
    struct rcu_node * const node = &(rcu->nodes[i]);
    for (u64 j = 0; j < 2; j++) {
      if ((node->x[j] & RCU_VALID_MASK) == 0) {
        // enable node pointer
        atomic_store(&(node->x[j]), xx);
        au64 * const v = &(node->x[1-j]);
        debug_assert(((*v) >> RCU_VALUE_SHIFT) != ((u64)ptr));
        (void)atomic_fetch_sub(v, RCU_VALID_MASK);
        break;
      }
    }
  }
  cpu_cfence();
  // wait
  for (u64 i = 0; i < nr; i++) {
    struct rcu_node * const node = &(rcu->nodes[i]);
    for (u64 j = 0; j < 2; j++) {
      const u64 x = node->x[j];
      if ((x & RCU_VALID_MASK) == 0) {
        au64 * const v = &(node->x[j]);
#pragma nounroll
        while (atomic_load(v) & RCU_COUNT_MASK)
          cpu_pause();
        break;
      }
    }
  }
}

#undef RCU_COUNT_MASK
#undef RCU_VALID_MASK
#undef RCU_VALUE_MASK
#undef RCU_VALUE_SHIFT
// }}} multi-rcu

// qsbr {{{
#define QSBR_STATES_NR ((23)) // 3*8-2 == 22; 5*8-2 == 38; 7*8-2 == 54
#define QSBR_BITMAP_FULL ((1lu << QSBR_STATES_NR) - 1)
#define QSBR_SHARD_BITS  ((5)) // bits <= 6
#define QSBR_SHARD_NR    (((1u) << QSBR_SHARD_BITS))
#define QSBR_SHARD_MASK  ((QSBR_SHARD_NR - 1))

struct qsbr_ref_real {
#ifdef QSBR_DEBUG
  pthread_t ptid; // 8
  u32 status; // 4
  u32 nbt; // 4 (number of backtrace frames)
#define QSBR_DEBUG_BTNR ((14))
  void * backtrace[QSBR_DEBUG_BTNR];
#endif
  volatile au64 qstate; // user updates it
  struct qsbr_ref_real * volatile * pptr; // internal only
  struct qsbr_ref_real * park;
};

static_assert(sizeof(struct qsbr_ref) == sizeof(struct qsbr_ref_real), "sizeof qsbr_ref");

// Quiescent-State-Based Reclamation RCU
struct qsbr {
  struct qsbr_ref_real target;
  u64 padding0[5];
  struct qshard {
    au64 bitmap;
    struct qsbr_ref_real * volatile ptrs[QSBR_STATES_NR];
  } shards[QSBR_SHARD_NR];
};

  struct qsbr *
qsbr_create(void)
{
  struct qsbr * const q = yalloc(sizeof(*q));
  memset(q, 0, sizeof(*q));
  return q;
}

  static inline struct qshard *
qsbr_shard(struct qsbr * const q, void * const ptr)
{
  const u32 sid = crc32c_u64(0, (u64)ptr) & QSBR_SHARD_MASK;
  debug_assert(sid < QSBR_SHARD_NR);
  return &(q->shards[sid]);
}

  static inline void
qsbr_write_qstate(struct qsbr_ref_real * const ref, const u64 v)
{
  atomic_store_explicit(&ref->qstate, v, MO_RELAXED);
}

  bool
qsbr_register(struct qsbr * const q, struct qsbr_ref * const qref)
{
  struct qsbr_ref_real * const ref = (typeof(ref))qref;
  struct qshard * const shard = qsbr_shard(q, ref);
  qsbr_write_qstate(ref, 0);

  do {
    u64 bits = atomic_load_explicit(&shard->bitmap, MO_CONSUME);
    if (unlikely(bits == QSBR_BITMAP_FULL))
      return false;

    const u32 pos = (u32)__builtin_ctzl(~bits);
    const u64 bits1 = bits | (1lu << pos);
    debug_assert(pos < QSBR_STATES_NR);
    if (atomic_compare_exchange_weak_explicit(&shard->bitmap, &bits, bits1, MO_ACQUIRE, MO_RELAXED)) {
      shard->ptrs[pos] = ref;

      ref->pptr = &(shard->ptrs[pos]);
      ref->park = &q->target;
#ifdef QSBR_DEBUG
      ref->ptid = (u64)pthread_self();
      ref->tid = 0;
      ref->status = 1;
      ref->nbt = backtrace(ref->backtrace, QSBR_DEBUG_BTNR);
#endif
      return true;
    }
  } while (true);
}

  void
qsbr_unregister(struct qsbr * const q, struct qsbr_ref * const qref)
{
  struct qsbr_ref_real * const ref = (typeof(ref))qref;
  struct qshard * const shard = qsbr_shard(q, ref);
  const u32 pos = (u32)(ref->pptr - shard->ptrs);
  debug_assert(pos < QSBR_STATES_NR);
  debug_assert(shard->bitmap & (1lu << pos));
  shard->ptrs[pos] = &q->target;
  atomic_fetch_and_explicit(&shard->bitmap, ~(1lu << pos), MO_RELEASE);
#ifdef QSBR_DEBUG
  ref->tid = 0;
  ref->ptid = 0;
  ref->status = 0xffff; // unregistered
  ref->nbt = 0;
#endif
  ref->pptr = NULL;
}

  inline void
qsbr_update(struct qsbr_ref * const qref, const u64 v)
{
  struct qsbr_ref_real * const ref = (typeof(ref))qref;
  debug_assert((*ref->pptr) == ref); // must be unparked
  // rcu update does not require release or acquire order
  qsbr_write_qstate(ref, v);
}

  inline void
qsbr_park(struct qsbr_ref * const qref)
{
  cpu_cfence();
  struct qsbr_ref_real * const ref = (typeof(ref))qref;
  *ref->pptr = ref->park;
#ifdef QSBR_DEBUG
  ref->status = 0xfff; // parked
#endif
}

  inline void
qsbr_resume(struct qsbr_ref * const qref)
{
  struct qsbr_ref_real * const ref = (typeof(ref))qref;
  *ref->pptr = ref;
#ifdef QSBR_DEBUG
  ref->status = 0xf; // resumed
#endif
  cpu_cfence();
}

// waiters needs external synchronization
  void
qsbr_wait(struct qsbr * const q, const u64 target)
{
  cpu_cfence();
  qsbr_write_qstate(&q->target, target);
  u64 cbits = 0; // check-bits
  u64 bms[QSBR_SHARD_NR]; // copy of all bitmap
  // take an unsafe snapshot of active users
  for (u32 i = 0; i < QSBR_SHARD_NR; i++) {
    bms[i] = atomic_load_explicit(&q->shards[i].bitmap, MO_CONSUME);
    if (bms[i])
      cbits |= (1lu << i); // set to 1 if [i] has ptrs
  }

  while (cbits) {
    for (u64 ctmp = cbits; ctmp; ctmp &= (ctmp - 1)) {
      const u32 i = (u32)__builtin_ctzl(ctmp);
      struct qshard * const shard = &(q->shards[i]);
      const u64 bits1 = atomic_load_explicit(&(shard->bitmap), MO_CONSUME);
      for (u64 bits = bms[i]; bits; bits &= (bits - 1)) {
        const u64 bit = bits & -bits; // extract lowest bit
        if (((bits1 & bit) == 0) ||
            (atomic_load_explicit(&(shard->ptrs[__builtin_ctzl(bit)]->qstate), MO_CONSUME) == target))
          bms[i] &= ~bit;
      }
      if (bms[i] == 0)
        cbits &= ~(1lu << i);
    }
#if defined(CORR)
    corr_yield();
#endif
  }
  debug_assert(cbits == 0);
  cpu_cfence();
}

  void
qsbr_destroy(struct qsbr * const q)
{
  if (q)
    free(q);
}
#undef QSBR_STATES_NR
#undef QSBR_BITMAP_NR
// }}} qsbr

// server {{{
struct server {
  int fd;
  bool running;
  pthread_t pt;
  void *(*worker)(void *);
  void * priv;
  au64 ncli;
};

struct server_wi {
  struct server * server;
  int fd;
};

  static void *
server_master(void * const ptr)
{
  const u32 nr_cores0 = process_affinity_count();
  u32 * const cores = calloc(nr_cores0, sizeof(cores[0]));
  const u32 nr_cores = process_getaffinity_list(nr_cores0, cores);
  u32 seq = 0;

  struct server * const server = (typeof(server))ptr;
  while (server->running) {
    struct pollfd pfd = {.fd = server->fd, .events = POLLIN};
    const int rp = poll(&pfd, 1, 50);
    if (rp == 0)
      continue;
    if (rp < 0)
      break;
    const int cli = accept(server->fd, NULL, NULL);
    if (cli < 0) {
      if (errno == EINTR)
        continue; // retry
      else
        break; // fatal
    }
    pthread_t worker;
    struct server_wi * const wi = malloc(sizeof(*wi));
    wi->server = server;
    wi->fd = cli;
    const int r = thread_create_at(cores[seq], &worker, server->worker, wi);
    if (r != 0) {
      close(cli);
      free(wi);
      continue;
    }
    pthread_detach(worker);
    server->ncli++;
    seq++;
    if (seq >= nr_cores)
      seq = 0;
  }
  free(cores);
  close(server->fd);
  // wait for client threads
  while (server->ncli)
    usleep(100);
  return NULL;
}

  struct server *
server_create(const char * const host, const char * const port,
    void * (* worker)(void *), void * const priv)
{
  struct addrinfo hint = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
  struct addrinfo * ai = NULL;
  if (getaddrinfo(host, port, &hint, &ai))
    return NULL;

  int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (fd < 0)
    goto fail_fd;
  int reuse = 1; // true
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
  if (bind(fd, ai->ai_addr, ai->ai_addrlen) || listen(fd, 64))
    goto fail_listen;

  struct server * const server = malloc(sizeof(*server));
  if (!server)
    goto fail_listen;
  server->running = true;
  server->fd = fd;
  server->worker = worker;
  server->priv = priv;
  server->ncli = 0;
  if (pthread_create(&(server->pt), NULL, server_master, server))
    goto fail_th;

  freeaddrinfo(ai);
  return server;

fail_th:
  free(server);
fail_listen:
  close(fd);
fail_fd:
  freeaddrinfo(ai);
  return NULL;
}

  void
server_wait_destroy(struct server * const server)
{
  pthread_join(server->pt, NULL);
  free(server);
}

  void
server_kill_destroy(struct server * const server)
{
  server->running = false;
  // the server thread will close fd
  shutdown(server->fd, SHUT_RDWR);
  pthread_join(server->pt, NULL);
  free(server);
}

  int
server_worker_fd(struct server_wi * const wi)
{
  return wi->fd;
}

  void *
server_worker_priv(struct server_wi * const wi)
{
  return wi->server->priv;
}

__attribute__((noreturn))
  void
server_worker_exit(struct server_wi * const wi)
{
  wi->server->ncli--;
  close(wi->fd);
  free(wi);
  pthread_exit(NULL);
}

  int
client_connect(const char * const host, const char * const port)
{
  struct addrinfo hint = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
  struct addrinfo * ai = NULL;
  if (getaddrinfo(host, port, &hint, &ai) != 0)
    return -1;

  const int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (fd < 0) {
    freeaddrinfo(ai);
    return -1;
  }
  if (connect(fd, ai->ai_addr, ai->ai_addrlen)) {
    freeaddrinfo(ai);
    close(fd);
    return -1;
  }
  freeaddrinfo(ai);
  return fd;
}
// }}} server

// forker {{{
#define FORKER_PAPI_MAX_EVENTS ((14))
static u64 forker_papi_nr = 0;

#ifdef FORKER_PAPI
#include <papi.h>
static int forker_papi_events[FORKER_PAPI_MAX_EVENTS] = {};
static char ** forker_papi_tokens = NULL;
__attribute__((constructor))
  static void
forker_papi_init(void)
{
  PAPI_library_init(PAPI_VER_CURRENT);
  PAPI_thread_init(pthread_self);

  char ** const tokens = string_tokens(getenv("FORKER_PAPI_EVENTS"), ",");
  if (tokens == NULL)
    return;
  u64 nr = 0;
  while (tokens[nr] && (nr < FORKER_PAPI_MAX_EVENTS)) {
    if (PAPI_OK == PAPI_event_name_to_code(tokens[nr], &forker_papi_events[nr]))
      nr++;
  }
  forker_papi_nr = nr;
  forker_papi_tokens = tokens;
}

__attribute__((destructor))
  static void
forker_papi_deinit(void)
{
  //PAPI_shutdown(); // even more memory leaks
  free(forker_papi_tokens);
}

  static void *
forker_papi_thread_func(void * const ptr)
{
  struct forker_worker_info * const wi = (typeof(wi))ptr;
  bool papi_ok = false;
  int es = PAPI_NULL;
  if (forker_papi_nr && (PAPI_create_eventset(&es) == PAPI_OK)) {
    if (PAPI_OK == PAPI_add_events(es, forker_papi_events, forker_papi_nr)) {
      PAPI_start(es);
      papi_ok = true;
    } else {
      PAPI_destroy_eventset(&es);
    }
  }
  void * const ret = wi->thread_func(ptr);
  if (papi_ok) {
    u64 v[FORKER_PAPI_MAX_EVENTS];
    if (PAPI_OK == PAPI_stop(es, (long long *)v))
      for (u64 i = 0; i < forker_papi_nr; i++)
        vctr_set(wi->vctr, wi->papi_vctr_base + i, v[i]);

    PAPI_destroy_eventset(&es);
  }
  return ret;
}

  static void
forker_papi_print(FILE * fout, const struct vctr * const vctr, const u64 base)
{
  if (forker_papi_nr == 0)
    return;
  const bool use_color = isatty(fileno(fout));
  if (use_color)
    fputs(TERMCLR(36), fout);
  fprintf(fout, "PAPI %lu ", forker_papi_nr);
  for (u64 i = 0; i < forker_papi_nr; i++)
    fprintf(fout, "%s %lu ", forker_papi_tokens[i]+5, vctr_get(vctr, base+i));
  if (use_color)
    fputs(TERMCLR(0), fout);
}
#endif // FORKER_PAPI

  static void
forker_pass_print(FILE * fout, char ** const pref, int argc, char ** const argv, char * const msg)
{
  for (int i = 0; pref[i]; i++)
    fprintf(fout, "%s ", pref[i]);
  for (int i = 0; i < argc; i++)
    fprintf(fout, "%s ", argv[i]);

  const bool use_color = isatty(fileno(fout));
  if (use_color)
    fputs(TERMCLR(34), fout);
  fputs(msg, fout);
  if (use_color)
    fputs(TERMCLR(0), fout);

  fflush(fout);
}

  int
forker_pass(const int argc, char ** const argv, char ** const pref,
    struct pass_info * const pi, const int nr_wargs0)
{
#define FORKER_GEN_SYNC   ((0))
  //      FORKER_GEN_WAIT   ((1))
#define FORKER_GEN_NOWAIT ((2))
  // pass <nth> <end-type> <magic> <repeat> <rgen_opt> <nr_wargs> ...
#define PASS_NR_ARGS ((7))
  if ((argc < PASS_NR_ARGS) || (strcmp(argv[0], "pass") != 0))
    return -1;

  const u32 c = a2u32(argv[1]);
  const u32 cc = c ? c : process_affinity_count();
  const u32 end_type = a2u32(argv[2]);
  const u64 magic = a2u64(argv[3]);
  const u32 repeat = a2u32(argv[4]);
  const u32 rgen_opt = a2u32(argv[5]);
  const int nr_wargs = atoi(argv[6]);
  if ((end_type > 1) || (rgen_opt > 2) || (nr_wargs != nr_wargs0))
    return -1;
  if (argc < (PASS_NR_ARGS + nr_wargs))
    return -1;

  const u32 nr_cores = process_affinity_count();
  u32 cores[CPU_SETSIZE];
  process_getaffinity_list(nr_cores, cores);
  struct damp * const damp = damp_create(7, 0.004, 0.05);
  const char * const ascfg = getenv("FORKER_ASYNC_SHIFT");
  const u32 async_shift = ascfg ? ((u32)a2s32(ascfg)) : 1;

  char out[1024] = {};
  // per-worker data
  struct forker_worker_info ** const wis = (typeof(wis))calloc_2d(cc, sizeof(*wis[0]));
  for (u32 i = 0; i < cc; i++) {
    struct forker_worker_info * const wi = wis[i];
    wi->thread_func = pi->wf;
    wi->passdata[0] = pi->passdata[0];
    wi->passdata[1] = pi->passdata[1];
    wi->gen = rgen_fork(pi->gen0);
    wi->seed = (i + 73) * 117;
    wi->end_type = end_type;
    if (end_type == FORKER_END_COUNT) // else: endtime will be set later
      wi->end_magic = magic;
    wi->worker_id = i;
    wi->conc = cc;

    // user args
    wi->argc = nr_wargs;
    wi->argv = argv + PASS_NR_ARGS;

    wi->vctr = vctr_create(pi->vctr_size + forker_papi_nr);
    wi->papi_vctr_base = pi->vctr_size;

    if (rgen_opt != FORKER_GEN_SYNC) {
      wi->gen_back = wi->gen;
      wi->gen = rgen_async_create(wi->gen_back, cores[i % nr_cores] + async_shift);
      debug_assert(wi->gen);
    }
    wi->rgen_next = (rgen_opt == FORKER_GEN_NOWAIT) ? wi->gen->next_nowait : wi->gen->next;
    // use a different next_write ONLY in one case: sync latest
    wi->rgen_next_write = (wi->gen->type == GEN_LATEST) ? wi->gen->next_write : wi->rgen_next;
  }

  bool done = false;
  FILE * fout[2] = {stdout, stderr};
  const u32 printnr = isatty(fileno(stderr)) ? 1 : 2; // when stderr is not a tty, also print to stderr
  struct vctr * const va = vctr_create(pi->vctr_size + forker_papi_nr);
  struct vctr * const vas = vctr_create(pi->vctr_size + forker_papi_nr);
  u64 dts = 0;
  const u64 t0 = time_nsec();
  // until: repeat times, or done determined by damp
  for (u32 r = 0; repeat ? (r < repeat) : (done == false); r++) {
    // prepare
    const u64 dt1 = time_diff_nsec(t0);
    for (u32 i = 0; i < cc; i++) {
      vctr_reset(wis[i]->vctr);
      rgen_async_wait_all(wis[i]->gen);
    }

    // set end-time
    if (end_type == FORKER_END_TIME) {
      const u64 end_time = time_nsec() + (1000000000lu * magic);
      for (u32 i = 0; i < cc; i++)
        wis[i]->end_magic = end_time;
    }

    const long rs0 = process_get_rss();

    debug_perf_switch();
#ifdef FORKER_PAPI
    const u64 dt = thread_fork_join(cc, forker_papi_thread_func, true, (void **)wis);
#else
    const u64 dt = thread_fork_join(cc, pi->wf, true, (void **)wis);
#endif
    debug_perf_switch();
    dts += dt;
    const long rs1 = process_get_rss();

    vctr_reset(va);
    for (u64 i = 0; i < cc; i++)
      vctr_merge(va, wis[i]->vctr);
    vctr_merge(vas, va); // total

    done = pi->af(dt, va, damp, out);
    for (u32 i = 0; i < printnr; i++) {
      fprintf(fout[i], "rss_kb %+ld r %u %.2lf %.2lf ", rs1 - rs0, r, ((double)dt1) * 1e-9, ((double)dt) * 1e-9);
#ifdef FORKER_PAPI
      forker_papi_print(fout[i], va, pi->vctr_size);
#endif // FORKER_PAPI
      forker_pass_print(fout[i], pref, PASS_NR_ARGS + nr_wargs, argv, out);
    }
  }

  damp_clean(damp);
  pi->af(dts, vas, damp, out);
  for (u32 i = 0; i < printnr; i++) {
    fprintf(fout[i], "total %.2lf ", ((double)dts) * 1e-9);
    forker_pass_print(fout[i], pref, PASS_NR_ARGS + nr_wargs, argv, out);
  }

  // clean up
  vctr_destroy(va);
  vctr_destroy(vas);
  damp_destroy(damp);
  for (u64 i = 0; i < cc; i++) {
    if (wis[i]->gen_back) {
      rgen_destroy(wis[i]->gen); // async
      rgen_join(wis[i]->gen_back); // real
    } else {
      rgen_join(wis[i]->gen); // real
    }
    vctr_destroy(wis[i]->vctr);
  }
  free(wis);

  // done messages
  return PASS_NR_ARGS + nr_wargs;
#undef PASS_NR_ARGS
#undef FORKER_GEN_SYNC
#undef FORKER_GEN_NOWAIT
}

  int
forker_passes(int argc, char ** argv, char ** const pref0,
    struct pass_info * const pi, const int nr_wargs0)
{
  char * pref[64];
  int np = 0;
  while (pref0[np]) {
    pref[np] = pref0[np];
    np++;
  }
  const int n1 = np;

  const int argc0 = argc;
  do {
    struct rgen * gen = NULL;
    if ((argc < 1) || (strcmp(argv[0], "rgen") != 0))
      break;

    const int n2 = rgen_helper(argc, argv, &gen);
    if (n2 < 0)
      return n2;

    memcpy(&(pref[n1]), argv, sizeof(argv[0]) * (size_t)n2);

    pref[n1 + n2] = NULL;
    argc -= n2;
    argv += n2;

    while ((argc > 0) && (strcmp(argv[0], "pass") == 0)) {
      pi->gen0 = gen;
      const int n3 = forker_pass(argc, argv, pref, pi, nr_wargs0);
      if (n3 < 0) {
        rgen_destroy(gen);
        return n3;
      }

      argc -= n3;
      argv += n3;
    }

    rgen_destroy(gen);
  } while (argc > 0);
  return argc0 - argc;
}

  void
forker_passes_message(void)
{
  fprintf(stderr, "%s Usage: {rgen ... {pass ...}}\n", __func__);
  rgen_helper_message();
  fprintf(stderr, "%s Usage: pass <nth> " TERMCLR(31) "<magic-type>" TERMCLR(0), __func__);
  fprintf(stderr, " <magic> <repeat> " TERMCLR(34) "<rgen-opt>" TERMCLR(0));
  fprintf(stderr, " <nr-wargs> [<warg1> <warg2> ...]\n");
  fprintf(stderr, "%s " TERMCLR(31) "magic-type: 0:time, 1:count" TERMCLR(0) "\n", __func__);
  fprintf(stderr, "%s repeat: 0:auto\n", __func__);
  fprintf(stderr, "%s " TERMCLR(34) "rgen-opt: 0:sync, 1:wait, 2:nowait" TERMCLR(0) "\n", __func__);
#ifdef FORKER_PAPI
  fprintf(stderr, "Run with FORKER_PAPI_EVENTS=e1,e2,... to use papi. Run papi_avail for available events.\n");
#else
  fprintf(stderr, "Compile with FORKER_PAPI=y to enable papi. Don't use papi and perf at the same time.\n");
#endif
  fprintf(stderr, "Run with env FORKER_ASYNC_SHIFT=s (default=1) to bind async-workers at core x+s\n");
}

  bool
forker_main(int argc, char ** argv, int(*test_func)(const int, char ** const))
{
  if (argc < 1)
    return false;

  // record args
  for (int i = 0; i < argc; i++)
    fprintf(stderr, " %s", argv[i]);

  fprintf(stderr, "\n");
  fflush(stderr);

  while (argc) {
    if (strcmp(argv[0], "api") != 0) {
      fprintf(stderr, "%s need `api' keyword to start benchmark\n", __func__);
      return false;
    }
    const int consume = test_func(argc, argv);
    if (consume < 0)
      return false;

    debug_assert(consume <= argc);
    argc -= consume;
    argv += consume;
  }

  return true;
}
// }}} forker

// vim:fdm=marker
