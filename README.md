# REMIX and RemixDB

The REMIX data structure was introduced in paper ["REMIX: Efficient Range Query for LSM-trees", FAST'21](https://www.usenix.org/conference/fast21/presentation/zhong).

This repository maintains a reference implementation of the REMIX index data structure,
as well as a thread-safe embedded key-value store implementation, namely RemixDB.
It compiles on recent Linux/FreeBSD/MacOS and supports x86\_64 and AArch64 CPUs.

This code repository is being actively maintained and contains optimizations beyong the original RemixDB implementation.

# Optimization 1: Minimizing REMIX (Re-)Building Cost

This implementation employs an optimization to minimize the REMIX building cost.
This optimization improves the throughput by 2x (0.96MOPS vs. 0.50MOPS) in a random-write experiment, compared to the implementation described in the REMIX paper.
Configuration: klen=16; vlen=120; 2.02 billion KVs; 256GB valid KV data; single-threaded loading in random order; no compression.

When creating a new table file, RemixDB can create a copy of all the keys in the table.
Specificially, it encodes all the keys (without values) in sorted order using prefix compression, which creates a *Compressed Keys Block* (*CKB*).
The CKB is stored at the end of the table file.
This feature can be freely turned on and off. There is no compatibility issue when tables with and without the CKB are used together.

When creating a new REMIX, the building process will check if every input table contains a CKB.
If true, the process will build the new REMIX using these CKBs. It also leverages the existing REMIX to avoid unncecssary key comparisons.
In this way, the new REMIX will be created by reading the old REMIX and the CKBs, without accessing the key-value data blocks of the table files.

In a running system the old REMIX structures are usually cache-resident.
The CKBs are only used for REMIX building, which are read into memory in batch, and discarded once the building is finished.

A CKB is often much smaller than the original key-value data block, unless the system manages huge keys with small values.
Suppose the average CKB size is 10% of the average key-value data block size,
this optimization trades 10% more write I/O and storage space usage for a 90% reduction of read I/O during REMIX building.

`remixdb_open` opens/creates a remixdb with the optimization turned on. Each newly created sstable will have the CKB.
You should use `remixdb_open` unless it's absolutely necessary to save a little bit disk space.
`remixdb_open_compact` opens a remixdb with the optimization turned off. Each newly created sstable will not contain a CKB.
A store created by one of these functions can be safely opened by the other function.

# Optimization 2: Improving Point Query with Hash Tags

A point query in the original RemixDB performs binary search in a segment, which takes about five key comparisons and can cost multiple I/Os.
The current implementation provides a new option, named `tags` (the last argument of `remixdb_open`).

With this option enabled, every new REMIX will store an array of 8-bit hash tags. Each tag corresponds to a key managed by the REMIX.
A point query (GET/PROBE) will first locate the target segment as usual.
 Then it will check the tags to find candidate keys for full-key matching without using binary search in the segment.
With 8-bit tags and at most 32 keys in a segment, a point query takes about 1.06 key comparisons if the key is found,
and about 0.12 key comparisons if the key does not exist.

TODO: the tags can also be used to speed up iterator seeks with existing keys.

# Limitations of the Current Implementation

* *KV size*: The maximum key+value size is capped at 65500 bytes.
This roughly corresponds to the 64KB block size limit.
TODO: store huge KV pairs in a separate file and store the file address of the KV pair in RemixDB.

# Configuration and Tuning

## CPU affinity
RemixDB employs background threads to perform asynchronous compaction.
When possible (on Linux or FreeBSD), these threads are pinned on specific cores for efficiency.
To avoid interferences with the foreground threads, it is necessary to separate the cores used by different threads.
By default, RemixDB pins 4 compaction threads on the last four cores of the current process's affinity list.
For example, on a machine with two 10-core processors, cores 0,2,4,...,16,18 belong to numa node 0,
and the rest cores belong to numa node 1.
The default behavior is to use the cores from 16 to 19, which is a suboptimal setup.
To avoid the performance penalty, one should use `numactl` to specify the cpu affinity.

```
$ numactl -C 0,2,4,6,8 ./xdbdemo.out    # compaction threads on 2,4,6,8

$ numactl -C 0,2,4,6,8,10,12,14 ./xdbtest.out 256 256 18 18 100    # user threads on 0,2,4,6; compaction threads on 8,10,12,14
```

The worker threads affinity can also be explicitly specified using `xdb_open`.

## Maximum number of open files
The current implementation keeps every table file open at run time.
This requires a large `nofile` in `/etc/security/limits.conf`.
For example, add `* - nofile 100000` to `limits.conf`, reboot/relogin, and double-check with `ulimit -n`.

## Maximum Table File Size
`MSSTZ_NBLKS` (sst.c) controls the maximum number of 4KB blocks in an SST file.  The default number is 20400.
The maximum value is 65520 (256MB data blocks, plus metadata).

## Hugepages

Configuring huge pages can effectively improve RemixDB's performance.
Usually a few hundred 2MB hugepages would be sufficient for memory allocation in MemTables.
The block cache automatically detects and uses 1GB huge pages when available (otherwise, fall back to 2MB pages, and then 4KB pages).
4x 1GB huge pages should be configured if you set cache size to 4GB.

# Getting Started

RemixDB by default uses `liburing` (`io_uring`) and thus requires a Linux kernel >= 5.1.
It also works with POSIX AIO on all the supported platforms but the performance can be negatively affected.

`clang` is the default compiler. It usually produces faster code than GCC. To use GCC:

    $ make CCC=gcc

`jemalloc` is highly recommended. If jemalloc is available and you prefer to use it, use `M=j` with `make`:

    $ make M=j

Similarly, `tcmalloc` can be linked with `M=t`.

The `xdbdemo.c` contains sample code that uses the `remixdb_*` functions.
These functions present a clean programming interface without using special data types or structures.

## xdbdemo
To compile and run the demo code:

    $ make M=j xdbdemo.out
    $ ./xdbdemo.out

## xdbtest

`xdbtest` is a stress test program that uses the `remixdb_*` functions.
It trys to use all the available cores on the affinity list, which can lead to mediocre performance.
You should use numactl to specify what cores are available for the tester threads.
Suppose you have eight cores (0...7) in total, the best practice is to let the testers to run on the first four cores and assign the last four cores to the compaction threads. The following examples use this configuration.

Run with a 4GB block cache, 4GB MemTables, and a dataset with 32 million KVs (2^25), performing 1 million updates in each round (2^20):

    $ make M=j xdbtest.out
    $ numactl -N 0 ./xdbtest.out /tmp/xdbtest 4096 4096 25 20 100

To run with smaller memory footprint (a 256MB block cache, 256MB Memtables, and 1 million KVs):

    $ numactl -N 0 ./xdbtest.out /tmp/xdbtest 256 256 20 20 100

This setup consumes up to 850MB memory (RSS) and 1.8GB space in /tmp/xdbtest.

A first run of xdbtest.out should always show stale=0.
If you run it again without deleting `/tmp/xdbtest`,
it will show non-zero stale numbers at the beginning but it will quickly drop and eventually reach zero.

## xdbexit

`xdbexit` is a simple program testing crash-recovery.
It inserts some new keys and calls `remixdb_sync()` to make all buffered data persist in the WAL.
Then it immediately calls `exit()` without doing any clean-up.
Run it repeatedly. In each run it should show that all the previously inserted KVs are found.

Run with a small footprint:

    $ for i in $(seq 1 30); do ./xdbexit.out ./dbdir 256 256; done

Run with in a regular-sized setup:

    $ for i in $(seq 1 30); do ./xdbexit.out ./dbdir 4096 4096; done

## libremixdb.so

To use remixdb as a shared library, run `make libremixdb.so` and `make install`.
A PKGBUILD (for Archlinux's pacman) is included as an example packaging script.
