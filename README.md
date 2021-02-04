# REMIX and RemixDB

The REMIX data structure was introduced in paper ["REMIX: Efficient Range Query for LSM-trees", FAST'21](https://www.usenix.org/conference/fast21/presentation/zhong).

This repository maintains a reference implementation of the REMIX index data structure,
as well as a thread-safe embedded key-value store implementation, namely RemixDB.
It compiles on recent Linux/FreeBSD/MacOS and supports x86\_64 and AArch64 CPUs.

# Limitations of the Current Implementation

* *KV size*: The maximum key+value size is capped at 65500 bytes.
This roughly corresponds to the 64KB block size limit.
TODO: store every huge value in a separate file and recording the file name as the value of the KV pair in RemixDB.

* *WAL recovery*: The log-recovery process has not been implemented.
Currently RemixDB performs a final compaction upon closing so all the data will be available when it gets reopened.
When a process running RemixDB crashes or gets killed, data buffered in the WAL will not be read.
TODO: implement the full WAL mechainisms to provide the same log-recovery semantics of LevelDB.

# Optimization: Minimizing REMIX (Re-)Building Cost

This implementation employs an optimization to minimize the REMIX building cost.

When creating a new table file, RemixDB can create a copy of all the keys in the table.
Specificially, it encodes all the keys (without values) in sorted order using prefix compression, which creates a *compressed keys block*.
The compressed keys block is stored at the end of the table file.
This feature can be freely turned on and off. There is no compatibility issue when tables with and without the compressed keys block are used together.

When creating a new REMIX, the building process will check if all the input tables contain such an compressed keys block.
If true, the process will build the new REMIX using these blocks. It also leverages the existing REMIX to avoid unncecssary key comparisons.
In this way, the new REMIX will be created by reading the old REMIX and the compressed keys blocks, without accessing the key-value data blocks of the table files.

In a running system the old REMIX structures are usually cache-resident.
The compressed keys blocks are only used for REMIX building, which are read into memory in batch, and discarded once the building is finished.

An compressed keys block is often much smaller than the original key-value data block, unless the system manages huge keys with small values.
Suppose the average compressed keys block size is 10% of the key-value data block,
this optimization trades 10% more write I/O and storage space usage for a 90% reduction of read I/O during REMIX building.

`remixdb_open` opens/creates a remixdb with the optimization turned on. New sstables will have the compressed keys block.
You should use `remixdb_open` unless you're sure its absolutely necessary to save a little bit disk space.
`remixdb_open_compact` opens a remixdb with the optimization turned off. New sstables will not have the compressed keys block.
A store created by one of these functions can be safely opened by the other function.

TODO: compress the compressed keys block with lz4/zstd/etc.?

# Getting Started

RemixDB by default uses `liburing` (`io_uring`) and thus requires a Linux kernel >= 5.1.
It also works with POSIX AIO on all the supported platforms but the performance can be negatively affected.

`clang` is the default compiler. It usually produces faster code than GCC. To use GCC:

    $ make CCC=gcc

If jemalloc is available and you prefer to use it, use `M=j` with `make`:

    $ make M=j

The `xdbdemo.c` contains sample code that uses the `remixdb_*` functions.
These functions present a clean programming interface without using special data types or structures.

## xdbdemo
To compile and run the demo code:

    $ make xdbdemo.out
    $ ./xdbdemo.out

## xdbtest

`xdbtest` is a stress test program that uses the `xdb_*` functions in `xdb.c`.
The `remixdb_*` functions are thin wrappers of the `xdb_*` functions.

Run with a 4GB block cache, 4GB MemTables, and a dataset with 32 million KVs:

    $ make xdbtest.out
    $ ./xdbtest.out /tmp/xdbtest 4096 25 30

If your memory (tmpfs) is small (a 256MB block cache, 256MB Memtables, and 1 million KVs):

    $ ./xdbtest.out /tmp/xdbtest 256 20 30

The first run of xdbtest.out should always show errors=0.
If you run it again without deleting `/tmp/xdbtest`, it will show non-zero error counts but the count will quickly drop and eventually reach zero.
