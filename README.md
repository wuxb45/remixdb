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

# Getting Started

RemixDB by default uses `liburing` (`io_uring`) and thus requires a Linux kernel >= 5.1.
It also works with POSIX AIO on all supported platforms but the performance can be affected.

`clang` is the default compiler. It usually produce faster code than GCC. To use GCC:

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
