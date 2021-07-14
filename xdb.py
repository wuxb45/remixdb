#!/usr/bin/python3

#
# Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
#
# All rights reserved. No warranty, explicit or implicit, provided.
#

import msgpack
from ctypes import *   # CDLL and c_xxx types

# libxdb {{{
# Change this path when necessary
libxdb = CDLL("./libremixdb.so")

# open
# dir, cachesz, mtsz, tags -> xdbptr
libxdb.remixdb_open.argtypes = [c_char_p, c_uint, c_uint, c_bool]
libxdb.remixdb_open.restype = c_void_p

# close (no return value)
libxdb.remixdb_close.argtypes = [c_void_p]

# ref
libxdb.remixdb_ref.argtypes = [c_void_p]
libxdb.remixdb_ref.restype = c_void_p

# unref
libxdb.remixdb_unref.argtypes = [c_void_p]
libxdb.remixdb_unref.restype = c_void_p

# put
# xdbptr, keyptr, keylen, vptr, vlen -> bool
libxdb.remixdb_put.argtypes = [c_void_p, c_char_p, c_uint, c_char_p, c_uint]
libxdb.remixdb_put.restype = c_bool

# get
# xdbptr, keyptr, keylen, vptr_out, vlen_out -> bool
libxdb.remixdb_get.argtypes = [c_void_p, c_char_p, c_uint, c_char_p, c_void_p]
libxdb.remixdb_get.restype = c_bool

# probe
libxdb.remixdb_probe.argtypes = [c_void_p, c_char_p, c_uint]
libxdb.remixdb_probe.restype = c_bool

# del
libxdb.remixdb_del.argtypes = [c_void_p, c_char_p, c_uint]
libxdb.remixdb_del.restype = c_bool

# sync
libxdb.remixdb_sync.argtypes = [c_void_p]

# iter_create
libxdb.remixdb_iter_create.argtypes = [c_void_p]
libxdb.remixdb_iter_create.restype = c_void_p

# iter_seek
libxdb.remixdb_iter_seek.argtypes = [c_void_p, c_char_p, c_uint]

# iter_valid
libxdb.remixdb_iter_valid.argtypes = [c_void_p]
libxdb.remixdb_iter_valid.restype = c_bool

# iter_skip1
libxdb.remixdb_iter_skip1.argtypes = [c_void_p]

# iter_skip
libxdb.remixdb_iter_skip.argtypes = [c_void_p, c_uint]

# iter_peek
libxdb.remixdb_iter_peek.argtypes = [c_void_p, c_char_p, c_void_p, c_char_p, c_void_p]
libxdb.remixdb_iter_peek.restype = c_bool

# iter_destroy
libxdb.remixdb_iter_destroy.argtypes = [c_void_p]
# }}} libxdb

# class {{{
class Xdb:
    def __init__(self, dirname, cachesz=256, mtsz=256, tags=True):
        self.xdbptr = libxdb.remixdb_open(dirname.encode('ascii'), c_uint(cachesz), c_uint(mtsz), c_bool(tags))

    # user must call explicitly
    def close(self):
        libxdb.remixdb_close(self.xdbptr)

    def ref(self):
        return XdbRef(self.xdbptr)

class XdbRef:
    # use xdb.ref()
    def __init__(self, xdbptr):
        self.refptr = libxdb.remixdb_ref(xdbptr)
        self.vbuf = create_string_buffer(65500)

    # user must call explicitly
    def unref(self):
        libxdb.remixdb_unref(self.refptr)

    def iter(self):
        return XdbIter(self.refptr)

    # key: python string; value: any (hierarchical) python object
    def put(self, key, value):
        binkey = key.encode()
        binvalue = msgpack.packb(value)
        print(key, msgpack.unpackb(binvalue), len(binvalue))

        return libxdb.remixdb_put(self.refptr, binkey, c_uint(len(binkey)), binvalue, c_uint(len(binvalue)))


    # return the value as a python object
    def get(self, key):
        binkey = key.encode()
        vlen = c_uint()
        ret = libxdb.remixdb_get(self.refptr, binkey, len(binkey), self.vbuf, byref(vlen))
        if ret:
            #vbuf[vlen.value] = b'\x00'
            return msgpack.unpackb(self.vbuf.value)
        else:
            return None

    def delete(self, key):
        binkey = key.encode()
        return libxdb.remixdb_del(self.refptr, binkey, c_uint(len(binkey)))

    def probe(self, key):
        binkey = key.encode()
        return libxdb.remixdb_probe(self.refptr, binkey, c_uint(len(binkey)))

    def sync(self):
        return libxdb.remixdb_sync(self.refptr)

class XdbIter:
    def __init__(self, refptr):
        self.iptr = libxdb.remixdb_iter_create(refptr)
        self.kbuf = create_string_buffer(65500)
        self.vbuf = create_string_buffer(65500)

    # user must call explicitly
    def destroy(self):
        libxdb.remixdb_iter_destroy(self.iptr)

    def seek(self, key):
        if key is None:
            libxdb.remixdb_iter_seek(self.iptr, None, c_uint(0))
        else:
            binkey = key.encode()
            libxdb.remixdb_iter_seek(self.iptr, binkey, c_uint(len(binkey)))

    def valid(self):
        return libxdb.remixdb_iter_valid(self.iptr)

    def skip1(self):
        libxdb.remixdb_iter_skip1(self.iptr)

    def skip(self, nr):
        libxdb.remixdb_iter_skip(self.iptr, c_uint(nr))

    # return (key, value) pair or None
    def peek(self):
        klen = c_uint()
        vlen = c_uint()
        if libxdb.remixdb_iter_peek(self.iptr, self.kbuf, byref(klen), self.vbuf, byref(vlen)):
            #kbuf[klen.value] = b'\x00'
            #vbuf[vlen.value] = b'\x00'
            return (self.kbuf.value.decode(), klen.value, msgpack.unpackb(self.vbuf.value), vlen.value)
        else:
            return None

# }}} class

# examples
xdb1 = Xdb("/tmp/pyxdb") # change this path when necessary
ref1 = xdb1.ref()  # take a ref for kv operations

ref1.put("Hello", "pyxdb")
ref1.put("key1", "value1")
ref1.put("key2", "value2")
ref1.put("key3", {"xxx":"valuex", "yyy":"valuey"})
ref1.delete("key2")

rget = ref1.get("Hello")
print(rget)

# don't use ref when iterating
iter1 = ref1.iter()
iter1.seek(None)
while iter1.valid():
    r = iter1.peek()
    print(r)
    iter1.skip1()

iter1.destroy() # must destroy all iters before unref

ref1.sync()
ref1.unref() # must unref all refs before close()
xdb1.close()

# vim:fdm=marker
