#!/bin/bash

# This script performs a naive COW copy of an xdb directory
# orig and dest must be in the same file system that supports hard links
# The table files will be duplicated using hard links without copying
# the WAL files are really copied because they are mutable

if [[ $# -lt 2 ]]; then
  echo "usage: <orig-path> <dest-path>"
  exit 0
fi

orig=${1} dest=${2}

if [[ ! -d ${orig} || ! -h ${orig}/HEAD ]]; then
  echo "${orig}/HEAD is not a symbolic link"
  exit 0
fi

if [[ -d ${dest} ]]; then
  echo "${dest} already exists; must use a non-existing path"
  exit 0
fi

mkdir -p ${dest}
if [[ ! -d ${dest} ]]; then
  echo "creating ${dest} failed"
  exit 0
fi

# hardlinks for immutable files
cp -l ${orig}/*.sstx ${orig}/*.ssty ${orig}/*.ver ${dest}/

# duplicate softlinks HEAD and HEAD1 (pointing to a *.ver)
cp -a ${orig}/HEAD ${dest}/HEAD
cp -a ${orig}/HEAD1 ${dest}/HEAD1

# really copy wals
cp ${orig}/wal1 ${orig}/wal2 ${dest}/
