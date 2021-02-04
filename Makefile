# Makefile
# rules (always with .out)
# SRC-X.out += abc        # extra source: abc.c
# MOD-X.out += abc        # extra module: abc.c abc.h
# ASM-X.out += abc        # extra assembly: abc.S
# DEP-X.out += abc        # extra dependency: abc
# FLG-X.out += -finline   # extra flags
# LIB-X.out += abc        # extra -labc options

# X.out : xyz.h xyz.c # for extra dependences that are to be compiled/linked.

# X => X.out
TARGETS += xdbdemo xdbtest
# X => X.c only
SOURCES +=
SOURCES += $(EXTRASRC)
# X => X.S only
ASSMBLY +=
ASSMBLY += $(EXTRAASM)
# X => X.c X.h
MODULES += lib kv wh blkio sst xdb
MODULES += $(EXTRAMOD)
# X => X.h
HEADERS += ctypes
HEADERS += $(EXTRAHDR)

# EXTERNSRC/EXTERNDEP do not belong to this repo.
# extern-src will be linked
EXTERNSRC +=
# extern-dep will not be linked
EXTERNDEP +=

FLG +=
LIB += m


#### all
TGT-all += $(TARGETS)
.PHONY : all

# append common rules (have to do it here)
include Makefile.common
