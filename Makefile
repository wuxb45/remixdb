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
.PHONY : all
all : bin libremixdb.so sotest.out

libremixdb.so : Makefile Makefile.common lib.h kv.h wh.h blkio.h sst.h xdb.h lib.c kv.c wh.c blkio.c sst.c xdb.c
	$(eval ALLFLG := $(CSTD) $(EXTRA) $(FLG) -shared -fPIC)
	$(eval ALLLIB := $(addprefix -l,$(LIB) $(LIB-$@)))
	$(CCC) $(ALLFLG) -o $@ lib.c kv.c wh.c blkio.c sst.c xdb.c $(ALLLIB)

sotest.out : sotest.c Makefile Makefile.common libremixdb.so remixdb.h
	$(eval ALLFLG := $(CSTD) $(EXTRA) $(FLG))
	$(CCC) $(ALLFLG) -o $@ $< -L . -lremixdb
	@echo "$(shell $(TPUT) setaf 4)Now run $ LD_LIBRARY_PATH=. ./sotest.out$(shell $(TPUT) sgr0)"

.PHONY : install
install : libremixdb.so remixdb.h
	install -D --mode=0755 libremixdb.so $(PREFIX)/lib/libremixdb.so
	install -D --mode=0644 remixdb.h $(PREFIX)/usr/include/remixdb.h

# append common rules (have to do it here)
include Makefile.common
