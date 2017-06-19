# vim: set filetype=make:


DESTDIR ?= .
OBJDIR ?= .

KPTOOLS:=$(CURDIR)/../../src
KPATCH_GENSRC:=$(KPTOOLS)/kpatch_gensrc
KPATCH_MAKE:=$(KPTOOLS)/kpatch_make
KPATCH_STRIP:=$(KPTOOLS)/kpatch_strip

get_buildid = $(shell eu-readelf -n $(1) 2>/dev/null | awk '/Build ID:/{print $$3 "'$(2)'"}')

TESTNAME ?= $(notdir $(CURDIR))
BINARY ?= $(OBJDIR)/$(TESTNAME)

ifneq ($(HAS_LIBRARY),)
LIBRARY ?= $(OBJDIR)/lib$(TESTNAME).so
LIBOBJ ?= $(subst .so,,$(LIBRARY))
endif

ifneq ($(IS_LIBCARE_CC),y)
include ../makefile-patch.inc
else
include ../makefile-lpmake.inc
endif

all:	$(LIBRARY) $(LIBRARY_PATCH) $(BINARY) $(BINARY_PATCH)

clean::
	-rm -f $(call get_buildid,$(BINARY),.kpatch)
	-rm -f $(BINARY) $(BINARY).stripped $(BINARY).undo-link $(BINARY_PATCH)
ifneq ($(LIBRARY_PATCH),)
	test -z "$(LIBRARY_PATCH)" || rm -f $(call get_buildid,$(LIBRARY),.kpatch)
endif
	-rm -f $(BINARY).o $(BINARY).orig.o $(BINARY).patched.o
	-rm -f $(BINARY).s $(BINARY).orig.s $(BINARY).patched.s
ifneq ($(LIBRARY),)
	-rm -f $(LIBOBJ).o $(LIBOBJ).orig.o $(LIBOBJ).patched.o
	-rm -f $(LIBOBJ).s $(LIBOBJ).orig.s $(LIBOBJ).patched.s
	-rm -f $(LIBRARY) $(LIBRARY).stripped $(LIBRARY).undo-link $(LIBRARY_PATCH)
endif
	-rm -rf .kpatch*.s .lpmaketmp lpmake build

install: all
	mkdir -p $(DESTDIR) || :
	cp $(BINARY) $(BINARY_PATCH) $(LIBRARY) $(LIBRARY_PATCH) $(DESTDIR)
	if test -n "$(BINARY_PATCH)"; then				\
		cp $(call get_buildid,$(BINARY),.kpatch) $(DESTDIR);	\
	fi
	if test -n "$(LIBRARY_PATCH)"; then				\
		cp -L $(call get_buildid,$(LIBRARY),.kpatch) $(DESTDIR);\
	fi
