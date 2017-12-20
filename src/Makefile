TARGETS = kpatch_gensrc \
	  kpatch_make \
	  kpatch_strip \
	  libcare-cc \
	  libcare-client \
	  libcare-ctl
DEBUG = yes # comment out this line if not debug

CC = gcc
CFLAGS_MISC = -Wall -g -O2 -D_GNU_SOURCE

cc-option = $(shell if $(CC) $(CFLAGS_MISC) $(1) -S -o /dev/null -xc /dev/null \
		> /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi ;)

CFLAGS_WARN = -Wuninitialized -Wreturn-type
CFLAGS_WARN += $(call cc-option,-Wno-builtin-macro-redefined)
CFLAGS_WARN += $(call cc-option,-Wno-deprecated-declarations)
CFLAGS = $(CFLAGS_MISC) $(CFLAGS_WARN)

ifdef DEBUG
CFLAGS += -DDEBUG -O0 -g
endif

ifeq ($(STATIC),y)
STATIC_OPTS += -static
endif

all: $(TARGETS)

.SUFFIXES:

kpatch_gensrc: kpatch_gensrc.o kpatch_dbgfilter.o kpatch_parse.o kpatch_io.o rbtree.o kpatch_log.o
kpatch_make: kpatch_make.o

LIBUNWIND_LIBS := $(shell pkg-config --libs libunwind libunwind-ptrace)


libcare-ctl: kpatch_user.o kpatch_elf.o kpatch_ptrace.o kpatch_coro.o rbtree.o kpatch_log.o
libcare-ctl: kpatch_process.o kpatch_common.o
libcare-ctl: LDLIBS += -lelf -lrt $(LIBUNWIND_LIBS)

libcare-client: libcare-client.o

kpatch_strip: kpatch_strip.o kpatch_elf_objinfo.o kpatch_log.o
kpatch_strip: LDLIBS = -lelf

libcare-cc: kpatch_cc.o

$(TARGETS): %:
	$(CC) -o $(@) $(^) $(STATIC_OPTS) $(LDLIBS)

deps/%.d: %.c
	$(CC) $(CFLAGS) $(CFLAGS_$(*)) -MM -MF "$@" -MG -MP -MT"$@" -MT"$(<:.c=.o)" $(<)

ifneq ($(wildcard deps/*.d),)
-include $(wildcard deps/*.d)
endif

.PRECIOUS: deps/%.d

%.o: %.c deps/%.d
	$(CC) $(CFLAGS) $(CFLAGS_$(*)) -o $(@) -c $(<)

clean:
	rm -rf *.o core.* deps/*.d $(TARGETS)
	for f in tests/gensrc/*.s; do \
		rm -f $$f.test; \
	done

distclean: clean

test: tests
tests: tests-gensrc tests-kpcc tests-strip
tests-gensrc: kpatch_gensrc
	for f in tests/gensrc/*.s; do \
		[ -f $$f.cmdline ] && opts="`cat $$f.cmdline`" || opts="" ; \
		if [ -f $$f.negative ]; then \
			./kpatch_gensrc --os=rhel6 -i $$f.s1 -i $$f.s2 -o /dev/null -d 1 $$opts && echo FAIL: $$f || echo PASS: $$f; \
		else \
			./kpatch_gensrc --os=rhel6 -i $$f.s1  -i $$f.s2 -o $$f.test -d 1 $$opts ; \
				diff $$f $$f.test > /dev/null && echo PASS: $$f || echo FAIL: $$f and $$f.test differ ; \
		fi \
	done;

tests-kpcc: kpatch_cc
	./tests/kpatch_cc/test_kpcc.sh

tests-strip: kpatch_strip
	KPATCH_STRIP=$(CURDIR)/kpatch_strip ./tests/strip/test_simple.sh


bindir ?= /usr/local/bin
libexecdir ?= /usr/local/libexec
INSTALL ?= install
install: all
	$(INSTALL) -d $(DESTDIR)/$(bindir)
	$(INSTALL) -m 0755 libcare-ctl $(DESTDIR)/$(bindir)/libcare-ctl
	$(INSTALL) -m 0755 libcare-client $(DESTDIR)/$(bindir)/libcare-client
	$(INSTALL) -m 0755 libcare-cc $(DESTDIR)/$(bindir)/libcare-cc
	$(INSTALL) -m 0755 libcare-patch-make $(DESTDIR)/$(bindir)/libcare-patch-make

	$(INSTALL) -d $(DESTDIR)/$(libexecdir)/libcare
	$(INSTALL) -m 0755 kpatch_gensrc $(DESTDIR)/$(libexecdir)/libcare/kpatch_gensrc
	$(INSTALL) -m 0755 kpatch_make $(DESTDIR)/$(libexecdir)/libcare/kpatch_make
	$(INSTALL) -m 0755 kpatch_strip $(DESTDIR)/$(libexecdir)/libcare/kpatch_strip

.PHONY:	all clean test tests tests-gensrc tests-strip
