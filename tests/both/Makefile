
HAS_LIBRARY := 1

include ../makefile.inc

ifneq ($(IS_LIBCARE_CC),y)
TGT := libboth.so
TGT_LDFLAGS := -shared
include ../makefile-patch-link.inc
endif
