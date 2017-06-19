# vim: set filetype=make:
#
ifneq ($(HAS_LIBRARY),)

ifeq ($(KPATCH_STAGE),original)
$(BINARY): LDLIBS += -l$(TESTNAME) -L$(OBJDIR)
else
$(BINARY): LDLIBS += -l$(TESTNAME) -L$(LPMAKE_ORIGINAL_DIR)
endif

endif

%.so: LDFLAGS += -shared
%.so: CFLAGS += -fPIC
%.so: %.o
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

%: %.o
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@
