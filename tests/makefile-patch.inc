# vim: set filetype=make:

%.stripped: %.patched
	$(KPATCH_STRIP) --strip $< $*.stripped
	/usr/bin/strip --strip-unneeded $*.stripped

%.so.stripped: %.patched
	$(KPATCH_STRIP) --strip $< $*.so.stripped
	/usr/bin/strip --strip-unneeded $*.so.stripped

%.so.kpatch: CFLAGS += -fPIC

%.undo-link: %.stripped %
	cp $< $@
	readelf -a $(word 2,$^)
	$(KPATCH_STRIP) --rel-fixup $(word 2,$^) $@
	$(KPATCH_STRIP) --undo-link $(word 2,$^) $@

%.kpatch: %.undo-link %
	buildid=$(call get_buildid,$(word 2,$^))	&&		\
	$(KPATCH_MAKE) -b $${buildid} $< -o $@		&&		\
	cp -fs $@ $(OBJDIR)/$${buildid}.kpatch

$(OBJDIR)/%.o: $(OBJDIR)/%.s
	$(AS) $< -o $@

$(OBJDIR)/%.orig.s: %.c
	$(CC) $< -S -o - $(CFLAGS) | \
		$(KPATCH_GENSRC) --dbg-filter --os=rhel6 -i - -o $@

DIFFEXT ?= diff

$(OBJDIR)/%.patched.s: %.c %.$(DIFFEXT)
	patch -b -p1 < $(word 2,$^)
	$(CC) $< -S -o - $(CFLAGS) | \
		$(KPATCH_GENSRC) --dbg-filter --os=rhel6 -i - -o $@
	mv $<.orig $<

$(OBJDIR)/%.s: $(OBJDIR)/%.orig.s $(OBJDIR)/%.patched.s
	$(KPATCH_GENSRC) --os=rhel6 -i $< -i $(word 2,$^) --force-global \
		--force-gotpcrel -o $@

lib%.patched: LDFLAGS += -shared
lib%.patched: LIBRARY :=
lib%.patched: CFLAGS += -fPIC

%.patched: %.o $(LIBRARY)
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@ -Wl,-q

%: %.orig.o $(LIBRARY)
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

%.so: CFLAGS += -fPIC
%.so: LDFLAGS += -shared
%.so: %.orig.o
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

.SUFFIXES:
.PRECIOUS = %.s %.orig.s %.patched.s

BINARY_PATCH ?= $(BINARY).kpatch

ifneq ($(HAS_LIBRARY),)
LIBRARY_PATCH ?= $(LIBRARY).kpatch
$(BINARY): LDLIBS += -l$(TESTNAME) -L$(OBJDIR)
endif
