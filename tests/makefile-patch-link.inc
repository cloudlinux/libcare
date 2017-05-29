
OBJ := $(subst .so,,$(TGT))
$(TGT).kpatch: $(OBJ).o $(TGT)
	$(CC) $(TGT_LDFLAGS) -Wl,-q $< $(LIBS) -o $(TGT).patched
	$(KPATCH_STRIP) --strip $(TGT).patched $(TGT).stripped
	$(KPATCH_STRIP) --rel-fixup $(TGT) $(TGT).stripped
	/usr/bin/strip --strip-unneeded $(TGT).stripped
	$(KPATCH_STRIP) --undo-link $(TGT) $(TGT).stripped

	# build kpatch
	buildid=$(call get_buildid,$(TGT));			\
	$(KPATCH_MAKE) $(TGT).stripped -o $@			\
		-b $${buildid};					\
	cp -fs $@ $(OBJDIR)/$${buildid}.kpatch

clean::
	rm -f $(TGT) $(TGT).patched $(TGT).stripped $(OBJ).o
