

all: first second

build_patchlevel = 							\
	for f in $$(find -type l -name '*.kpatch'); do 			\
		buildid=$${f%.kpatch};					\
		buildid="$${buildid\#\#*/}";				\
		mkdir -p patchlevel-root/$${buildid}/$(1) || :;		\
		cp $$f patchlevel-root/$${buildid}/$(1)/kpatch.bin;	\
	done

first: FORCE
	make -f makefile.first clean all
	$(call build_patchlevel,1)

second: FORCE
	make -f makefile.second clean all
	$(call build_patchlevel,2)

clean:
	make -f makefile.first clean
	rm -fr patchlevel-root

install:
	make -f makefile.second install

FORCE:
