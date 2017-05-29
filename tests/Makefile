MAKEFLAGS += --no-builtin-rules

SUBDIRS := $(patsubst %/desc,%,$(wildcard */desc))

KPATCH_PATH:=$(CURDIR)/../src
export KPATCH_PATH

all: run

list:
	@echo TESTS: $(SUBDIRS)

fastsleep.so: CFLAGS += -fPIC
fastsleep.so: fastsleep.c
	$(LINK.c) $^ -o $@ -shared -ldl

clean: $(addprefix clean-,$(SUBDIRS))
	rm -fr 	$(CURDIR)/build-patchroot	\
		$(CURDIR)/kpmake-patchroot	\
		$(CURDIR)/kpmakelevel-patchroot
	rm -f fastsleep.so

clean-%: FORCE
	make -C $* clean

build: $(addprefix build-,$(SUBDIRS))

build-%: FORCE
	make -C $* clean all install DESTDIR=build

build-patchroot: build
	mkdir -p $(CURDIR)/build-patchroot
	find	-type l -iname \*.kpatch \
		-exec cp -L \{} $(CURDIR)/build-patchroot \;

KPMAKE_TGTS := $(addprefix kpmake-,$(SUBDIRS))
kpmake: $(KPMAKE_TGTS)
kpmakelevel: $(KPMAKE_TGTS)

kpmake-%: export KPMAKE_PATCHROOT := kpmake
kpmake-%: FORCE
	cd $*; $(CURDIR)/../src/kpmake --clean *.diff

kpmake-patchroot: kpmake
	mkdir -p $(CURDIR)/kpmake-patchroot
	find 	-path '*/kpmake/*.kpatch' \
		-exec cp \{} $(CURDIR)/kpmake-patchroot \;

kpmakelevel-patchroot: kpmake
	mkdir -p $(CURDIR)/kpmakelevel-patchroot
	for f in $$(find -path '*/kpmake/*.kpatch'); do			\
		buildid=$${f%.kpatch};					\
		buildid=$${buildid##*/};				\
		dir=$(CURDIR)/kpmakelevel-patchroot/$$buildid/;	\
		mkdir -p $$dir/1/;					\
		cp $$f $$dir/1/kpatch.bin;				\
		ln -fs 1 $$dir/latest;					\
	done

RUN_TESTS = ./run_tests.sh $(RUNTESTSFLAGS)

run-file-%: %
	$(RUN_TESTS)

run-unpatch:
	$(RUN_TESTS) -f test_unpatch_files

run-dir-%: %
	$(RUN_TESTS) -f test_patch_dir

run-startup-%: % %-patchroot
	$(RUN_TESTS) -f test_patch_startup

run-startup-ld-linux-%: % %-patchroot
	$(RUN_TESTS) -f test_patch_startup_ld_linux

run-patchlevel: fastsleep.so
run-patchlevel: build-patchlevel
	$(RUN_TESTS) -f test_patch_patchlevel

run-build: fastsleep.so
run-build: run-file-build run-dir-build run-startup-build run-unpatch
run-build: run-startup-ld-linux-build

run-kpmake: RUNTESTSFLAGS := -d kpmake
run-kpmake: fastsleep.so
run-kpmake: run-dir-kpmake run-startup-kpmake
run-kpmake: run-startup-ld-linux-kpmake

run-kpmakelevel: RUNTESTSFLAGS := -d kpmake -p $(CURDIR)/kpmakelevel-patchroot
run-kpmakelevel: fastsleep.so
run-kpmakelevel: run-startup-kpmakelevel

run: run-build run-patchlevel run-kpmake run-kpmakelevel

FORCE:
