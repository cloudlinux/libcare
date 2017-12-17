

all: src

src: FORCE
	make -C src

tests: src FORCE
	make -C tests

clean:
	make -C src clean
	make -C tests clean

ALL_HOSTS ?= $(shell cat vagrant_boxes)
LATEST_HOSTS ?= centos-6.8 centos-7.4 ubuntu-14.04 ubuntu-16.04
KEEP_ENV ?=

LOGDIR?=logs/
vagrant-ci-%: FORCE
	mkdir -p $(LOGDIR);						\
	host="$(subst vagrant-ci-,,$@)-test";				\
	test -z "$(QUIET)" || 						\
		exec 3<&1 4<&2 1>$(LOGDIR)$(LOGPREFIX)$$host.log 2>&1;	\
	vagrant up $$host	&&					\
	vagrant ssh $$host -- -tt 'ls -R ~/kernelcare';			\
	vagrant ssh $$host -- -tt					\
		'KPCC_DEBUG=1						\
		make -C libcare clean tests';				\
	rv=$$?;								\
	test "$(KEEP_ENV)" = "always" -o 				\
		"$(KEEP_ENV)" = "failed" -a $$rv -ne 0 ||		\
		vagrant destroy -f $$host;				\
	test $$rv -ne 0 -a -n "$(QUIET)" &&				\
		{							\
			echo "LOG for $$host in $(LOGDIR)$(LOGPREFIX)$$host.log" >&4;\
			cat $(LOGDIR)$(LOGPREFIX)$$host.log >&4;	\
		};							\
	test $$rv -eq 0


vagrant-ci: QUIET:=1
vagrant-ci: $(addprefix vagrant-ci-,$(LATEST_HOSTS))

vagrant-ci-full: QUIET:=1
vagrant-ci-full: $(addprefix vagrant-ci-,$(ALL_HOSTS))

vagrant-ci-clean:
	for host in $(addsuffix -test,$(HOSTS)); do		\
		vagrant destroy -f $$host;			\
	done

FORCE:
