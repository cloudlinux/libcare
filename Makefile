

all: src tests

src: FORCE
	make -C src

execve: FORCE
	make -C execve

tests: FORCE execve
	make -C tests

FORCE:
