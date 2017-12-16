

all: src

src: FORCE
	make -C src

tests: src FORCE
	make -C tests

FORCE:
