

all: src

src: FORCE
	make -C src

tests: FORCE
	make -C tests

FORCE:
