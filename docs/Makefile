
DOCS := internals.pdf libcare-patch-make.pdf libcare-src.pdf

all: $(DOCS)

%.pdf: %.rst
	rst2pdf $< -o $@
