
DOCS := internals.pdf libcare.pdf libcare-patch-make.pdf libcare-doctor.pdf

all: $(DOCS)

%.pdf: %.rst
	rst2pdf $< -o $@
