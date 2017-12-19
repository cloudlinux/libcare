
datadir ?= /usr/share

libcare.pp: libcare.te libcare.fc libcare.if
	$(MAKE) -j1 -f $(datadir)/selinux/devel/Makefile libcare.pp

SELINUXROOT = $(DESTDIR)$(datadir)/selinux

INSTALL?=install
install:
	$(INSTALL) -d $(SELINUXROOT)/packages
	$(INSTALL) -m 644 libcare.pp $(SELINUXROOT)/packages
