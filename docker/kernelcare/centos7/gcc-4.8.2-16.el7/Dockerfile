FROM centos:centos7
RUN yum install -y --enablerepo=C7.0.1406-base gcc rpm-build xmlto "perl(ExtUtils::Embed)" patchutils redhat-rpm-config asciidoc elfutils-devel zlib-devel binutils-devel newt-devel python-devel audit-libs-devel perl bison flex hmaccalc tar gzip bzip2 vim python-setuptools ncurses-devel make net-tools bc openssl pesign numactl-devel pciutils-devel gettext kmod hostname libunwind-devel
RUN yum downgrade -y --enablerepo=C7.0.1406-base gcc-4.8.2-16.el7 cpp-4.8.2-16.el7 kernel-headers-3.10.0-123.el7 libgomp-4.8.2-16.el7 cpp-4.8.2-16.el7 binutils-2.23.52.0.1-16.el7 binutils-devel-2.23.52.0.1-16.el7
RUN easy_install pyelftools
