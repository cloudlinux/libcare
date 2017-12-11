Version: 0.1
Name: libcare
Summary: LibCare tools
Release: 1
Group: Applications/System
License: GPLv2
Url: http://www.cloudlinux.com
Source0: %{name}-%{version}.tar.bz2
BuildRequires: elfutils-libelf-devel libunwind-devel

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
LibCare userland tools

%prep
%setup -q

%build
make -C src

%install
%{__rm} -rf %{buildroot}

install -D -m 755 src/libcare-ctl $RPM_BUILD_ROOT%{_bindir}/libcare-ctl
install -D -m 755 src/libcare-cc $RPM_BUILD_ROOT%{_bindir}/libcare-cc
install -D -m 755 src/libcare-patch-make $RPM_BUILD_ROOT%{_bindir}/libcare-patch-make

install -D -m 755 src/kpatch_gensrc $RPM_BUILD_ROOT%{_libexecdir}/libcare/kpatch_gensrc
install -D -m 755 src/kpatch_make $RPM_BUILD_ROOT%{_libexecdir}/libcare/kpatch_make
install -D -m 755 src/kpatch_strip $RPM_BUILD_ROOT%{_libexecdir}/libcare/kpatch_strip

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{_bindir}/libcare-ctl
%{_bindir}/libcare-cc
%{_bindir}/libcare-patch-make
%{_libexecdir}/libcare/kpatch_gensrc
%{_libexecdir}/libcare/kpatch_strip
%{_libexecdir}/libcare/kpatch_make

%changelog
* Mon Dec 11 2017 Pavel Boldin <pboldin@cloudlinux.com> - 0.1-1
- first version
