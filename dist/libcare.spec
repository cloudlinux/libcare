
%bcond_without selinux

Version: 0.1.4
Name: libcare
Summary: LibCare tools
Release: 1%{?dist}
Group: Applications/System
License: GPLv2
Url: http://www.cloudlinux.com
Source0: %{name}-%{version}.tar.bz2
BuildRequires: elfutils-libelf-devel libunwind-devel

%if 0%{with selinux}
BuildRequires: checkpolicy
BuildRequires: selinux-policy-devel
BuildRequires: /usr/share/selinux/devel/policyhelp
%endif

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%if 0%{with selinux}
Requires:      libcare-selinux = %{version}-%{release}
%endif

%description
LibCare userland tools

%if 0%{with selinux}

%package selinux
Summary: SELinux package for LibCare/QEMU integration
Group: System Environment/Base
Requires(post): selinux-policy-base, policycoreutils
Requires(postun): policycoreutils
%description selinux
This package contains SELinux module required to allow for
LibCare interoperability with the QEMU run by sVirt.

%endif


%package devel
Summary: LibCare development package
Group: System Environment/Development Tools
%description devel
LibCare devel files.


%prep
%setup -q

%build

make -C src
%if 0%{with selinux}
make -C dist/selinux
%endif

%install
%{__rm} -rf %{buildroot}

make -C src install \
        DESTDIR=%{buildroot} \
        bindir=%{_bindir} \
        libexecdir=%{_libexecdir}

%if 0%{with selinux}
make -C dist/selinux install \
        DESTDIR=%{buildroot}
%endif


install -m 0644 -D dist/libcare.service %{buildroot}%{_unitdir}/libcare.service
install -m 0644 -D dist/libcare.socket %{buildroot}%{_unitdir}/libcare.socket
install -m 0644 -D dist/libcare.preset %{buildroot}%{_presetdir}/90-libcare.preset

%pre
/usr/sbin/groupadd libcare -r 2>/dev/null || :
/usr/sbin/usermod -a -G libcare qemu 2>/dev/null || :

%post
%systemd_post libcare.service
%systemd_post libcare.socket

if [ $1 -eq 1 ]; then
        # First install
        systemctl start libcare.socket
fi
if [ $1 -eq 2 ]; then
        # Upgrade. Just stop it, we will be reactivated
        # by a connect to /run/libcare.sock
        systemctl stop libcare.service
fi

%preun
%systemd_preun libcare.service
%systemd_preun libcare.socket

%postun
%systemd_postun libcare.service
%systemd_postun libcare.socket

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{_bindir}/libcare-ctl
%{_bindir}/libcare-client
%{_unitdir}/libcare.service
%{_unitdir}/libcare.socket
%{_presetdir}/90-libcare.preset

%files devel
%defattr(-,root,root)
%{_bindir}/libcare-cc
%{_bindir}/libcare-patch-make
%{_libexecdir}/libcare/kpatch_gensrc
%{_libexecdir}/libcare/kpatch_strip
%{_libexecdir}/libcare/kpatch_make

%if 0%{with selinux}

%files selinux
%defattr(-,root,root,-)
%attr(0600,root,root) %{_datadir}/selinux/packages/libcare.pp

%post selinux
. /etc/selinux/config
FILE_CONTEXT=/etc/selinux/${SELINUXTYPE}/contexts/files/file_contexts
cp ${FILE_CONTEXT} ${FILE_CONTEXT}.pre

/usr/sbin/semodule -i %{_datadir}/selinux/packages/libcare.pp

# Load the policy if SELinux is enabled
if ! /usr/sbin/selinuxenabled; then
    # Do not relabel if selinux is not enabled
    exit 0
fi

/usr/sbin/fixfiles -C ${FILE_CONTEXT}.pre restore 2> /dev/null

rm -f ${FILE_CONTEXT}.pre

exit 0

%postun selinux
if [ $1 -eq 0 ]; then
    . /etc/selinux/config
    FILE_CONTEXT=/etc/selinux/${SELINUXTYPE}/contexts/files/file_contexts
    cp ${FILE_CONTEXT} ${FILE_CONTEXT}.pre

    # Remove the module
    /usr/sbin/semodule -n -r libcare > /dev/null 2>&1

    /usr/sbin/fixfiles -C ${FILE_CONTEXT}.pre restore 2> /dev/null
fi
exit 0

%endif

%changelog
* Tue Jan 02 2018 Pavel Boldin <pboldin@cloudlinux.com> - 0.1.4-1
- fix libcare service verbosity

* Wed Dec 27 2017 Pavel Boldin <pboldin@cloudlinux.com> - 0.1.3-1
- use systemd's libcare.socket
- use libcare-client default's path

* Mon Dec 25 2017 Pavel Boldin <pboldin@cloudlinux.com> - 0.1.2-1
- add code executing after/before scripts
- spec: exec systemctl's hooks
- fix files in /run

* Mon Dec 11 2017 Pavel Boldin <pboldin@cloudlinux.com> - 0.1.1-1
- add libcare-client
- add systemd startup script
- add selinux support so we can patch RHEL7's QEMU's

* Mon Dec 11 2017 Pavel Boldin <pboldin@cloudlinux.com> - 0.1-1
- first version
