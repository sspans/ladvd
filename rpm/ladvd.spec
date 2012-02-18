
# http://fedoraproject.org/wiki/Packaging:RPMMacros
# http://en.opensuse.org/Packaging/RPM_Macros
# http://www.rpm.org/wiki/Problems/Distributions

%global pkgname	ladvd
%global homedir	/var/run/ladvd
%global gecos	LLDP/CDP sender for unix

%global devel_release		1
#global static_libs		0

%if 0%{?devel_release}
%global name_suffix	-unstable
%endif
%if 0%{?static_libs}
%global name_suffix	-static
%global	configure_args	--enable-static-libevent --enable-static-libpcap
%endif

Name:		%{pkgname}%{?name_suffix}
BuildRequires:  libpcap-devel
BuildRequires:  libevent-devel
%if 0%{?fedora} >= 12
BuildRequires:  libcap-ng-devel
%else
BuildRequires:  libcap-devel
%endif
BuildRequires:  pciutils-devel
BuildRequires:  pkgconfig
BuildRequires:  check-devel
Requires:	/usr/bin/lsb_release
%if ! 0%{?suse_version}
Requires:	hwdata
%endif
Version:	1.0.4
Release:	1%{?dist}
License:	ISC
URL:		http://code.google.com/p/ladvd/
Source0:	%{pkgname}-%{version}.tar.gz
Source1:	%{pkgname}.init
Source2:	%{pkgname}.sysconfig
BuildRoot:	%{_tmppath}/%{pkgname}-%{version}-build
Summary:	LLDP/CDP sender for unix 
Group:		Productivity/Networking/System
%description
ladvd uses lldp / cdp frames to inform switches about connected hosts,
which simplifies ethernet switch management. It does this by creating
a raw socket at startup, and then switching to a non-privileged user
for the remaining runtime. Every 30 seconds it will transmit LLDP/CDP packets
reflecting the current system state. Interfaces (bridge, bonding,
wireless), capabilities (bridging, forwarding, wireless) and addresses (IPv4,
IPv6) are detected dynamically.


%prep
%setup -q -n %{pkgname}-%{version}


%build
%configure --docdir=%{_docdir}/%{pkgname} %{?configure_args}
make %{?_smp_mflags}


%check
make check


%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install-strip
rm -rf %{buildroot}%{_docdir}/%{pkgname}
install -D -m 755 %{SOURCE1} %{buildroot}%{_initrddir}/%{pkgname}
%if 0%{?suse_version}
    install -D -m 0644 %{SOURCE2} %{buildroot}/var/adm/fillup-templates/sysconfig.%{pkgname}
%else
    install -D -m 644 %{SOURCE2} %{buildroot}%{_sysconfdir}/sysconfig/%{pkgname}
%endif
mkdir -p %{buildroot}%{homedir}


%clean
rm -rf %{buildroot}


%pre
/usr/sbin/groupadd -r %{pkgname} &>/dev/null || :
/usr/sbin/useradd  -r -s /sbin/nologin -d %{homedir} -M \
    -c '%{gecos}' -g %{pkgname} %{pkgname} &>/dev/null || :


%post
%if ! 0%{?suse_version}
/sbin/chkconfig --add %{pkgname}
%else
%fillup_and_insserv %{pkgname}
%restart_on_update %{pkgname}
%endif


%preun
%if ! 0%{?suse_version}
if [ "$1" = "0" ]; then
	/sbin/service %{pkgname} stop >/dev/null 2>&1 || :
	/sbin/chkconfig --del %{pkgname}
fi
%else
%stop_on_removal %{pkgname}
%endif


%postun
%if ! 0%{?suse_version}
if [ "$1" -ge "1" ]; then
	/sbin/service %{pkgname} condrestart >/dev/null 2>&1 || :
fi
/usr/sbin/userdel %{pkgname} >/dev/null 2>&1 || :
/usr/sbin/groupdel %{pkgname} >/dev/null 2>&1 || :
%else
%{insserv_cleanup}  
%endif


%files
%defattr(-,root,root)
%doc doc/ChangeLog doc/README doc/LICENSE doc/TODO doc/HACKING
%if 0%{?suse_version}
/var/adm/fillup-templates/sysconfig.%{pkgname}
%else
%config(noreplace) %{_sysconfdir}/sysconfig/%{pkgname}
%endif
%{_initrddir}/%{pkgname}
%{_sbindir}/%{pkgname}
%{_sbindir}/%{pkgname}c
%{_mandir}/man8/%{pkgname}.8*
%{_mandir}/man8/%{pkgname}c.8*
%attr(755,root,root) %dir %{homedir}


%changelog
* Mon Jan 30 2012 sten@blinkenlights.nl
- new upstream release
* Sat Feb 20 2010 sten@blinkenlights.nl
- added ladvdc, check-devel and libcap-devel
* Tue Jan 26 2010 sten@blinkenlights.nl
- packaged ladvd version 0.8.6 using the buildservice spec file wizard
