
# http://fedoraproject.org/wiki/Packaging:RPMMacros
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

%define use_systemd (0%{?fedora} && 0%{?fedora} >= 18) || (0%{?rhel} && 0%{?rhel} >= 7) || (0%{?suse_version} && 0%{?suse_version} >=1210)

Name:		%{pkgname}%{?name_suffix}
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  libtool
BuildRequires:  libpcap-devel
BuildRequires:  libevent-devel
BuildRequires:  libcap-ng-devel
BuildRequires:  pciutils-devel
BuildRequires:  libmnl-devel
%if %{use_systemd}
BuildRequires:  libteam-devel
BuildRequires:  libnl3-devel
%endif
BuildRequires:  pkgconfig
BuildRequires:  check-devel
Requires:	/usr/bin/lsb_release
Requires:	libmnl,libevent,libpcap

%if %{use_systemd}
Requires: systemd
BuildRequires: systemd
%else
Requires(postun):   initscripts
Requires(post):     chkconfig
Requires(preun):    chkconfig
%endif

Version:	1.1.4
Release:	1%{?dist}
License:	ISC
URL:		http://github.com/sspans/ladvd/
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
autoreconf -fi
%configure --docdir=%{_docdir}/%{pkgname} %{?configure_args}
make %{?_smp_mflags}


%check
make check


%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install-strip
rm -rf %{buildroot}%{_docdir}/%{pkgname}

%if %{use_systemd}
# install systemd-specific files
%{__mkdir} -p %{buildroot}%{_unitdir}
%{__install} -m644 systemd/%{pkgname}.service \
    %{buildroot}%{_unitdir}/%{pkgname}.service
%{__mkdir} -p %{buildroot}%{_prefix}/lib/tmpfiles.d
%{__install} -m644 systemd/%{pkgname}.conf \
    %{buildroot}%{_prefix}/lib/tmpfiles.d/%{pkgname}.conf
%else
# install SYSV init stuff
%{__install} -D -m 755 %{SOURCE1} %{buildroot}%{_initrddir}/%{pkgname}
%{__install} -D -m 644 %{SOURCE2} %{buildroot}%{_sysconfdir}/sysconfig/%{pkgname}
%endif
mkdir -p %{buildroot}%{homedir}


%clean
rm -rf %{buildroot}


%pre
getent group %{pkgname} >/dev/null || /usr/sbin/groupadd -r %{pkgname}
getent passwd %{pkgname} >/dev/null || \
    /usr/sbin/useradd  -r -s /sbin/nologin -d %{homedir} -M \
    -c '%{gecos}' -g %{pkgname} %{pkgname}


%post
%if %{use_systemd}
    /usr/bin/systemctl preset %{pkgname}.service >/dev/null 2>&1 ||:
%else
    /sbin/chkconfig --add %{pkgname}
#   /sbin/chkconfig %{pkgname} on
%endif


%preun
%if %{use_systemd}
    /usr/bin/systemctl --no-reload disable %{pkgname}.service >/dev/null 2>&1 || :
    /usr/bin/systemctl stop %{pkgname}.service >/dev/null 2>&1 ||:
%else
if [ "$1" = "0" ]; then
	/sbin/service %{pkgname} stop >/dev/null 2>&1 || :
	/sbin/chkconfig --del %{pkgname}
fi
%endif


%postun
if [ "$1" -ge "1" ]; then
%if %{use_systemd}
    /usr/bin/systemctl daemon-reload >/dev/null 2>&1 ||:
%else
    /sbin/service %{pkgname} condrestart >/dev/null 2>&1 || :
%endif
fi
test "$1" != 0 || /usr/sbin/userdel %{pkgname} >/dev/null 2>&1 || :
test "$1" != 0 || /usr/sbin/groupdel %{pkgname} >/dev/null 2>&1 || :


%files
%defattr(-,root,root)
%doc doc/README doc/LICENSE doc/TODO doc/HACKING
%if %{use_systemd}
%{_unitdir}/%{pkgname}.service
%{_prefix}/lib/tmpfiles.d/ladvd.conf
%else
%{_initrddir}/%{pkgname}
%config(noreplace) %{_sysconfdir}/sysconfig/%{pkgname}
%endif
%{_sbindir}/%{pkgname}
%{_sbindir}/%{pkgname}c
%{_mandir}/man8/%{pkgname}.8*
%{_mandir}/man8/%{pkgname}c.8*
%attr(755,root,root) %dir %{homedir}


%changelog
* Sat Jul 10 2017 sten@blinkenlights.nl
- new upstream release
* Wed Feb 04 2015 Anton Samets <a_samets@wargaming.net> - 1.1.0-1
- Updates for systemd / Centos 7
* Mon Jan 30 2012 sten@blinkenlights.nl
- new upstream release
* Sat Feb 20 2010 sten@blinkenlights.nl
- added ladvdc, check-devel and libcap-devel
* Tue Jan 26 2010 sten@blinkenlights.nl
- packaged ladvd version 0.8.6 using the buildservice spec file wizard
