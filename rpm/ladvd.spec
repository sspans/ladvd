
# http://fedoraproject.org/wiki/Packaging:RPMMacros
# http://en.opensuse.org/Packaging/RPM_Macros
# http://www.rpm.org/wiki/Problems/Distributions

%global homedir /var/run/ladvd
%global gecos CDP/LLDP sender for unix

Name:		ladvd
BuildRequires:  libevent-devel
%if 0%{?fedora} >= 12
BuildRequires:  libcap-ng-devel
%else
BuildRequires:  libcap-devel
%endif
BuildRequires:  pkgconfig
BuildRequires:  check-devel
Version:	0.8.6
Release:	1
License:	ISC
URL:		http://www.blinkenlights.nl/software/ladvd/
Source0:	ladvd-%{version}.tar.gz
Source1:        ladvd.init
Source2:        ladvd.sysconfig
Group:          Productivity/Networking/System
Summary:        CDP/LLDP sender for unix 

BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
ladvd uses cdp / lldp frames to inform switches about connected hosts,
which simplifies ethernet switch management. It does this by creating
a raw socket at startup, and then switching to a non-privileged user
for the remaining runtime. Every 30 seconds it will transmit CDP/LLDP packets
reflecting the current system state. Interfaces (bridge, bonding,
wireless), capabilities (bridging, forwarding, wireless) and addresses (IPv4,
IPv6) are detected dynamically.


%prep
%setup -q


%build
%configure --docdir=%{_docdir}/%{name}
make %{?_smp_mflags}


%check
make check


%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install-strip
rm -rf %{buildroot}%{_docdir}/%{name}
install -D -m 755 %{SOURCE1} %{buildroot}%{_initrddir}/%{name}
%if 0%{?suse_version}
    install -D -m 0644 %{SOURCE2} %{buildroot}/var/adm/fillup-templates/sysconfig.%{name}
%else
    install -D -m 644 %{SOURCE2} %{buildroot}%{_sysconfdir}/sysconfig/%{name}
%endif


%clean
rm -rf %{buildroot}


%pre
/usr/sbin/groupadd -r %{name} &>/dev/null || :
/usr/sbin/useradd  -r -s /sbin/nologin -d %{homedir} -M \
    -c '%{gecos}' -g %{name} %{name} &>/dev/null || :


%post
%if ! 0%{?suse_version}
/sbin/chkconfig --add %{name}
%service %{name} restart
%else
%fillup_and_insserv %{name}
%restart_on_update %{name}
%endif


%preun
%if ! 0%{?suse_version}
if [ "$1" = "0" ]; then
	%service %{name} stop >/dev/null 2>&1
	/sbin/chkconfig --del %{name}
fi
%else
%stop_on_removal %{name}
%endif


%postun
%if ! 0%{?suse_version}
if [ "$1" -ge "1" ]; then
	/sbin/service %{name} condrestart >/dev/null 2>&1 || :
fi
%userremove %{name}
%groupremove %{name}
%else
%{insserv_cleanup}  
%endif


%files
%defattr(-,root,root)
%doc doc/ChangeLog doc/README doc/LICENSE doc/TODO
%if 0%{?suse_version}
/var/adm/fillup-templates/sysconfig.%{name}
%else
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%endif
%{_initrddir}/%{name}
%{_sbindir}/%{name}
%{_sbindir}/%{name}c
%{_mandir}/man8/%{name}.8*
%{_mandir}/man8/%{name}c.8*


%changelog
* Sat Feb 20 2010 sten@blinkenlights.nl
- added ladvdc, check-devel and libcap-devel
* Tue Jan 26 2010 sten@blinkenlights.nl
- packaged ladvd version 0.8.6 using the buildservice spec file wizard
