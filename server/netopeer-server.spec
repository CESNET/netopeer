Summary: Netopeer - NETCONF implementation. Server part.
Name: netopeer-server
Version: %(cut -f1 ./VERSION | tr -d '\n')
Release: 1
URL: http://www.liberouter.org/
Source: https://www.liberouter.org/repo/SOURCES/%{name}-%{version}-%{release}.tar.gz
Group: Liberouter
License: BSD
Vendor: CESNET, z.s.p.o.
Packager: Peter Nagy <xnagyp01@stud.fit.vutbr.cz>
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}

BuildRequires: gcc make doxygen pkgconfig
BuildRequires:  libnetconf-devel python libxml2-devel libnetconf-devel
Requires:  libnetconf python libxml2 libnetconf

%description
Netopeer project implements NETCONF protocol for remote configuration of
network devices. This package contains its server part.

%prep
%setup

%build
./configure --with-distro=debian --prefix=%{_prefix} --sysconfdir=%{_sysconfdir} --with-rpm ;
make
make doc

%install
make DESTDIR=$RPM_BUILD_ROOT install

%postun

%files
%{_bindir}/netopeer-server
%{_bindir}/netopeer-manager
%{_bindir}/netopeer-configurator
%{_prefix}/lib/python*/site-packages/netopeer*
%{_sysconfdir}/netopeer/*
%{_sysconfdir}/init.d/netopeer.rc
%{_mandir}/man1/*
%{_mandir}/man8/*
%{_datadir}/netopeer/*.html

