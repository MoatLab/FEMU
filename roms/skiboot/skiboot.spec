Name:		opal-prd
Version:	5.10
Release:	1%{?dist}
Summary:	OPAL Processor Recovery Diagnostics Daemon

Group:		System Environment/Daemons
License:	ASL 2.0
URL:		http://github.com/open-power/skiboot
ExclusiveArch:	ppc64le

BuildRequires:	systemd

Requires:	systemd

Source0:	https://github.com/open-power/skiboot/archive/v%{version}.tar.gz

%description
This package provides a daemon to load and run the OpenPower firmware's
Processor Recovery Diagnostics binary. This is responsible for run time
maintenance of OpenPower Systems hardware.


%package -n	opal-utils
Summary:	OPAL firmware utilities
Group:		Applications/System

%description -n opal-utils
This package contains utility programs.

The 'gard' utility can read, parse and clear hardware gard partitions
on OpenPower platforms. The 'getscom' and 'putscom' utilities provide
an interface to query or modify the registers of the different chipsets
of an OpenPower system. 'pflash' is a tool to access the flash modules
on such systems and update the OpenPower firmware.

%package -n     opal-firmware
Summary:        OPAL firmware
BuildArch:      noarch

%description -n opal-firmware
OPAL firmware, aka skiboot, loads the bootloader and provides runtime
services to the OS (Linux) on IBM Power and OpenPower systems.


%prep

%setup -q -n skiboot-%{version}

%build
SKIBOOT_VERSION=%version CROSS= make V=1 %{?_smp_mflags}
OPAL_PRD_VERSION=%version make V=1 -C external/opal-prd
GARD_VERSION=%version make V=1 -C external/gard
PFLASH_VERSION=%version make V=1 -C external/pflash
XSCOM_VERSION=%version make V=1 -C external/xscom-utils

%install
make -C external/opal-prd install DESTDIR=%{buildroot} prefix=/usr
make -C external/gard install DESTDIR=%{buildroot} prefix=/usr
make -C external/xscom-utils install DESTDIR=%{buildroot} prefix=/usr
make -C external/pflash install DESTDIR=%{buildroot} prefix=/usr

mkdir -p %{buildroot}%{_unitdir}
install -m 644 -p external/opal-prd/opal-prd.service %{buildroot}%{_unitdir}/opal-prd.service

mkdir -p %{buildroot}%{_datadir}/qemu
install -m 644 -p skiboot.lid %{buildroot}%{_datadir}/qemu/skiboot.lid

%post
if [ $1 -eq 1 ] ; then
    # Initial installation
    /bin/systemctl enable opal-prd.service >/dev/null 2>&1 || :
    /bin/systemctl start opal-prd.service >/dev/null 2>&1 || :
fi

%preun
if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
    /bin/systemctl --no-reload disable opal-prd.service > /dev/null 2>&1 || :
    /bin/systemctl stop opal-prd.service > /dev/null 2>&1 || :
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$1" -ge 1 ] ; then
    /bin/systemctl try-restart opal-prd.service >/dev/null 2>&1 || :
fi

%files
%doc README.md
%license LICENCE
%{_sbindir}/opal-prd
%{_unitdir}/opal-prd.service
%{_mandir}/man8/*

%files -n opal-utils
%doc README.md
%license LICENCE
%{_sbindir}/opal-gard
%{_sbindir}/getscom
%{_sbindir}/putscom
%{_sbindir}/getsram
%{_sbindir}/pflash
%{_mandir}/man1/*

%files -n opal-firmware
%doc README.md
%license LICENCE
%{_datadir}/qemu/

%changelog
* Thu Mar 01 2018 Murilo Opsfelder Araujo <muriloo@linux.vnet.ibm.com> - 5.10-1
- Update to v5.10 release

* Tue Feb 09 2016 Vasant Hegde <hegdevasant@linux.vnet.ibm.com> - 5.1.13
- Update to latest upstream release

* Mon Nov 23 2015 Vasant Hegde <hegdevasant@linux.vnet.ibm.com> - 5.1.12
- initial upstream spec file
