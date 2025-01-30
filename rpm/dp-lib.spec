Name:           dp-lib
Version:        %{version}
Release:        1%{?dist}
Summary:        RHEL pkg for dp-lib
BuildArch:      x86_64
License:        BSD-3-Clause-Clear
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  gcc make bash libpcap-devel

%global __brp_ldconfig %{nil}
%description
DP-lib csm host modules

%prep
%setup -q

%install
export DPLIB_ROOT=dp-lib
echo -e "\n Starting INSTALL step... \n"

#building dp-lib
cd $DPLIB_ROOT
make
cd test/dp_ping
make
cd ../../../

rm -rf $RPM_BUILD_ROOT

mkdir -p $RPM_BUILD_ROOT%{_usr}/local/bin
mkdir -p $RPM_BUILD_ROOT%{_libdir}
mkdir -p $RPM_BUILD_ROOT%{_includedir}
install -m 644 $DPLIB_ROOT/include/csm_dp_api.h $RPM_BUILD_ROOT%{_includedir}
install $DPLIB_ROOT/test/dp_ping/dp_ping $RPM_BUILD_ROOT%{_usr}/local/bin
install $DPLIB_ROOT/libcsm_dp.so $RPM_BUILD_ROOT%{_libdir}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%{_usr}/local/bin/dp_ping
%{_libdir}/libcsm_dp.so
%{_includedir}/csm_dp_api.h
