%global provider        github
%global provider_tld    com
%global project sgallagher
%global repo sscg
# https://github.com/sgallagher/sscg
%global provider_prefix %{provider}.%{provider_tld}/%{project}/%{repo}
%global import_path     %{provider_prefix}

%{!?meson_test: %global meson_test %{__meson} test -C %{_vpath_builddir} --num-processes %{_smp_build_ncpus} --print-errorlogs}

Name:           sscg
Version:        3.0.2
Release:        %autorelease
Summary:        Simple SSL certificate generator

License:        GPLv3+ with exceptions
URL:            https://%{provider_prefix}
Source0:        https://%{provider_prefix}/archive/refs/tags/%{repo}-%{version}.tar.gz
BuildRequires:  gcc
BuildRequires:  libtalloc-devel
BuildRequires:  openssl-devel
BuildRequires:  popt-devel
BuildRequires:  libpath_utils-devel
BuildRequires:  meson
BuildRequires:  ninja-build
BuildRequires:  help2man


%description
A utility to aid in the creation of more secure "self-signed"
certificates. The certificates created by this tool are generated in a
way so as to create a CA certificate that can be safely imported into a
client machine to trust the service certificate without needing to set
up a full PKI environment and without exposing the machine to a risk of
false signatures from the service certificate.

%prep
%autosetup -p1 -n %{name}-%{name}-%{version}


%build
%meson
%meson_build

%install
%meson_install

%check
%meson_test -t 10

%files
%license COPYING
%doc README.md
%{_bindir}/%{name}
%{_mandir}/man8/%{name}.8*

%changelog
%autochangelog
