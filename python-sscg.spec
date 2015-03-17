%if (0%{?fedora} >= 13 || 0%{?rhel} >= 7)
%global with_python3 1
%if (0%{?fedora} >= 22 || 0%{?rhel} >= 8)
%global use_python3 1
%endif
%endif

Name:           python-sscg
Version:        0.1
Release:        1%{?dist}
Summary:        Self-signed certificate generator

License:        PSF
URL:            https://github.com/sgallagher/sscg
Source0:        sscg-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python-devel
BuildRequires:  pyOpenSSL

%description
A utility to aid in the creation of more secure "self-signed"
certificates. The certificates created by this tool are generated in a
way so as to create a CA certificate that can be safely imported into a
client machine to trust the service certificate without needing to set
up a full PKI environment and without exposing the machine to a risk of
false signatures from the service certificate.

%if 0%{?with_python3}
%package -n python3-sscg
Summary: Self-signed certificate generator
Requires: python3-pyOpenSSL
BuildRequireS: python3-devel

%description -n python3-sscg
A utility to aid in the creation of more secure "self-signed"
certificates. The certificates created by this tool are generated in a
way so as to create a CA certificate that can be safely imported into a
client machine to trust the service certificate without needing to set
up a full PKI environment and without exposing the machine to a risk of
false signatures from the service certificate.
%endif #0%{?with_python3}

%prep
%setup -q -n sscg-%{version}

%if 0%{?with_python3}
rm -rf %{py3dir}
cp -a . %{py3dir}
%endif #0%{?with_python3}

%build
# Remove CFLAGS=... for noarch packages (unneeded)
CFLAGS="$RPM_OPT_FLAGS" %{__python2} setup.py build

%if 0%{?with_python3}
pushd %{py3dir}
CFLAGS="$RPM_OPT_FLAGS" %{__python3} setup.py build
popd
%endif # with_python3

%install
rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install -O1 --skip-build --root $RPM_BUILD_ROOT
mv $RPM_BUILD_ROOT/%{_bindir}/sscg \
   $RPM_BUILD_ROOT/%{_bindir}/sscg-%{python2_version}

%if 0%{?with_python3}
pushd %{py3dir}
%{__python3} setup.py install --skip-build --root $RPM_BUILD_ROOT
mv $RPM_BUILD_ROOT/%{_bindir}/sscg \
   $RPM_BUILD_ROOT/%{_bindir}/sscg-%{python3_version}
%endif # with_python3

# On platforms where python3 is preferred, symlink that version
# to /usr/bin/sscg
%if 0%{?use_python3}
ln -s sscg-%{python3_version} $RPM_BUILD_ROOT/%{_bindir}/sscg
%else
ln -s sscg-%{python2_version} $RPM_BUILD_ROOT/%{_bindir}/sscg
%endif #use_python3
 
%files
%doc
# For noarch packages: sitelib
%{python2_sitelib}/*
%{_bindir}/sscg-%{python2_version}
%if !0%{?use_python3}
%{_bindir}/sscg
%endif

%if 0%{?with_python3}
%files -n python3-sscg
%{python3_sitelib}/*
%{_bindir}/sscg-%{python3_version}
%if 0%{?use_python3}
%{_bindir}/sscg
%endif #use_python3
%endif #with_python3

%changelog
* Tue Mar 17 2015 Stephen Gallagher <sgallagh@redhat.com>
- First packaging
