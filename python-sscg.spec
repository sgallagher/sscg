%if (0%{?fedora} >= 13 || 0%{?rhel} >= 7)
%global with_python3 1
%if (0%{?fedora} >= 22 || 0%{?rhel} >= 8)
%global use_python3 1
%endif
%endif

%global srcname sscg

Name:           python-%{srcname}
Version:        0.2.1
Release:        1%{?dist}
Summary:        Self-signed certificate generator

License:        BSD
URL:            https://github.com/sgallagher/%{srcname}
Source0:        https://github.com/sgallagher/%{srcname}/releases/download/%{srcname}-%{version}/%{srcname}-%{version}.tar.gz

BuildArch:      noarch
Requires:       pyOpenSSL
Requires:       python-pyasn1
BuildRequires:  python-devel
BuildRequires:  python-setuptools
BuildRequires:  pyOpenSSL
BuildRequires:  python-pyasn1

%description
A utility to aid in the creation of more secure "self-signed"
certificates. The certificates created by this tool are generated in a
way so as to create a CA certificate that can be safely imported into a
client machine to trust the service certificate without needing to set
up a full PKI environment and without exposing the machine to a risk of
false signatures from the service certificate.

%if 0%{?with_python3}
%package -n python3-%{srcname}
Summary: Self-signed certificate generator
Requires:       python3-pyOpenSSL
Requires:       python3-pyasn1
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  python3-pyOpenSSL
BuildRequires:  python3-pyasn1

%description -n python3-%{srcname}
A utility to aid in the creation of more secure "self-signed"
certificates. The certificates created by this tool are generated in a
way so as to create a CA certificate that can be safely imported into a
client machine to trust the service certificate without needing to set
up a full PKI environment and without exposing the machine to a risk of
false signatures from the service certificate.
%endif #0%{?with_python3}

%prep
%setup -qc -n %{srcname}-%{version}

mv %{srcname}-%{version} python2
find python2 -name '*.py' | xargs sed -i '1s|^#!python|#!%{__python2}|'

%if 0%{?with_python3}
rm -rf python3
cp -a python2 python3
find python3 -name '*.py' | xargs sed -i '1s|^#!python|#!%{__python3}|'
%endif #0%{?with_python3}

%build
# Ensure egg-info is regenerated
rm -rf src/*.egg-info

pushd python2
%{__python2} setup.py build
popd

%if 0%{?with_python3}
pushd python3
%{__python3} setup.py build
popd
%endif # with_python3

%install
rm -rf $RPM_BUILD_ROOT

pushd python2
%{__python} setup.py install -O1 --skip-build --root $RPM_BUILD_ROOT
mv $RPM_BUILD_ROOT/%{_bindir}/%{srcname} \
   $RPM_BUILD_ROOT/%{_bindir}/%{srcname}-%{python2_version}
popd

%if 0%{?with_python3}
pushd python3
%{__python3} setup.py install --skip-build --root $RPM_BUILD_ROOT
mv $RPM_BUILD_ROOT/%{_bindir}/%{srcname} \
   $RPM_BUILD_ROOT/%{_bindir}/%{srcname}-%{python3_version}
popd
%endif # with_python3

# On platforms where python3 is preferred, symlink that version
# to /usr/bin/%{srcname}
%if 0%{?use_python3}
ln -s %{srcname}-%{python3_version} $RPM_BUILD_ROOT/%{_bindir}/%{srcname}
%else
ln -s %{srcname}-%{python2_version} $RPM_BUILD_ROOT/%{_bindir}/%{srcname}
%endif #use_python3
 
%files
%license python2/src/sscg/LICENSE
# For noarch packages: sitelib
%{python2_sitelib}/*
%{_bindir}/%{srcname}-%{python2_version}
%if !0%{?use_python3}
%{_bindir}/%{srcname}
%endif

%if 0%{?with_python3}
%files -n python3-%{srcname}
%license python3/src/sscg/LICENSE
%{python3_sitelib}/*
%{_bindir}/%{srcname}-%{python3_version}
%if 0%{?use_python3}
%{_bindir}/%{srcname}
%endif #use_python3
%endif #with_python3

%changelog
* Tue Mar 17 2015 Stephen Gallagher <sgallagh@redhat.com> 0.2.1-1
- Include the LICENSE file in the tarball

* Tue Mar 17 2015 Stephen Gallagher <sgallagh@redhat.com> 0.2-2
- Include the license in the build RPMs

* Tue Mar 17 2015 Stephen Gallagher <sgallagh@redhat.com> 0.2-1
- Add support for namedConstraints
- Add support for subjectAltNames
- Fix packaging issues from Fedora package review

* Mon Mar 16 2015 Stephen Gallagher <sgallagh@redhat.com> 0.1-2
- Update BuildRequires

* Mon Mar 16 2015 Stephen Gallagher <sgallagh@redhat.com> 0.1-1
- First packaging
