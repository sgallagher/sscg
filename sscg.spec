%if (0%{?fedora} >= 22 || 0%{?rhel} >= 8)
%global use_python3 1
%endif

%global srcname sscg

Name:           %{srcname}
Version:        0.4.1
Release:        0%{?dist}
Summary:        Self-signed certificate generator

License:        BSD
URL:            https://github.com/sgallagher/%{srcname}
Source0:        https://github.com/sgallagher/%{srcname}/releases/download/%{srcname}-%{version}/%{srcname}-%{version}.tar.gz

BuildArch:      noarch

%if 0%{?use_python3}
Requires:       python3-pyOpenSSL
Requires:       python3-pyasn1
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  python3-pyOpenSSL
BuildRequires:  python3-pyasn1
%else
Requires:       pyOpenSSL
Requires:       python-pyasn1
BuildRequires:  python-devel
BuildRequires:  python-setuptools
BuildRequires:  pyOpenSSL
BuildRequires:  python-pyasn1
%endif
BuildRequires: gettext

%description
A utility to aid in the creation of more secure "self-signed"
certificates. The certificates created by this tool are generated in a
way so as to create a CA certificate that can be safely imported into a
client machine to trust the service certificate without needing to set
up a full PKI environment and without exposing the machine to a risk of
false signatures from the service certificate.

%prep
%setup -q -n %{srcname}-%{version}

%build
# Ensure egg-info is regenerated
rm -rf src/*.egg-info

%if 0%{?use_python3}
%{__python3} setup.py build
%else
%{__python2} setup.py build
%endif # use_python3

%install
rm -rf $RPM_BUILD_ROOT

%if 0%{?use_python3}
%{__python3} setup.py install --skip-build --root $RPM_BUILD_ROOT
%else
%{__python} setup.py install -O1 --skip-build --root $RPM_BUILD_ROOT
%endif # use_python3

%files
%license src/sscg/LICENSE
%{_bindir}/%{srcname}

%if 0%{?use_python3}
%{python3_sitelib}/%{srcname}/
%{python3_sitelib}/%{srcname}-%{version}-py%{python3_version}.egg-info/
%else
%{python2_sitelib}/%{srcname}/
%{python2_sitelib}/%{srcname}-%{version}-py%{python2_version}.egg-info/
%endif #use_python3

%changelog
* Mon Mar 30 2015 Stephen Gallagher <sgallagh@redhat.com> 0.4.1-1
- Change default CA location to match service certificate
- Improve error handling

* Tue Mar 24 2015 Stephen Gallagher <sgallagh@redhat.com> 0.4.0-1
- Spec file cleanups
- PEP8 Cleanups
- Make location arguments optional

* Mon Mar 23 2015 Stephen Gallagher <sgallagh@redhat.com> 0.3.0-1
- Rename to sscg
- Only build with default python interpreter

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
