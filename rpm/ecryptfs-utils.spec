Name: ecryptfs-utils
Version: 24
Release: 0%{?dist}
Summary: The eCryptfs mount helper and support libraries
Group: System Environment/Base
License: GPL
URL: http://ecryptfs.org
Source0: https://launchpad.net/ecryptfs/+download
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: libgcrypt-devel keyutils-libs-devel openssl-devel pam-devel
Conflicts: kernel < 2.6.19

%description
eCryptfs is a stacked cryptographic filesystem that ships in Linux
kernel versions 2.6.19 and above. This package provides the mount
helper and supporting libraries to perform key management and mount
functions.

Install ecryptfs-utils if you would like to mount eCryptfs.

%package devel
Summary: The eCryptfs userspace development package
Group: System Environment/Base
Requires: keyutils-libs-devel %{name} = %{version}-%{release}

%description devel
Userspace development files for eCryptfs.

%prep

%setup -q

%build
%configure --disable-opencryptoki --disable-rpath
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc README COPYING AUTHORS NEWS THANKS

/sbin/mount.ecryptfs
%{_bindir}/ecryptfs-manager
%{_bindir}/ecryptfs-insert-wrapped-passphrase-into-keyring
%{_bindir}/ecryptfs-rewrap-passphrase
%{_bindir}/ecryptfs-unwrap-passphrase
%{_bindir}/ecryptfs-wrap-passphrase
%{_bindir}/ecryptfs-add-passphrase
%{_bindir}/ecryptfsd
%{_libdir}/libecryptfs.so.0.0.0
%{_libdir}/libecryptfs.so.0
%{_libdir}/ecryptfs
/%{_lib}/security/pam_ecryptfs.so
%{_mandir}/man7/ecryptfs.7.gz

%files devel
%defattr(-,root,root,-)
%doc doc/design_doc/ecryptfs_design_doc_v0_2.tex doc/design_doc/*.eps
%{_libdir}/libecryptfs.so
%{_includedir}/ecryptfs.h

%changelog
* Fri Oct 05 2007 Mike Halcrow <mhalcrow@us.ibm.com> - 24-0
- Bump to version 24. Several bugfixes. Key modules are overhauled
  with a more sane API.
* Wed Aug 29 2007 Fedora Release Engineering <rel-eng at fedoraproject dot org> - 18-1
- Rebuild for selinux ppc32 issue.
* Thu Jun 28 2007 Mike Halcrow <mhalcrow@us.ibm.com> - 18-0
- Bump to version 18 with an OpenSSL key module fix
* Thu Jun 21 2007 Kevin Fenzi <kevin@tummy.com> - 17-1
- Change kernel Requires to Conflicts
- Remove un-needed devel buildrequires
* Wed Jun 20 2007 Mike Halcrow <mhalcrow@us.ibm.com>  - 17-0
- Provide built-in fallback passphrase key module. Remove keyutils,
  openssl, and pam requirements (library dependencies take care of
  this). Include wrapped passphrase executables in file set.
* Fri Apr 20 2007 Mike Halcrow <mhalcrow@us.ibm.com>  - 15-1
- Change permission of pam_ecryptfs.so from 644 to 755.
* Thu Apr 19 2007 Mike Halcrow <mhalcrow@us.ibm.com>  - 15-0
- Fix mount option parse segfault. Fix pam_ecryptfs.so semaphore
  issue when logging in via ssh.
* Thu Mar 01 2007 Mike Halcrow <mhalcrow@us.ibm.com>  - 10-0
- Remove verbose syslog() calls; change key module build to allow
  OpenSSL module to be disabled from build; add AUTHORS, NEWS, and
  THANKS to docs; update Requires with variables instead of hardcoded
  name and version.
* Tue Feb 06 2007 Mike Halcrow <mhalcrow@us.ibm.com>  - 9-1
- Minor update in README, add dist tag to Release, add --disable-rpath
  to configure step, and remove keyutils-libs from Requires.
* Tue Jan 09 2007 Mike Halcrow <mhalcrow@us.ibm.com>  - 9-0
- Correct install directories for 64-bit; add support for xattr and
  encrypted_view mount options
* Tue Jan 02 2007 Mike Halcrow <mhalcrow@us.ibm.com>  - 8-0
- Introduce build support for openCryptoki key module.  Fix -dev build
  dependencies for devel package
* Mon Dec 11 2006 Mike Halcrow <mhalcrow@us.ibm.com>  - 7-0
- Initial package creation
