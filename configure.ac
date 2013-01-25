# Copyright (C) 2006-2007 International Business Machines Corp.
#  
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without 
# modifications, as long as this notice is preserved.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.


AC_PREREQ(2.59)
AC_INIT([ecryptfs-utils],[104])
AC_CANONICAL_HOST
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([${PACKAGE_NAME}], [${PACKAGE_VERSION}])
AC_CONFIG_SRCDIR([src/libecryptfs])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_DISABLE_STATIC

LIBECRYPTFS_LT_CURRENT="0"
LIBECRYPTFS_LT_REVISION="0"
LIBECRYPTFS_LT_AGE="0"
AC_SUBST([LIBECRYPTFS_LT_CURRENT])
AC_SUBST([LIBECRYPTFS_LT_REVISION])
AC_SUBST([LIBECRYPTFS_LT_AGE])

AC_ARG_ENABLE(
	[nss],
	[AS_HELP_STRING([--disable-nss],[Build against gcrypt rather than NSS])],
	,
	[enable_nss="detect"]
)

AC_ARG_ENABLE(
	[pywrap],
	[AS_HELP_STRING([--disable-pywrap],[Disable build of libecryptfs Python wrappers])],
	,
	[enable_pywrap="detect"]
)

AC_ARG_ENABLE(
	[openssl],
	[AS_HELP_STRING([--disable-openssl],[Disable build of OpenSSL key module])],
	,
	[enable_openssl="detect"]
)

AC_ARG_ENABLE(
	[pkcs11-helper],
	[AS_HELP_STRING([--enable-pkcs11-helper],[Build pkcs11-helper key module])],
	,
	enable_pkcs11_helper="no"
)

AC_ARG_ENABLE(
	[tspi],
	[AS_HELP_STRING([--enable-tspi],[Build TrouSerS key module])],
	,
	[enable_tspi="no"]
)

AC_ARG_ENABLE(
	[gpg],
	[AS_HELP_STRING([--enable-gpg],[Build GnuPG key module])],
	,
	[enable_gpg="no"]
)

AC_ARG_ENABLE(
	[pam],
	[AS_HELP_STRING([--disable-pam],[Disable build of PAM module])],
	,
	[enable_pam="yes"]
)

AC_ARG_ENABLE(
	[gui],
	[AS_HELP_STRING([--enable-gui],[Enable building of GUI components])],
	,
	[enable_gui="no"]
)

AC_ARG_ENABLE(
	[docs],
	[AS_HELP_STRING([--enable-docs],[Enable installing document])],
	,
	[enable_docs="no"]
)

AC_ARG_ENABLE(
	[docs-gen],
	[AS_HELP_STRING([--enable-docs-gen],[Enable generating documents])],
	,
	[enable_docs_gen="no"]
)
test "${enable_docs_gen}" = "yes" && enable_docs="yes"

AC_ARG_ENABLE(
	[tests],
	[AS_HELP_STRING([--enable-tests],[Enable system specific tests])],
	,
	[enable_tests="no"]
)

AC_ARG_ENABLE(
	[mudflap],
	[AS_HELP_STRING([--enable-mudflap],[Build with -fmudflap gcc option])],
	[
		if "${enableval}" = "yes"; then
			CFLAGS="$CFLAGS -fmudflap"
			LDFLAGS="$LDFLAGS -lmudflap"
		fi
	]
)

AC_ARG_WITH(
	[gpgme-prefix],
	[AS_HELP_STRING([--with-gpgme-prefix=PATH],[Specify the directory where gpgme install, default /usr])],
	,
	[with_gpgme_prefix="/usr"]
)

AC_ARG_WITH(
	[pamdir],
	[AS_HELP_STRING([--with-pamdir=PATH],[Specify the directory where PAM modules are stored])],
	[pamdir="${withval}"],
	[
		if test "${prefix}" = "/usr"; then
			pamdir="/lib${libdir##*/lib}/security"
		else
			pamdir="\$(libdir)/security"
		fi
	]
)

AC_ARG_WITH(
	[ecryptfskeymoddir],
	[AS_HELP_STRING([--with-ecryptfskeymoddir=PATH],[Specify the directory where key modules are stored])],
	[
		ecryptfskeymoddir="${withval}"
		full_ecryptfskeymoddir="${ecryptfskeymoddir}"
	],
	[
		full_ecryptfskeymoddir=`eval eval eval eval eval echo "${libdir}/ecryptfs" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
		ecryptfskeymoddir="\$(libdir)/ecryptfs"
	]
)
AC_DEFINE_UNQUOTED([ECRYPTFS_DEFAULT_KEY_MOD_DIR], ["$full_ecryptfskeymoddir"], "Location of key modules")

AC_GNU_SOURCE

AC_PROG_CC
AC_MINIX
AM_PROG_CC_C_O
AC_PROG_LN_S
PKG_PROG_PKG_CONFIG

ifdef(
	[LT_INIT],
	[LT_INIT],
	[AC_PROG_LIBTOOL]
)

AC_PATH_PROGS([POD2MAN], [pod2man])
test -z "${POD2MAN}" && AC_MSG_ERROR([I couldn't find pod2man; make sure it's installed and in your path])

AC_PATH_PROGS([TAR], [tar])
AC_PATH_PROGS([PS2PDF], [ps2pdf])
AC_PATH_PROGS([DVIPS], [dvips])
AC_PATH_PROGS([LATEX2HTML], [latex2html])
AC_PATH_PROGS([LATEX], [latex])
if test "${enable_docs_gen}" = "yes"; then
	test -z "${TAR}" && AC_MSG_ERROR([Couldn't find tar])
	test -z "${PS2PDF}" && AC_MSG_ERROR([Couldn't find ps2pdf])
	test -z "${DVIPS}" && AC_MSG_ERROR([Couldn't find dvips])
	test -z "${LATEX2HTML}" && AC_MSG_ERROR([Couldn't find latex2html])
	test -z "${LATEX}" && AC_MSG_ERROR([Couldn't find latex])
fi

AC_ISC_POSIX
AC_HEADER_STDC
AC_CHECK_LIB([dl], [dlopen])

# Verify keyutils version 1.0 or higher
if test -z "${KEYUTILS_LIBS}"; then
	AC_ARG_VAR([KEYUTILS_CFLAGS], [C compiler flags for keyutils])
	AC_ARG_VAR([KEYUTILS_LIBS], [linker flags for keyutils])
	AC_CHECK_LIB(
		[keyutils],
		[keyctl_search],
		[KEYUTILS_LIBS="-lkeyutils"],
		[AC_MSG_ERROR([eCryptfs userspace tools require Keyutils version 1.0 or higher.
You might find the package at:
http://people.redhat.com/~dhowells/keyutils/
])
		]
	)
fi

if test -z "${OPENSSL_LIBS}"; then
	PKG_CHECK_MODULES(
		[OPENSSL],
		[libcrypto >= 0.9.7],
		[have_openssl="yes"],
		[PKG_CHECK_MODULES(
			[OPENSSL],
			[openssl >= 0.9.7],
			[have_openssl="yes"],
			[AC_CHECK_LIB(
				[crypto],
				[RSA_version],
				[
					have_openssl="yes"
					OPENSSL_LIBS="-lcrypto"
				],
				[have_openssl="no"]
			)]
		)]
	)
else
	have_openssl="yes"
fi

#Verify nss
PKG_CHECK_MODULES(
	[NSS],
	[nss],
        [have_nss="yes"
	 NSS_CFLAGS="${NSS_CFLAGS} -DENABLE_NSS"],
        [have_nss="no"])

if test "${enable_nss}" = "detect" ; then
        if test "$have_nss" == "yes" ; then
                enable_nss="yes"
        else
                enable_nss="no"
        fi
fi

OLD_CFLAGS="${CFLAGS}"
CFLAGS="${CFLAGS} ${OPENSSL_CFLAGS}"
AC_CHECK_HEADER([openssl/rsa.h],, [have_openssl="no"])
CFLAGS="${OLD_CFLAGS}"

if test "${enable_pywrap}" != "no" ; then
	AM_PATH_PYTHON(2.5, [have_python="yes"], [have_python="no"])
	AC_PROG_SWIG(1.3.31)
	SWIG_PYTHON
fi

if test "x${SWIG}" != "x" ; then
   have_swig="yes"
else
   have_swig="no"
fi

if test "${enable_pywrap}" = "detect" ; then
        if test "${have_python}" = "yes" ; then
                if test "${have_swig}" = "yes" ; then
                        enable_pywrap="yes"
                fi
        fi
fi

if test "${enable_pywrap}" = "yes" ; then
        test "${have_python}" != "yes" && AC_MSG_ERROR([Python not found])
        test "${have_swig}" != "yes" && AC_MSG_ERROR([SWIG not found])
fi

test "${enable_openssl}" = "detect" && enable_openssl="${have_openssl}"

if test "${enable_openssl}" = "yes" ; then
	test "${have_openssl}" != "yes" && AC_MSG_ERROR([OpenSSL not found])
fi

if test "${enable_pkcs11_helper}" = "yes" ; then
	test "${have_openssl}" != "yes" && AC_MSG_ERROR([OpenSSL not found])
	PKG_CHECK_MODULES([PKCS11_HELPER], [libpkcs11-helper-1 >= 1.04],, [AC_MSG_ERROR([Cannot locate pkcs11-helper])])
fi

if test "${enable_tspi}" = "yes" ; then
	if test -z "${TSPI_LIBS}"; then
		AC_ARG_VAR([TSPI_CFLAGS], [C compiler flags for tspi])
		AC_ARG_VAR([TSPI_LIBS], [linker flags for tspi])
		AC_CHECK_LIB(
			[tspi],
			[Tspi_Context_Create],
			[TSPI_LIBS="-ltspi"],
			[AC_MSG_ERROR([Cannot find tspi])]
		)
	fi
fi

if test "${enable_gpg}" = "yes" ; then
	AC_MSG_CHECKING([for gpgme])
	if ! test -x "${with_gpgme_prefix}/bin/gpgme-config"; then
		AC_MSG_ERROR([Cannot locate gpgme])
	else
		AC_MSG_RESULT([found])
		GPGME_CFLAGS="`\"${with_gpgme_prefix}/bin/gpgme-config\" --cflags`"
		GPGME_LIBS="`\"${with_gpgme_prefix}/bin/gpgme-config\" --libs`"
	fi
fi

if test "${enable_pam}" = "yes" ; then
	if test -z "${PAM_LIBS}"; then
		AC_ARG_VAR([PAM_CFLAGS], [C compiler flags for pam])
		AC_ARG_VAR([PAM_LIBS], [linker flags for pam])
		AC_CHECK_LIB(
			[pam],
			[pam_authenticate],
			[PAM_LIBS="-lpam"],
			[AC_MSG_ERROR([Cannot find pam])]
		)
		AC_CHECK_LIB(
			[pam_misc],
			[pam_misc_setenv],
			[PAM_LIBS="${PAM_LIBS} ${TSPI_LIBS} -lpam_misc"],
			[AC_MSG_ERROR([Cannot find pam_misc])]
		)
	fi
fi

if test "${enable_gui}" = "yes"; then
	PKG_CHECK_MODULES(
		[GTK],
		[gtk+-2.0 >= 2.0],
		,
		PKG_CHECK_MODULES(
			[GTK],
			[gtk+ >= 1.0],,
			AC_MSG_ERROR([Cannot locate gtk+])
		)
	)
fi

pkgconfigdir="\$(libdir)/pkgconfig"
if test "${prefix}" = "/usr"; then
	rootsbindir="/sbin"
else
	rootsbindir="\$(sbindir)"
fi

GETTEXT_PACKAGE=ecryptfs-utils
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE,"$GETTEXT_PACKAGE",
                   [the gettext translation domain])

AM_GLIB_GNU_GETTEXT

IT_PROG_INTLTOOL([0.41.0])

LOCALEDIR='${prefix}/${datadir}/locale'
AC_SUBST(LOCALEDIR)


CRYPTO_CFLAGS=${NSS_CFLAGS}
CRYPTO_LIBS=${NSS_LIBS}

AC_SUBST([pamdir])
AC_SUBST([pamlibdir])
AC_SUBST([pkgconfigdir])
AC_SUBST([rootsbindir])
AC_SUBST([ecryptfskeymoddir])
AC_SUBST([GPGME_CFLAGS])
AC_SUBST([GPGME_LIBS])
AC_SUBST([CRYPTO_CFLAGS])
AC_SUBST([CRYPTO_LIBS])
AM_CONDITIONAL([BUILD_OPENSSL], [test "${enable_openssl}" = "yes"])
AM_CONDITIONAL([BUILD_PKCS11_HELPER], [test "${enable_pkcs11_helper}" = "yes"])
AM_CONDITIONAL([BUILD_TSPI], [test "${enable_tspi}" = "yes"])
AM_CONDITIONAL([BUILD_GPG], [test "${enable_gpg}" = "yes"])
AM_CONDITIONAL([BUILD_PAM], [test "${enable_pam}" = "yes"])
AM_CONDITIONAL([BUILD_PYWRAP], [test "${enable_pywrap}" = "yes"])
AM_CONDITIONAL([BUILD_NSS], [test "${enable_nss}" = "yes"])
AM_CONDITIONAL([BUILD_GUI], [test "${enable_gui}" = "yes"])
AM_CONDITIONAL([BUILD_DOCS], [test "${enable_docs}" = "yes"])
AM_CONDITIONAL([BUILD_DOCS_GEN], [test "${enable_docs_gen}" = "yes"])
AM_CONDITIONAL([ENABLE_TESTS], [test "${enable_tests}" = "yes"])

# workaround for <autoconf-2.60
if test -z "${docdir}"; then
	docdir="\$(datarootdir)/doc/\$(PACKAGE_NAME)"
	AC_SUBST([docdir])
fi
if test -z "${htmldir}"; then
	htmldir="\$(docdir)"
	AC_SUBST([htmldir])
fi
# end workaround
# workaround for <automake-1.10
if test -z "${MKDIR_P}"; then
	MKDIR_P="\$(mkdir_p)"
	AC_SUBST([MKDIR_P])
fi
# end workaround

AC_CONFIG_FILES([
	Makefile
	doc/Makefile
	src/Makefile
	src/libecryptfs/Makefile
	src/utils/Makefile
	src/key_mod/Makefile
	src/daemon/Makefile
	src/desktop/Makefile
	src/desktop/ecryptfs-mount-private.desktop
	src/desktop/ecryptfs-setup-private.desktop
	src/include/Makefile
	doc/manpage/Makefile
	src/pam_ecryptfs/Makefile
	src/libecryptfs/libecryptfs.pc
	src/libecryptfs-swig/Makefile
    	tests/Makefile
	tests/lib/Makefile
	tests/kernel/Makefile
	tests/userspace/Makefile
	po/Makefile.in
])
AC_OUTPUT

if test "${prefix}" != "/usr"; then
	echo
	echo "Warning: install prefix is $prefix"
	echo
	echo "Most mount applications expect the mount helper to install to"
	echo "/sbin. You can install the mount helper to that location by "
	echo "running the configure script again with --prefix=/usr:"
	echo
	echo "./configure --prefix=/usr"
	echo
fi
