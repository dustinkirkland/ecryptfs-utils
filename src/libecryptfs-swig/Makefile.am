if BUILD_PYWRAP

BUILT_SOURCES = $(srcdir)/libecryptfs_wrap.c
SWIG_SOURCES = libecryptfs.i

pkgpython_PYTHON = libecryptfs.py
pkgpyexec_LTLIBRARIES = _libecryptfs.la
_libecryptfs_la_SOURCES = $(srcdir)/libecryptfs_wrap.c $(SWIG_SOURCES)
_libecryptfs_la_CFLAGS = $(SWIG_PYTHON_CPPFLAGS) -I$(top_srcdir)/src/include
_libecryptfs_la_LDFLAGS = -module
_libecryptfs_la_LIBADD = ../libecryptfs/.libs/libecryptfs.la

$(srcdir)/libecryptfs_wrap.c : $(SWIG_SOURCES)
	$(SWIG) $(SWIG_PYTHON_OPT) -I$(top_srcdir)/src/include -o $@ $<

endif
