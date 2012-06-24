MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = manpage

dist_doc_DATA =
dist_noinst_DATA =
dist_html_DATA = ecryptfs-faq.html

if BUILD_PKCS11_HELPER
dist_doc_DATA += ecryptfs-pkcs11-helper-doc.txt
else
dist_noinst_DATA += ecryptfs-pkcs11-helper-doc.txt
endif

dist_pkgdata_DATA = ecryptfs-mount-private.txt
