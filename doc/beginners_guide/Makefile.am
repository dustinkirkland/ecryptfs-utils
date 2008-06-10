MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

#
# Please note that "make dist" will also distribute
# Post generated documentation so users will not
# require to reproduce them.
#

FILENAME = ecryptfs_beginners_guide
EXTRA_DIST = \
	ecryptfs_beginners_guide.tex \
	\
	final \
	$(FILENAME).tar.gz

beginnersguidedir = $(docdir)/$(FILENAME)

if BUILD_DOCS
beginnersguide_DATA = final/*
endif

final-hook: \
		$(FILENAME).pdf \
		$(FILENAME)_html
	-rm -fr final
	-mkdir final
	-cp $(FILENAME)_html/*png final/
	-cp $(FILENAME)_html/*html final/
	-cp $(FILENAME)_html/*css final/
	-cp $(FILENAME).pdf final/


$(FILENAME).tar.gz-hook: \
		final-hook
	$(TAR) -C final -cz . > $(FILENAME).tar.gz

if BUILD_DOCS_GEN
final/*:	final-hook

$(FILENAME).tar.gz:	$(FILENAME).tar.gz-hook

distclean-local:	final-hook
	-rm -f *~

clean-local:
	-rm -rf final
	-rm -f *.pdf *.ps *.html *.css *.png *.log *.aux *.dvi *.tar.gz *.bbl *.blg
endif

final:	\
		final-hook \
		$(FILENAME).tar.gz-hook

$(FILENAME).pdf: $(FILENAME).ps
	-$(PS2PDF) $(FILENAME).ps $(FILENAME).pdf

$(FILENAME).ps: $(FILENAME).dvi
	-$(DVIPS) -f $(FILENAME).dvi -t letter > $(FILENAME).ps

$(FILENAME)_html: $(FILENAME).tex
	-$(LATEX2HTML) -split 0 -nonavigation -notop_navigation -noinfo \
		-mkdir -dir $(FILENAME)_html $(FILENAME).tex

$(FILENAME).dvi: $(FILENAME).tex
	-$(LATEX) $(FILENAME).tex
	-$(LATEX) $(FILENAME).tex

