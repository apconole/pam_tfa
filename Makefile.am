AM_CFLAGS= ${regular_CFLAGS} ${libcurl_CFLAGS} ${libssl_CFLAGS}

pamlibdir          = @PAMLIBDIR@
pamlib_LTLIBRARIES = pam_tfa.la

pam_tfa_la_SOURCES = pam_tfa.c
pam_tfa_la_LIBADD  = -lpam ${libcurl_LIBS} ${libssl_LIBS}
pam_tfa_la_LDFLAGS = -module -avoid-version

install-data-hook:
	rm -f $(DESTDIR)$(pamlibdir)/pam_tfa.la;

check-syntax:
	-@$(CC) $(CFLAGS) -fsyntax-only -S $(CHK_SOURCES)
	-@cppcheck $(CHK_SOURCES)
