CC=gcc
CFLAGS=-Wall -Werror
SHARED_FLAGS=-fPIC -shared

all: pam_tfa.so
	@echo All Built

pam_tfa.so: pam_tfa.c
	$(CC) $(CFLAGS) $(SHARED_FLAGS) -o $@ $<

check-syntax:
	-@$(CC) $(CFLAGS) -fsyntax-only -S $(CHK_SOURCES)

clean:
	@rm -rf *~ *.so *.o
