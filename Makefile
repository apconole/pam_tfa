CC=gcc
CFLAGS=-Wall -Werror -g
SHARED_FLAGS=-fPIC -shared -rdynamic
LIBRARIES=-lssl -lcurl

all: pam_tfa.so dlopen
	@echo All Built

pam_tfa.so: pam_tfa.c
	$(CC) $(CFLAGS) $(SHARED_FLAGS) -o $@ $< $(LIBRARIES)

dlopen: dlopen.c
	$(CC) $(CFLAGS) $(SHARED_FLAGS) -o $@ $< -ldl

check-syntax:
	-@$(CC) $(CFLAGS) -fsyntax-only -S $(CHK_SOURCES)

clean:
	@rm -rf *~ *.so *.o dlopen
