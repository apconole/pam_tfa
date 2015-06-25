CC ?= gcc
LD = ld
LDFLAGS = -x --shared
CFLAGS = -Wall -Werror -g -O2 
SHARED_FLAGS = -fPIC
LIBRARIES = --whole-archive -lcurl --no-whole-archive -lpam

all: pam_tfa.so dlopen
	@echo All Built

pam_tfa.so: pam_tfa.c
	$(CC) $(CFLAGS) $(SHARED_FLAGS) -c -o pam_tfa.o $< 
	$(LD) $(LIBRARIES) $(LDFLAGS) -o $@ pam_tfa.o

dlopen: dlopen.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

check-syntax:
	-@$(CC) $(CFLAGS) -fsyntax-only -S $(CHK_SOURCES)

clean:
	@rm -rf *~ *.so *.o dlopen
