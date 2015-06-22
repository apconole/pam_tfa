Two Factor PAM Account library
==============================

The Two Factor PAM Account library aims to provide a simple mechanism by which
we can implement two-factor login privileges by plugging into the PAM stack.
This module should work for any specific PAM-aware application, but the primary
target is the SSH daemon.

In order to work with the SSH Daemon, there are two considerations:

1. Systems where users authenticate with passwords.
2. Systems where users authenticate with keys.

The way I've chosen to handle this is by treating the 'challenge-response' phase
as an account management function. IE: By successfully passing the 'auth' stack,
you prove you know the authentication token.

The Authentication Part
=======================

Authentication is done on a per-user basis. It is either opt-in OR system
mandated. In either case, the two-factor information is stored in a 600 mask
file "~/.tfa_config" and consists of the initial random seed for the key
schedule, and the smtp email by which the user will be contacted.

ex:
> seed=RandomLettersAndNumbers
> email=someEmail@foo.com

Configuring
===========

To use pam_tfa, set up either an account stack or auth stack as follows:

*{accout/auth} required pam_tfa.so*

Add the *debug* keyword for additional logs in your AUTHPRIV logs, and add noopt
to disallow users from opting in (ie: users MUST have a valid $HOME/.tfa_config
file).
