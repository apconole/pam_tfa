#Two Factor PAM Account library
==============================

The Two Factor PAM Account library aims to provide a simple mechanism by which
we can implement two-factor login privileges by plugging into the PAM stack.
This module should work for any specific PAM-aware application, but the primary
target is the SSH daemon.

In order to work with the SSH Daemon, there are two considerations:

1. Systems where users authenticate with passwords.
2. Systems where users authenticate with keys.

The way I've chosen to handle this is by treating the 'challenge-response' phase
as an account OR auth management function. IE: By successfully passing the
'auth' stack, you prove you know the authentication token and we can either stay
in 'auth' land to do the challenge response or use 'account' as a means by which
we say "you can be on this system."

This also lets us get around '2' above - according to the OpenSSH manual, pubkey
authentication bypasses the 'auth' stack in pam, but ONLY the 'auth' stack.

The Authentication Part
=======================

Authentication is done on a per-user basis. It is either opt-in OR system
mandated. In either case, the two-factor information is stored in a 600 mask
file "~/.tfa_config" and consists of the smtp email by which the user will be
contacted.

example config

This is the destination email (ex: i use my cell number @vtext.com for a text
message)
> email=someEmail@foo.com

This is the 'from' address. it could be the same as 'email' above
> from=myProviderEmail@target.com

This sets the server address
> server=foo.com

This is the server port. Common ports are 25, 2525, and 587 - see your mail
provider details. NOTE: for good reason, we ONLY do TLS mail
> port=587

Your mail username
> username=myuser

Your mail password
> password=pass

Fail option (deny means block if we fail to send, pass means allow anyway)
> fail=deny

Configuring
===========

To use pam_tfa, set up either an account stack or auth stack as follows:

* After the pam_permit.so line, add the following.

*{accout/auth} required pam_tfa.so*

Add the _debug_ keyword for additional logs in your AUTHPRIV logs, and add _noopt_
to disallow users from opting in (ie: users MUST have a valid $HOME/.tfa_config
file).

Additionally, to use SSH as well, you'll need to edit the SSHD config and set /ChallengeResponseAuthentication/ flag to yes.
