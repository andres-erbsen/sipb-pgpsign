# Concept

MIT CA signs x509 public MIT users' keys in x509 certificate format.

`pgp.xvm.mit.edu` signs PGP public key UID-s if

- the PGP public key was signed by MIT CA
- the name on the UID matches the name on MIT records
- the person is a student (otherwise MIT might not have checked their identity throughly)

Everything `pgp.xvm.mit.edu` does or does not do is publicly logged at <http://pgp.xvm.mit.edu:8000/>, allowing everyone to verify that we adhere to this policy.

# Usage

You will need the standard distribution `go` programming language (`golang`).

	go run sipb-pgpsign-client.go

Some keys cannot be submitted to sipb using that method. If the server fails to parse your key, copy the certificate the previous command produced to file `cert.pem` and run `( cat cert.pem; gpg --export --armor $KEYID ) | nc pgp.xvm.mit.edu 7564`.

# License

GPLv3+, but not religious about it. If you'd like to use this code in an open source project, contact me.
