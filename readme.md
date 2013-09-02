# Concept

MIT CA (<https://ca.mit.edu/ca/>) signs MIT users' public keys in x509 certificate format.

`pgp.xvm.mit.edu` signs PGP public key UID-s if

- the public key was prevously signed by MIT CA
- the person is a student (otherwise MIT might not have checked their identity throughly)
- the name on the UID matches the name on MIT records

Everything `pgp.xvm.mit.edu` does or does not do is publicly logged at <http://pgp.xvm.mit.edu:8000/>, allowing everyone to verify that we adhere to this policy. If you wish to do so, `sipb-pgpsign-server.go` should be suitable for this purpose if modified to not send emails to people.

# Usage

You will need the standard distribution `go` programming language (`golang`).

	go run sipb-pgpsign-client.go

Some keys cannot be submitted to sipb using that method. If the server fails to parse your key, copy the certificate the previous command produced to file `cert.pem` and run `( cat cert.pem; gpg --export --armor $KEYID ) | nc pgp.xvm.mit.edu 7564`.

# License

GPLv3+, but not religious about it. If you'd like to use this code in an open source project, contact me.
