package main

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/mqu/openldap"
	"io"
	"io/ioutil"
	"log"
	"net/smtp"
	"os"
	"reflect"
	"strings"
	"time"
)

func getVerifiedName(username string) (name string, err error) {
	ldap, err := openldap.Initialize("ldap://ldap-too.mit.edu:389/")
	if err != nil {
		return
	}
	ldap.SetOption(openldap.LDAP_OPT_PROTOCOL_VERSION, openldap.LDAP_VERSION3)
	result, err := ldap.SearchAll("dc=mit,dc=edu", openldap.LDAP_SCOPE_SUBTREE, "uid="+username, []string{"eduPersonAffiliation", "cn"})
	if err != nil {
		return
	}
	if result.Count() != 1 {
		return "", errors.New("No or multiple ldap responses")
	}
	if len(result.Entries()[0].Attributes()) != 2 {
		return "", errors.New("!= 2 attributes in the only ldap response")
	}
	for _, attr := range result.Entries()[0].Attributes() {
		if len(attr.Values()) != 1 {
			return "", errors.New("!= 1 values in the only ldap attribute")
		}
		if attr.Name() == "cn" {
			name = attr.Values()[0]
		}
		if attr.Name() == "eduPersonAffiliation" {
			err = nil
			if attr.Values()[0] != "student" {
				err = errors.New("Not a student")
			}
		}
	}
	return
}

func namecmp(a, b string) bool {
	return a == b
}

func main() {
	log.SetOutput(io.MultiWriter(os.Stdout, os.Stderr))
	mit_ca := x509.NewCertPool()
	mit_ca_pem, err := ioutil.ReadFile("mitCAclient.pem")
	if err != nil {
		panic(err)
	}
	mit_ca.AppendCertsFromPEM(mit_ca_pem)

	skfile, err := os.Open("secret.gpg")
	defer skfile.Close()
	if err != nil {
		panic(err)
	}
	our_elist, err := openpgp.ReadArmoredKeyRing(skfile)
	if err != nil || len(our_elist) != 1 {
		panic(err)
	}
	ourPGPsk := our_elist[0]

	stdindata, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}
	elist, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(stdindata))
	if err != nil || len(elist) != 1 {
		log.Fatal("Input must contain exactly one ASCII-armored PGP public key", err)
	}
	pgpKey := elist[0]

	block, _ := pem.Decode(stdindata)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		log.Fatal("Input must contain exactly one SSL client certificate in PEM format")
	}
	x509cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal("Input must contain exactly one SSL client certificate in PEM format")
	}

	// check 1: MIT CA says that certificate info is correct
	_, err = x509cert.Verify(x509.VerifyOptions{
		Roots:     mit_ca,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	})
	if err != nil {
		log.Fatal("The client certificate must be signed by MIT Client CA")
	}

	// check 2: PGP key is the same as the one signed by MIT Client CA
	// XXX: correct comparision?
	if !reflect.DeepEqual(x509cert.PublicKey, pgpKey.PrimaryKey.PublicKey) {
		log.Fatal("The PGP key and the client certificate must have the same public key")
	}

	var username, email string
	for _, xname := range x509cert.Subject.Names {
		maybe_email := strings.ToLower(xname.Value.(string))
		if !strings.HasSuffix(maybe_email, "@mit.edu") {
			continue
		}
		email = maybe_email
		username = strings.Split(email, "@")[0]
	}
	fingerprint := hex.EncodeToString(pgpKey.PrimaryKey.Fingerprint[:])
	filename := time.Now().Format(time.RFC3339) + "-" + fingerprint

	err = ioutil.WriteFile("log/"+filename+".req", stdindata, 0644)
	if err != nil {
		panic(err)
	}

	n_sign := 0
	fullname, nameErr := getVerifiedName(username)
	for _, uid := range pgpKey.Identities {
		if strings.ContainsAny(uid.Name, "()") {
			log.Println("Not signing '" + uid.Name + "' because it has a comment")
			continue
		}
		opens := strings.Count(uid.Name, "<")
		closes := strings.Count(uid.Name, ">")
		if !(closes == opens && opens <= 1 && (closes == 0 || uid.Name[len(uid.Name)-1] == '>')) {
			log.Println("Not signing '" + uid.Name + "' because multiple or misplaced < >")
			continue
		}
		pgpname := strings.Trim(strings.Split(uid.Name, "<")[0], " ")
		pgpmail := ""
		if opens == 1 {
			pgpmail = strings.ToLower(strings.Trim(strings.Split(uid.Name, "<")[1], " >"))
		}
		sign := false

		// check 3, variant 1: PGP key is to be certified only to the same email that MIT CA approved
		if strings.Trim(uid.Name, "<> ") == pgpmail && pgpmail == email {
			sign = true
		}

		// check 3, variant 2: PGP uid has a name and it belongs to the correct MIT student
		// email is verified by delivering the signed UID through it
		if namecmp(pgpname, fullname) && nameErr == nil {
			sign = true
		}

		if sign {
			rmail := email
			if pgpmail != "" {
				rmail = pgpmail
			}
			log.Println("signing '" + uid.Name + "' and sending it to <" + rmail + ">")
			elist, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(stdindata))
			if err != nil || len(elist) != 1 {
				panic(err)
			}
			signKey := elist[0]
			err = signKey.SignIdentity(uid.Name, ourPGPsk, nil)
			if err != nil {
				panic(err)
			}

			sigfile, err := os.Create("log/" + filename + "-" + fmt.Sprint(n_sign) + ".gpg")
			defer sigfile.Close()
			if err != nil {
				panic(err)
			}

			c, err := smtp.Dial("outgoing.mit.edu:25")
			if err != nil {
				panic(err)
			}
			c.Mail("pgp-autosign@mit.edu")
			c.Rcpt(rmail)
			mailwriter, err := c.Data()
			if err != nil {
				panic(err)
			}
			defer mailwriter.Close()

			armorer, err := armor.Encode(io.MultiWriter(mailwriter, sigfile), openpgp.PublicKeyType, nil)
			defer armorer.Close()
			err = signKey.Serialize(armorer)
			if err != nil {
				panic(err)
			}
			n_sign++
		} else {
			log.Println("Not signing '" + uid.Name + "' because we cannot verify it")
			log.Println("Certificates with names are only signed if you are a student and the name matches exactly")
		}
	}
}
