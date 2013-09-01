package main

import (
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/packet"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/gopass"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/md5"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
)

type SubjectPublicKeyInfo struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

type PublicKeyAndChallenge struct {
	SubjectPublicKeyInfo SubjectPublicKeyInfo
	Challenge            string `asn1:"ia5"`
}

type SignedPublicKeyAndChallenge struct {
	PublicKeyAndChallenge PublicKeyAndChallenge
	SignatureAlgorithm    []asn1.ObjectIdentifier
	Signature             asn1.BitString
}

var oidSignatureMD5WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
const ffx_useragent = "Mozilla/5.0 (X11; Linux x86_64; rv:23.0) Gecko/20100101 Firefox/23.0"

func main() {
	var username, password, mitid string
	fmt.Print("MIT username: ")
	_, err := fmt.Scan(&username)
	if err != nil {
		log.Fatalln(err)
	}
	//
	fmt.Print("MIT ID: ")
	mitid, err = gopass.GetPass("")
	if err != nil {
		log.Fatalln(err)
	}
	//
	fmt.Print("MIT password: ")
	password, err = gopass.GetPass("")
	if err != nil {
		log.Fatalln(err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatalln(err)
	}

	// MIT CA round 1: get a session cookie
	client := &http.Client{Jar: jar}
	req, err := http.NewRequest("GET", "https://ca.mit.edu/ca/", nil)
	if err != nil {
		log.Fatalln(err)
	}
	req.Header.Set("User-agent", ffx_useragent)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	// fmt.Println(resp)
	_, err = ioutil.ReadAll(resp.Body)
	// os.Stdout.Write(rr)

	// MIT CA rount 2: log in
	login := url.Values{}
	login.Set("data", "1")
	login.Set("login", username)
	login.Set("password", password)
	login.Set("mitid", mitid)
	login.Set("Submit", "Next >>")

	req, err = http.NewRequest("POST", "https://ca.mit.edu/ca/login",
		strings.NewReader(login.Encode()))
	if err != nil {
		log.Fatalln(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-agent", ffx_useragent)
	resp, err = client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	rr, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	// os.Stdout.Write(rr)
	// fmt.Println(jar)
	// fmt.Println(client)
	// fmt.Println(req)
	// fmt.Println(resp)

	ml := regexp.MustCompile("challenge=\"([0-9a-zA-Z]+)\"").FindSubmatch(rr)
	if len(ml) < 2 {
		log.Fatal("Could not extract server challenge")
	}
	challenge := string(ml[1])
	// fmt.Println(challenge)

	fmt.Println("Please copy-paste `gpg --export-secret-keys --armor $KEYID` here")
	elist, err := openpgp.ReadArmoredKeyRing(os.Stdin)
	if err != nil || len(elist) != 1 {
		log.Fatal("Input must contain exactly one ASCII-armored PGP secret key")
	}
	pgpKey := elist[0]
	pk := pgpKey.PrimaryKey.PublicKey
	pkBytes, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		log.Fatalln(err)
	}

	for pgpKey.PrivateKey.Encrypted {
		fmt.Print("PGP passphrase: ")
		pgppass, err := gopass.GetPass("")
		if err != nil {
			log.Fatalln(err)
		}
		pgpKey.PrivateKey.Decrypt([]byte(pgppass))
		if pgpKey.PrivateKey.Encrypted {
			fmt.Println("Incorrect. Try again or press ctrl+c to exit.")
		}
	}

	var spki SubjectPublicKeyInfo
	asn1.Unmarshal(pkBytes, &spki)
	// fmt.Println(spki.Algo)

	var pkac PublicKeyAndChallenge
	pkac.SubjectPublicKeyInfo = spki
	pkac.Challenge = challenge

	pkac_der, err := asn1.Marshal(pkac)
	if err != nil {
		log.Fatal(err)
	}
	h := crypto.MD5.New()
	h.Write(pkac_der)
	pkac_hash := h.Sum(nil)

	var spkac SignedPublicKeyAndChallenge
	spkac.PublicKeyAndChallenge = pkac
	switch pgpKey.PrivateKey.PubKeyAlgo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly:
		spkac.SignatureAlgorithm = append(spkac.SignatureAlgorithm, oidSignatureMD5WithRSA)
		spkac.Signature.Bytes, err = rsa.SignPKCS1v15(rand.Reader,
			pgpKey.PrivateKey.PrivateKey.(*rsa.PrivateKey), crypto.MD5, pkac_hash)
		spkac.Signature.BitLength = 8 * len(spkac.Signature.Bytes)
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("Only RSA keys are supported at the moment")
	}
	spkac_der, err := asn1.Marshal(spkac)
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Println(base64.StdEncoding.EncodeToString(spkac_der))

	// MIT CA round 3: get the key certified
	post := url.Values{}
	post.Set("data", "1")
	post.Set("userkey", base64.StdEncoding.EncodeToString(spkac_der))
	post.Set("life", "1")
	post.Set("Submit", "Next >>")

	req, err = http.NewRequest("POST", "https://ca.mit.edu/ca/handlemoz",
		strings.NewReader(post.Encode()))
	if err != nil {
		log.Fatalln(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-agent", ffx_useragent)
	resp, err = client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	// fmt.Println(resp)

	// MIT CA round 4: retrieve the signed certificate
	req, err = http.NewRequest("GET", "https://ca.mit.edu/ca/mozcert/2", nil)
	if err != nil {
		log.Fatalln(err)
	}
	req.Header.Set("User-agent", ffx_useragent)
	resp, err = client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	rr, err = ioutil.ReadAll(resp.Body)
	brr := base64.StdEncoding.EncodeToString(rr)
	cert := "-----BEGIN CERTIFICATE-----\n"
	for i:=0; i+76<=len(brr); i+=76 {
		cert += brr[i:i+76] + "\n"
	}
	cert += brr[len(brr)-len(brr)%76:] + "\n"
	cert += "-----END CERTIFICATE-----\n\n"
	fmt.Print(cert)

	// pgp.xvm.mit.edu round 1/1: submit the cert and key
	addr, err := net.ResolveTCPAddr("tcp", "pgp.xvm.mit.edu:7564")
	if err != nil {
		log.Fatalln(err)
	}
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		log.Fatalln(err)
	}
	if _, err := conn.Write([]byte(cert)); err != nil {
		log.Fatalln(err)
	}
	armorer, err := armor.Encode(conn, openpgp.PublicKeyType, nil)
	if err != nil {
		log.Fatalln(err)
	}
	if err := pgpKey.Serialize(armorer); err != nil {
		log.Fatalln(err)
	}
	armorer.Close()
	conn.CloseWrite()
	io.Copy(os.Stdout, conn)
	conn.Close()
}
