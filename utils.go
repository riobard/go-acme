package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"regexp"
)

// base64url encoding without padding
func b64(s []byte) string { return base64.RawURLEncoding.EncodeToString(s) }

// Parse HTTP Link header to get rel => link map
func parseLinks(links []string) map[string]string {
	re := regexp.MustCompile(`<(.*)>;\s*rel="(.*)"`)
	m := make(map[string]string)
	for _, link := range links {
		rs := re.FindStringSubmatch(link)
		m[rs[2]] = rs[1]
	}
	return m
}

// Parse PEM-encoded RSA private key from r.
func parseKey(r io.Reader) (*rsa.PrivateKey, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	blk := new(pem.Block)
	// find the first RSA private key
	for {
		blk, b = pem.Decode(b)
		if blk != nil && blk.Type == "RSA PRIVATE KEY" {
			return x509.ParsePKCS1PrivateKey(blk.Bytes)
		}
	}
	return nil, errors.New("no RSA private key found")
}

// Open PEM-encoded RSA private key at the given path.
func openKey(path string) (*rsa.PrivateKey, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return parseKey(r)
}

// Parse PEM-encoded x509 certificate
func parseCert(r io.Reader) (*x509.Certificate, error) {
	der, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

// Generate RSA private key and write to w in PEM format.
func genKey(w io.Writer, bits int) error {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}

	return pem.Encode(w, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}
