package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"regexp"
)

func loadRSAKey(r io.Reader) (*rsa.PrivateKey, error) {
	d, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	b := new(pem.Block)

	// find the first RSA private key
	for {
		b, d = pem.Decode(d)
		if b != nil && b.Type == "RSA PRIVATE KEY" {
			return x509.ParsePKCS1PrivateKey(b.Bytes)
		}
	}

	return nil, errors.New("no RSA private key found")
}

func saveRSAKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

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

func parseCert(r io.Reader) (*x509.Certificate, error) {
	der, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}
