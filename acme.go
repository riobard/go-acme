package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ACME Challenge object
type Challenge struct {
	Type   string
	Status string
	URI    string
	Token  string
	Error  *struct {
		Type   string
		Detail string
	}
}

// ACME Authorization object
type Auth struct {
	Challenges []Challenge
	Expires    time.Time
	Status     string
	Identifier struct {
		Type  string // ACME spec only supports Type=DNS
		Value string // so Value must be a domain name
	}
	Combinations [][]int // pointers to sets of challenges to solve
}

// ACME API
type ACME struct {
	URL string // ACME directory URL
	Dir struct {
		NewReg     string `json:"new-reg"`
		NewCert    string `json:"new-cert"`
		NewAuthz   string `json:"new-authz"`
		RevokeCert string `json:"revoke-cert"`
	}
	key       *rsa.PrivateKey
	keyAuth   map[string]string // token => key authorization
	rwmutex   sync.RWMutex
	noncePool chan string
}

// Connect to the ACME server at the url using the given account key
func OpenACME(url string, key *rsa.PrivateKey) (*ACME, error) {
	acme := &ACME{
		URL:       url,
		key:       key,
		keyAuth:   make(map[string]string),
		noncePool: make(chan string, 100),
	}
	rsp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode != 200 {
		return nil, fmt.Errorf("ACME server error: %s", rsp.Status)
	}
	acme.noncePool <- rsp.Header.Get("Replay-Nonce")
	if err := json.NewDecoder(rsp.Body).Decode(&acme.Dir); err != nil {
		return nil, err
	}
	return acme, nil
}

// Post a JWS signed payload to the given url
func (a *ACME) do(url string, payload []byte) (*http.Response, error) {
	var nonce string
	select {
	case nonce = <-a.noncePool:
	default: // nonce pool is empty
		rsp, err := http.Head(a.URL)
		if err != nil {
			return nil, err
		}
		nonce = rsp.Header.Get("Replay-Nonce")
	}

	rsp, err := http.Post(url, "", bytes.NewBuffer(jsonWebSign(a.key, payload, nonce)))
	if err != nil {
		return nil, err
	}
	go func() { // put back a new nonce
		a.noncePool <- rsp.Header.Get("Replay-Nonce")
	}()
	return rsp, nil
}

// Update the registration object at regURL with the agreement to Terms of
// Service at tosURL.
func (a *ACME) agreeTOS(regURL, tosURL string) error {
	payload, err := json.Marshal(map[string]string{
		"resource":  "reg",
		"agreement": tosURL,
	})
	if err != nil {
		return err
	}

	rsp, err := a.do(regURL, payload)
	if err != nil {
		return err
	}

	if rsp.StatusCode != 202 {
		return fmt.Errorf("failed to agree terms of service: HTTP %s", rsp.Status)
	}
	return nil
}

// Register the account key, even if the key is already registred.
func (a *ACME) NewReg() error {
	payload, err := json.Marshal(map[string]string{
		"resource": "new-reg",
	})
	if err != nil {
		return err
	}
	rsp, err := a.do(a.Dir.NewReg, payload)
	if err != nil {
		return err
	}

	switch rsp.StatusCode {
	case 201: // new registration ok
		links := parseLinks(rsp.Header["Link"])
		// agree to Terms of Service if present
		if tos, ok := links["terms-of-service"]; ok {
			a.agreeTOS(rsp.Header.Get("Location"), tos)
		}
	case 409: // key already registered
	default: // error
		return fmt.Errorf("key registration failed: HTTP %s", rsp.Status)
	}
	return nil
}

// Authorize a domain name. Currently only http-01 method is supported.
func (a *ACME) NewAuthz(domain string) error {
	payload, err := json.Marshal(map[string]interface{}{
		"resource": "new-authz",
		"identifier": map[string]string{
			"type":  "dns",
			"value": domain,
		},
	})
	if err != nil {
		return err
	}

	rsp, err := a.do(a.Dir.NewAuthz, payload)
	if err != nil {
		return err
	}
	if rsp.StatusCode != 201 {
		return fmt.Errorf("failed to create authorization: HTTP %s", rsp.Status)
	}

	auth := new(Auth)
	if err := json.NewDecoder(rsp.Body).Decode(auth); err != nil {
		return err
	}

	for _, c := range auth.Challenges {
		switch c.Type {
		case "http-01":
			if err := a.http01(domain, c.URI, c.Token); err != nil {
				return err
			}
		}
	}

	return nil
}

// Solve http01 challenge at at uri fro domain using token
func (a *ACME) http01(domain, uri, token string) error {
	keyAuth := token + "." + b64(rsa2jwk(a.key).Thumbprint(crypto.SHA256))

	a.rwmutex.Lock()
	a.keyAuth[token] = keyAuth
	a.rwmutex.Unlock()

	// verify that the key auth for the token can be fetched
	url := "http://" + domain + ACMEChallengePathPrefix + token
	rsp, err := http.Get(url)
	if err != nil {
		return err
	}
	if rsp.StatusCode != 200 {
		return fmt.Errorf("failed to fetch key authorization at %s", url)
	}
	b, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return err
	}
	if bytes.Equal(b, []byte(keyAuth)) != true {
		return fmt.Errorf("incorrect key authorization at %s", url)
	}

	// ask the ACME server to start challenge validation
	payload, err := json.Marshal(map[string]string{
		"resource":         "challenge",
		"keyAuthorization": keyAuth,
	})
	if err != nil {
		return err
	}
	rsp, err = a.do(uri, payload)
	if err != nil {
		return err
	}
	if rsp.StatusCode != 202 {
		return fmt.Errorf("failed to post challenge")
	}

	c := new(Challenge)
	if err := json.NewDecoder(rsp.Body).Decode(c); err != nil {
		return err
	}

	// poll to get latest validation status
	for {
		time.Sleep(2 * time.Second)
		rsp, err := http.Get(c.URI)
		if err != nil {
			return err
		}
		if rsp.StatusCode != 202 {
			return fmt.Errorf("HTTP %s", rsp.Status)
		}
		c := new(Challenge)
		if err := json.NewDecoder(rsp.Body).Decode(c); err != nil {
			return err
		}
		switch c.Status {
		case "", "pending", "processing":
			// missing status defaults to pending. wait and poll again.
		case "valid":
			return nil
		default:
			if c.Error != nil {
				return fmt.Errorf("%s [%s] %s", c.Status, c.Error.Type, c.Error.Detail)
			}
			return fmt.Errorf("%s", c.Status)
		}
	}
}

// HTTP handler to solve ACME HTTP challenge
func (a *ACME) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.URL.Path, ACMEChallengePathPrefix)
	a.rwmutex.RLock()
	keyAuth, ok := a.keyAuth[tok]
	a.rwmutex.RUnlock()
	if ok {
		io.WriteString(w, keyAuth)
	} else {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}
}

// Create a new certificate using the given certificate signing request
func (a *ACME) NewCert(csr []byte) (domainCrt *x509.Certificate, issuerCrt *x509.Certificate, err error) {
	payload, err := json.Marshal(map[string]string{
		"resource": "new-cert",
		"csr":      b64(csr),
	})
	if err != nil {
		return nil, nil, err
	}

	rsp, err := a.do(a.Dir.NewCert, payload)
	if err != nil {
		return nil, nil, err
	}

	if rsp.StatusCode != 201 {
		return nil, nil, fmt.Errorf("failed to get domain certificate: HTTP %s", rsp.Status)
	}

	// The server might not return the certificate in the body, in which case
	// we need to poll the Location header to get the actual certificate.  If
	// the certificate is unavailable, GET request to the Location header will
	// return 202 Accepted with a Retry-After header.
	for rsp.Header.Get("Content-Type") != "application/pkix-cert" {
		delay, _ := strconv.Atoi(rsp.Header.Get("Retry-After"))
		if delay == 0 {
			delay = 2
		}
		time.Sleep(time.Duration(delay) * time.Second)
		rsp, err = http.Get(rsp.Header.Get("Location"))
		if err != nil {
			return nil, nil, err
		}
	}

	// now the certificate should be available
	domainCrt, err = parseCert(rsp.Body)
	if err != nil {
		return nil, nil, err
	}

	// fetch issuer certificate
	links := parseLinks(rsp.Header["Link"])
	issuer, ok := links["up"]
	if !ok {
		return nil, nil, fmt.Errorf("issuer certificate not specified")
	}
	rsp, err = http.Get(issuer)
	if err != nil {
		return nil, nil, err
	}
	if rsp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("failed to fetch issuer certificate: HTTP %s", rsp.Status)
	}
	issuerCrt, err = parseCert(rsp.Body)
	if err != nil {
		return nil, nil, err
	}
	return domainCrt, issuerCrt, nil
}
