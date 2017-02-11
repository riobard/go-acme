package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	ACMEChallengePathPrefix = "/.well-known/acme-challenge/"
	LetsEncryptStaging      = "https://acme-staging.api.letsencrypt.org/directory"
	LetsEncryptProduction   = "https://acme-v01.api.letsencrypt.org/directory"
)

var cfg struct {
	accKey  string // path to account key
	crtKey  string // path to certificate key
	Addr    string
	Domains string // comma-separated domains
	API     string
	GenRSA  int
	Delay   time.Duration
}

func init() {
	log.SetFlags(0) // do not log date
	flag.StringVar(&cfg.accKey, "acckey", "", "path to account key")
	flag.StringVar(&cfg.crtKey, "crtkey", "", "path to certificate key")
	flag.StringVar(&cfg.Addr, "addr", "127.0.0.1:81", "challenge server address")
	flag.StringVar(&cfg.Domains, "domains", "", "comma-separated list of up to 100 domain names")
	flag.StringVar(&cfg.API, "api", LetsEncryptProduction, "ACME API URL")
	flag.IntVar(&cfg.GenRSA, "genrsa", 0, "generate RSA private key of the given bits in length")
	flag.DurationVar(&cfg.Delay, "delay", 100*time.Millisecond, "delay per authorization to avoid hitting rate limit")
	flag.Parse()
}

func main() {

	if cfg.GenRSA > 0 {
		if err := genKey(os.Stdout, cfg.GenRSA); err != nil {
			log.Printf("Failed to generate RSA key: %v", err)
		}
		return
	}

	domains := strings.Split(cfg.Domains, ",")
	if len(domains) > 100 {
		log.Fatalf("Too many domains (%d > 100)", len(domains))
	}

	// read account key
	accKey, err := openKey(cfg.accKey)
	if err != nil {
		log.Fatalf("Failed to parse account key: %s", err)
	}

	// read certificate key
	crtKey, err := openKey(cfg.crtKey)
	if err != nil {
		log.Fatalf("Failed to parse certificate key: %s", err)
	}

	log.Printf("Connecting to ACME server at %s", cfg.API)
	acme, err := OpenACME(cfg.API, accKey)
	if err != nil {
		log.Fatalf("Failed to connect to ACME server: %s", err)
	}

	// start the challenge server in background
	log.Printf("Responding to ACME challenges at http://%s", cfg.Addr)
	go http.ListenAndServe(cfg.Addr, acme)

	log.Printf("Registering account key")
	if err := acme.NewReg(); err != nil {
		log.Fatalf("Failed to register account key: %s", err)
	}

	// authorize domains in parallel
	type Done struct {
		Domain string
		Error  error
	}
	ch := make(chan Done)
	for _, domain := range domains {
		go func(domain string) {
			log.Printf("Authorizing domain %s", domain)
			done := Done{Domain: domain}
			if err := acme.NewAuthz(domain); err != nil {
				done.Error = err
			}
			ch <- done
		}(domain)
		time.Sleep(cfg.Delay) // sleep 0.1 sec to avoid hitting rate limit
	}

	// collect authorization result
	failed := false
	for range domains {
		if done := <-ch; done.Error != nil {
			failed = true
			log.Printf("Failed to authorize domain %s: %s", done.Domain, done.Error)
		} else {
			log.Printf("Authorized domain %s", done.Domain)
		}
	}
	if failed {
		log.Fatalln("Some domains failed authorization")
	}

	// create certificate signing request
	tpl := &x509.CertificateRequest{DNSNames: domains}
	csr, err := x509.CreateCertificateRequest(rand.Reader, tpl, crtKey)
	if err != nil {
		log.Fatalf("Failed to create certificate request: %s", err)
	}

	log.Printf("Fetching certificates")
	domainCrt, issuerCrt, err := acme.NewCert(csr)
	if err != nil {
		log.Fatalf("Failed to fetch certificates: %s", err)
	}

	// print domain certificate in PEM to stdout
	if err := pem.Encode(os.Stdout, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: domainCrt.Raw,
	}); err != nil {
		log.Fatalln(err)
	}

	// print issuer certificate in PEM to stdout
	if err := pem.Encode(os.Stdout, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuerCrt.Raw,
	}); err != nil {
		log.Fatalln(err)
	}
}
