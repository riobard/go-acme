package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
)

// JSON Web Key public RSA key
type JSONWebKey struct {
	Type string
	E    int
	N    *big.Int
}

// Make a JSON Web Key from an RSA private key
func rsa2jwk(key *rsa.PrivateKey) *JSONWebKey {
	pub := key.Public().(*rsa.PublicKey)
	return &JSONWebKey{Type: "RSA", E: pub.E, N: pub.N}
}

func (k *JSONWebKey) MarshalJSON() ([]byte, error) {
	d := map[string]string{
		"kty": k.Type,
		"e":   b64(big.NewInt(int64(k.E)).Bytes()),
		"n":   b64(k.N.Bytes()),
	}
	return json.Marshal(d)
}

// Compute the thumbprint of the JWK using the given crypto hash
func (k *JSONWebKey) Thumbprint(hash crypto.Hash) []byte {
	// NOTE: This is not _strictly_ correct per RFC7638, as it requires that
	// JWK JSON object to have lexicographically ordered keys before computing
	// the thumbprint. Additionally, all unnecessary whitespaces must be trimmed.
	// Go's default JSON serialization of map fits the requirement for this case.

	j, err := json.Marshal(k)
	if err != nil {
		panic(err) // this should never happen
	}
	h := hash.New()
	h.Write(j)
	return h.Sum(nil)
}

// RFC7518 JSON Web Algorithms RS256 algorithm: RSA with SHA256
func rs256(key *rsa.PrivateKey, data []byte) []byte {
	h := crypto.SHA256.New()
	h.Write(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h.Sum(nil))
	if err != nil {
		panic(err) // this should never happen
	}
	return sig
}

// RFC7515 JSON Web Signature JSON serialization with replay protection
func jsonWebSign(key *rsa.PrivateKey, payload []byte, nonce string) []byte {
	jwk := rsa2jwk(key)

	// JWS protected header
	protected := map[string]interface{}{
		"alg":   "RS256",
		"jwk":   jwk,
		"nonce": nonce,
	}
	b, err := json.Marshal(protected)
	if err != nil {
		panic(err) // this should never happen
	}

	protected64 := b64(b)
	payload64 := b64(payload)

	// JWS JSON serializaton
	j, err := json.Marshal(map[string]string{
		"protected": protected64,
		"payload":   payload64,
		"signature": b64(rs256(key, []byte(protected64+"."+payload64))),
	})
	if err != nil {
		panic(err) // this should never happen
	}
	return j
}
