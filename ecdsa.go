/*
Copyright © 2022 Robert Tezli robert.tezli+github@gmail.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

const (
	ECDSA_P256 = "P-256"
	ECDSA_P348 = "P-384"
	ECDSA_P521 = "P-521"
)

var JWT_ECDS_MAP = map[string]string{
	JWT_ES256: ECDSA_P256,
	JWT_ES348: ECDSA_P348,
	JWT_ES512: ECDSA_P521,
}

// ES512 provides methods for signing and verifying JWTs with ECDSA521 and SHA512
type _ecdsa struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	hash       crypto.Hash
	name       string
}

// newECDSA creates a new ECDSA helper from a private key
func newECDSA(name string, key []byte, hash crypto.Hash) (*_ecdsa, error) {
	if key == nil {
		return nil, errors.New("key is empty")
	}
	block, rest := pem.Decode(key)
	if block == nil {
		return nil, errors.New("Could not parse private key from PEM file")
	}
	if len(rest) > 0 {
		return nil, errors.New("Multiple blocks per key are not supported")
	}
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	params := privateKey.Params()
	requiredKey := JWT_ECDS_MAP[name]
	if requiredKey != params.Name {
		return nil, errors.New("JWT algorithm does not match private key. Want: " + requiredKey + ". Have: " + params.Name)
	}
	return &_ecdsa{privateKey, &privateKey.PublicKey, hash, name}, nil
}

// Sign signs arbitrary data and returns a signature
func (e *_ecdsa) sign(data []byte) ([]byte, error) {
	hash := e.hash.New()
	hash.Write(data)
	sum := hash.Sum(nil)
	return ecdsa.SignASN1(rand.Reader, e.privateKey, sum)
}

// Verify verifies signed data
func (e *_ecdsa) verify(data []byte, signature []byte) error {
	hash := e.hash.New()
	hash.Write(data)
	sum := hash.Sum(nil)
	verified := ecdsa.VerifyASN1(e.publicKey, sum, signature)
	if verified != true {
		return errors.New("Token could not be verified")
	}
	return nil
}
