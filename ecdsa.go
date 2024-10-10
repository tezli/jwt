/*
MIT License

Copyright (c) 2022 Róbert Tézli (robert.tezli+github@gmail.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
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

type _ecdsa struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	hash       crypto.Hash
	name       string
}

func newECDSA(name string, key []byte, hash crypto.Hash) (*_ecdsa, error) {
	if key == nil {
		return nil, errors.New("Key is empty")
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

func (e *_ecdsa) sign(data []byte) ([]byte, error) {
	hash := e.hash.New()
	hash.Write(data)
	sum := hash.Sum(nil)
	return ecdsa.SignASN1(rand.Reader, e.privateKey, sum)
}

// Verify Verifies signed data
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
