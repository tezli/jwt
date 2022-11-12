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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type _rsapss struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	hash       crypto.Hash
	name       string
	options    *rsa.PSSOptions
}

func newRSAPSS(name string, key []byte, hash crypto.Hash) (*_rsapss, error) {
	if key == nil {
		return nil, errors.New("key is empty")
	}
	block, rest := pem.Decode(key)
	if block == nil {
		return nil, errors.New("Could not parse private key from PEM file")
	}
	if len(rest) > 0 {
		return nil, errors.New("Multiple blocks per key file are not supported")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey := &privateKey.PublicKey

	options := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: hash}
	return &_rsapss{privateKey, publicKey, hash, name, options}, nil
}

func (e *_rsapss) sign(data []byte) ([]byte, error) {
	hasher := e.hash.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)
	return rsa.SignPSS(rand.Reader, e.privateKey, e.hash, hash, e.options)
}

func (e *_rsapss) verify(data []byte, signature []byte) error {
	hasher := e.hash.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)
	return rsa.VerifyPSS(e.publicKey, e.hash, hash, signature, e.options)
}
