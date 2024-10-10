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
		return nil, errors.New("Key is empty")
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
