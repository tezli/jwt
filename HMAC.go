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
	"crypto/hmac"
	"errors"
)

// ES512 provides methods for signing and verifying JWTs with ECDSA521 and SHA512
type HMAC struct {
	hash   crypto.Hash
	secret []byte
	name   string
}

func newHMAC(name string, secret []byte, hash crypto.Hash) (*HMAC, error) {
	if secret == nil {
		return nil, errors.New("Secret or private key can't be empty")
	}
	return &HMAC{hash, secret, name}, nil
}

func (e *HMAC) sign(data []byte) ([]byte, error) {
	if data == nil {
		return nil, errors.New("Data to be signed can't be empty")
	}
	hash := e.hash.New()
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func (e *HMAC) verify(data, mac []byte) error {
	hash := e.hash.New()
	hash.Write(data)
	sum := hash.Sum(nil)
	verified := hmac.Equal(mac, sum)
	if verified == false {
		return errors.New("Token could not be verified")
	}
	return nil
}
