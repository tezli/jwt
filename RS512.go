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

import "crypto"

// RS512 provides methods for signing and verifying JWTs with RSASSA-PKCS1 using SHA-512.
type RS512 struct {
	rsa *_rsa
}

// NewRS512 creates a new ES512 helper from a RSA private key. The private key must be PEM encoded.
func NewRS512(key []byte) (*RS512, error) {
	rsa, err := newRSA(JWT_RS512, key, crypto.SHA512)
	if err != nil {
		return nil, err
	}
	return &RS512{rsa}, nil
}

// Sign signs arbitrary data and returns a signature or and error if signing failed
func (e *RS512) Sign(data []byte) ([]byte, error) {
	return e.rsa.sign(data)
}

// Verify verifies signed data
func (e *RS512) Verify(data []byte, signature []byte) error {
	return e.rsa.verify(data, signature)
}

// Name returns the the JWT algorithm name
func (e *RS512) Name() string {
	return e.rsa.name
}
