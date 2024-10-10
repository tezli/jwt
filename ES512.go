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

// ES512 provides methods for signing and verifying JWTs with ECDSA using P-521 and SHA-512.
type ES512 struct {
	ecdsa *_ecdsa
}

// NewES512 creates a new ES512 helper from a ECDSA private key. The private key must be PEM encoded.
func NewES512(key []byte) (*ES512, error) {
	ecdsa, err := newECDSA(JWT_ES512, key, crypto.SHA512)
	if err != nil {
		return nil, err
	}
	return &ES512{ecdsa}, nil
}

// Sign signs arbitrary data and returns a signature.
func (e *ES512) Sign(data []byte) ([]byte, error) {
	return e.ecdsa.sign(data)
}

// Verify verifies signed data.
func (e *ES512) Verify(data []byte, signature []byte) error {
	return e.ecdsa.verify(data, signature)
}

// Name returns the the JWT algorithm name.
func (e *ES512) Name() string {
	return e.ecdsa.name
}
