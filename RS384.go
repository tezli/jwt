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

// RS384 provides methods for signing and verifying JWTs with RSASSA-PKCS1 using SHA-384.
type RS384 struct {
	rsa *_rsa
}

// NewRS384 creates a new RS384 helper from a RSA private key. The private key must be PEM encoded.
func NewRS384(key []byte) (*RS384, error) {
	rsa, err := newRSA(JWT_RS384, key, crypto.SHA384)
	if err != nil {
		return nil, err
	}
	return &RS384{rsa}, nil
}

// Sign signs arbitrary data and returns a signature.
func (e *RS384) Sign(data []byte) ([]byte, error) {
	return e.rsa.sign(data)
}

// Verify verifies signed data.
func (e *RS384) Verify(data []byte, signature []byte) error {
	return e.rsa.verify(data, signature)
}

// Name returns the the JWT algorithm name
func (e *RS384) Name() string {
	return e.rsa.name
}
