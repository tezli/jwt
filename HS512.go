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

// HS512 provides methods for signing and verifying JWTs with HMAC using SHA-512.
type HS512 struct {
	hmac *HMAC
}

// NewHS512 creates a new HS512 helper from a secret.
func NewHS512(secret []byte) (*HS512, error) {
	hmac, err := newHMAC(JWT_HS512, secret, crypto.SHA512)
	if err != nil {
		return nil, err
	}
	return &HS512{hmac}, nil
}

// Sign signs arbitrary data and returns a signature.
func (alg *HS512) Sign(data []byte) ([]byte, error) {
	return alg.hmac.sign(data)
}

// Verify verifies signed data.
func (alg *HS512) Verify(code, data []byte) error {
	return alg.hmac.verify(code, data)
}

// Name returns the the JWT algorithm name.
func (alg *HS512) Name() string {
	return alg.hmac.name
}
