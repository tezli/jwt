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

import "crypto"

// RS256 provides methods for signing and verifying JWTs with ECDSA521 and SHA512
type RS256 struct {
	rsa *_rsa
}

// NewRS256 creates a new ES512 helper from a RSA private key. The private key must be PEM encoded.
func NewRS256(key []byte) (*RS256, error) {
	rsa, err := newRSA(JWT_RS256, key, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return &RS256{rsa}, nil
}

// Sign signs arbitrary data and returns a signature
func (e *RS256) Sign(data []byte) ([]byte, error) {
	return e.rsa.sign(data)
}

// Verify verifies signed data
func (e *RS256) Verify(data []byte, signature []byte) error {
	return e.rsa.verify(data, signature)
}

// Name returns the the JWT algorithm name
func (e *RS256) Name() string {
	return e.rsa.name
}
