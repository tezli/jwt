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

// ES512 provides methods for signing and verifying JWTs of type ES512.
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
