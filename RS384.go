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

// RS384 provides methods for signing and verifying JWTs of type RS384.
type RS384 struct {
	rsa *_rsa
}

// NewRS384 creates a new ES512 helper from a RSA private key. The private key must be PEM encoded.
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
