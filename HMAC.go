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
		return errors.New("Token could not be verfify")
	}
	return nil
}
