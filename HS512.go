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

type HS512 struct {
	hmac *HMAC
}

func NewHS512(secret []byte) (*HS512, error) {
	hmac, err := newHMAC(JWT_HS512, secret, crypto.SHA512)
	if err != nil {
		return nil, err
	}
	return &HS512{hmac}, nil
}

func (alg *HS512) Sign(data []byte) ([]byte, error) {
	return alg.hmac.sign(data)
}

func (alg *HS512) Verify(code, data []byte) error {
	return alg.hmac.verify(code, data)
}

func (alg *HS512) Name() string {
	return alg.hmac.name
}
