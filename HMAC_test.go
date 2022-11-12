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
	"testing"
)

func TestHMAC(t *testing.T) {
	data := []byte("test")
	hmac, err := newHMAC(JWT_HS256, []byte("test"), crypto.SHA256)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	signed, err := hmac.sign(data)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	err = hmac.verify(data, signed)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
}

func TestSignNilData(t *testing.T) {
	hmac, err := newHMAC(JWT_HS256, []byte("test"), crypto.SHA256)
	_, err = hmac.sign(nil)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}

func TestHMACNilSecret(t *testing.T) {
	_, err := newHMAC(JWT_HS256, nil, crypto.SHA256)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}

func TestHMACVerfiyFailure(t *testing.T) {
	hmac, err := newHMAC(JWT_HS256, []byte("secret"), crypto.SHA256)
	err = hmac.verify([]byte("invalid"), []byte("invalid"))
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}
