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

func TestRSA(t *testing.T) {
	key, _ := readFixture("rsa")
	data := []byte("test")
	rsa, err := newRSA("RS256", key, crypto.SHA256)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	signed, err := rsa.sign(data)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	err = rsa.verify(data, signed)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
}

func TestRSAInvalidData(t *testing.T) {
	key, _ := readFixture("rsa")
	data1 := []byte("test")
	rsa, err := newRSA("RS256", key, crypto.SHA256)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	signed, err := rsa.sign(data1)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	data2 := []byte("invalid")
	err = rsa.verify(data2, signed)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}

func TestRSAMultiblock(t *testing.T) {
	key, _ := readFixture("rsa.multiblock")
	_, err := newRSA("RS256", key, crypto.SHA256)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}

func TestRSAInvalidPrivateKey(t *testing.T) {
	key, _ := readFixture("rsa.pub")
	_, err := newRSA("RS256", key, crypto.SHA256)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}
