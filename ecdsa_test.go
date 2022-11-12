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

type MockECDSA struct{}

func TestECDSA256(t *testing.T) {
	key, _ := readFixture("ecdsa_256")
	data := []byte("test")
	ecdsa, err := newECDSA("ES256", key, crypto.SHA256)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	signed, err := ecdsa.sign(data)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	err = ecdsa.verify(data, signed)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
}

func TestECDSAInvalidData(t *testing.T) {
	key, _ := readFixture("ecdsa_256")
	data1 := []byte("test")
	ecdsa, err := newECDSA("ES256", key, crypto.SHA256)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	signed, err := ecdsa.sign(data1)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	data2 := []byte("invalid")
	err = ecdsa.verify(data2, signed)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}

func TestECDSAMultiblock(t *testing.T) {
	key, _ := readFixture("ecdsa.multiblock")
	_, err := newECDSA("ES256", key, crypto.SHA256)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}

func TestECDSAInvalidPrivateKey1(t *testing.T) {
	key, _ := readFixture("ecdsa_256.invalid")
	_, err := newECDSA("ES256", key, crypto.SHA256)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}

func TestECDSAInvalidPrivateKey2(t *testing.T) {
	key, _ := readFixture("ecdsa_256.pub")
	_, err := newECDSA("ES256", key, crypto.SHA256)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}

func TestECDSAInvalidAlgorithm(t *testing.T) {
	key, _ := readFixture("ecdsa_256")
	_, err := newECDSA("ES384", key, crypto.SHA384)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}
