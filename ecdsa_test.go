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
