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
