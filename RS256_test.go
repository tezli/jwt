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

import "testing"

func TestRS256(t *testing.T) {
	privateKey, _ := readFixture("rsa")
	alg, err := NewRS256(privateKey)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	err = CheckTokenFor(alg, t)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
}

func TestRS256NilKey(t *testing.T) {
	_, err := NewRS256(nil)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}

func TestRS256NonPemKey(t *testing.T) {
	_, err := NewRS256([]byte("invalid"))
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}

func TestRS256InvalidKey(t *testing.T) {
	privateKey, _ := readFixture("RSA4096.pub")
	_, err := NewRS256(privateKey)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}
