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
	"os"
	"path"
	"testing"
	"time"
)

func TestCreateES256(t *testing.T) {
	claims := &Claims{Expires: time.Now().Add(time.Hour).Unix()}
	fixture := "ecdsa_256"
	key, _ := readFixture(fixture)
	alogithm, err := NewES256(key)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	token, err := Create(claims, alogithm)
	if token == "" {
		t.Log(err)
		t.Fail()
	}
	writeFixture(fixture+".token", []byte(token))
}

func TestCreateES384(t *testing.T) {
	claims := &Claims{Expires: time.Now().Add(time.Hour).Unix()}
	fixture := "ecdsa_384"
	key, _ := readFixture(fixture)
	alogithm, err := NewES384(key)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	token, err := Create(claims, alogithm)
	if token == "" {
		t.Log(err)
		t.Fail()
	}
	writeFixture(fixture+".token", []byte(token))
}

func TestCreateES512(t *testing.T) {
	claims := &Claims{Expires: time.Now().Add(time.Hour).Unix()}
	fixture := "ecdsa_521"
	key, _ := readFixture(fixture)
	alogithm, err := NewES512(key)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	token, err := Create(claims, alogithm)
	if token == "" {
		t.Log(err)
		t.Fail()
	}
	writeFixture(fixture+".token", []byte(token))
}

func TestCreateRS256(t *testing.T) {
	claims := &Claims{Expires: time.Now().Add(time.Hour).Unix()}
	fixture := "rsa"
	key, _ := readFixture(fixture)
	alogithm, err := NewRS256(key)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	token, err := Create(claims, alogithm)
	if token == "" {
		t.Log(err)
		t.Fail()
	}
	writeFixture(fixture+".RS256.token", []byte(token))
}

func TestCreateRS384(t *testing.T) {
	claims := &Claims{Expires: time.Now().Add(time.Hour).Unix()}
	fixture := "rsa"
	key, _ := readFixture(fixture)
	alogithm, err := NewRS384(key)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	token, err := Create(claims, alogithm)
	if token == "" {
		t.Log(err)
		t.Fail()
	}
	writeFixture(fixture+".RS384.token", []byte(token))
}

func TestCreateRS512(t *testing.T) {
	claims := &Claims{Expires: time.Now().Add(time.Hour).Unix()}
	fixture := "rsa"
	key, _ := readFixture(fixture)
	alogithm, err := NewRS512(key)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	token, err := Create(claims, alogithm)
	if token == "" {
		t.Log(err)
		t.Fail()
	}
	writeFixture(fixture+".RS512.token", []byte(token))
}

func TestCreateExpiredToken(t *testing.T) {
	claims := &Claims{}
	key, _ := readFixture("ecdsa_256")
	alogithm, err := NewES256(key)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	tk, err := Create(claims, alogithm)
	token, err := Parse(tk, alogithm)
	if token.IsExpired() == false {
		t.Log(err)
		t.Fail()
	}
}

func TestCreateInvalidtAlg(t *testing.T) {
	claims := &Claims{Expires: time.Now().Add(time.Hour).Unix()}
	_, err := Create(claims, nil)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}

func TestCreateNilClaims(t *testing.T) {
	_, err := Create(nil, nil)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}

func TestCreateInvalidClaims(t *testing.T) {
	claims := &Claims{
		Raw: nil,
	}
	_, err := Create(claims, nil)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}

func TestVerifyInvalidToken(t *testing.T) {
	key, _ := readFixture("ecdsa_256")
	alogithm, err := NewES256(key)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	_, err = Parse("", alogithm)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
	_, err = Parse("...", alogithm)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
	_, err = Parse("a.a.a", alogithm)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
	_, err = Parse("YQo=.a.a", alogithm)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
	_, err = Parse("e251bGx9Cg==.a.a", alogithm)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
	_, err = Parse("e30K.a.a", alogithm)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}

func CheckTokenFor(algorithm Algorithm, t *testing.T) error {
	claims := &Claims{
		Expires: 0,
	}
	tokenString, err := Create(claims, algorithm)
	if err != nil {
		return err
	}
	_, err = Parse(tokenString, algorithm)
	if err != nil {
		return err
	}
	return nil
}

func readFixture(file string) ([]byte, error) {
	pwd, _ := os.Getwd()
	filePath := path.Join(pwd, "fixtures", file)
	return os.ReadFile(filePath)
}

func writeFixture(file string, data []byte) error {
	pwd, _ := os.Getwd()
	filePath := path.Join(pwd, "fixtures", file)
	return os.WriteFile(filePath, data, os.ModePerm)
}
