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
