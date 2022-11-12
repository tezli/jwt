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

import "testing"

func TestES512(t *testing.T) {
	privateKey, _ := readFixture("ecdsa_521")
	alg, err := NewES512(privateKey)
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

func TestES512InvalidKey(t *testing.T) {
	_, err := NewES512([]byte("invalid"))
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}
