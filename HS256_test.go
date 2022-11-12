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

func TestHS256(t *testing.T) {
	alg, err := NewHS256([]byte("test"))
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

func TestHS256WithNilSecret(t *testing.T) {
	_, err := NewHS256(nil)
	if err == nil {
		t.Log(err)
		t.Fail()
	}
}
