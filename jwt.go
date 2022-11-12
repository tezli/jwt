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
	base64 "encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	JWT_ES256 = "ES256"
	JWT_ES348 = "ES348"
	JWT_ES512 = "ES512"
	JWT_HS256 = "HS256"
	JWT_HS348 = "HS348"
	JWT_HS512 = "HS512"
	JWT_PS256 = "PS256"
	JWT_PS348 = "PS348"
	JWT_PS512 = "PS512"
	JWT_RS256 = "RS256"
	JWT_RS384 = "RS384"
	JWT_RS512 = "RS512"
)

var algorithms = []string{
	JWT_ES256, JWT_ES348, JWT_ES512, JWT_HS256, JWT_HS348, JWT_HS512,
	JWT_PS256, JWT_PS348, JWT_PS512, JWT_RS256, JWT_RS384, JWT_RS512,
}

// Algorithm an abitrary JWT alogithm
type Algorithm interface {
	Sign([]byte) ([]byte, error)
	Verify([]byte, []byte) error
	Name() string
}

// JwtCkaims represents jwt standard claims
type Claims struct {
	Expires   int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	Issuer    string `json:"iss"`
	// Disabled
	// JwtID     string                 `json:"jti"`
	Raw map[string]interface{} `json:"-"`
}

// JwtHeader represents a jwt header
type JwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type JwtToken struct {
	Header    JwtHeader `json:"header"`
	Claims    Claims    `json:"claims"`
	signature []byte    `json:"-"`
}

// CreateToken returns a JWT. First argument are the claims, second the private key
func Create(claims *Claims, algorithm Algorithm) (string, error) {
	if claims == nil {
		claims = &Claims{}
	}
	if algorithm == nil {
		return "", errors.New("algorithm can't be nil")
	}
	jwtHeader := &JwtHeader{
		Alg: algorithm.Name(),
		Typ: "jwt",
	}
	header, _ := json.Marshal(jwtHeader)
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)

	claims.IssuedAt = time.Now().Unix()

	payload, err := json.Marshal(claims)

	if err != nil {
		return "", err
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))

	headerAndPayload := []byte(encodedHeader + "." + encodedPayload)

	signature, err := algorithm.Sign(headerAndPayload)

	if err != nil {
		return "", errors.New("Failed to sign token: " + err.Error())
	}
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	return encodedHeader + "." + encodedPayload + "." + encodedSignature, err
}

func Parse(token string, alg Algorithm) (*JwtToken, error) {
	splitted := strings.Split(token, ".")
	if len(splitted) != 3 {
		return nil, errors.New("Invalid token format")
	}

	encodedHeader := splitted[0]
	header, err := base64.RawURLEncoding.DecodeString(encodedHeader)
	if err != nil {
		return nil, err
	}
	var jwtHeader JwtHeader
	err = json.Unmarshal(header, &jwtHeader)
	if err != nil {
		return nil, err
	}
	ok := false
	for _, accepted := range algorithms {
		if jwtHeader.Alg == accepted {
			ok = true
		}
	}
	if !ok {
		return nil, errors.New("Invalid JWT algorithm")
	}
	if jwtHeader.Alg != alg.Name() {
		return nil, errors.New("Invalid JWT algorithm")
	}

	encodedPayload := splitted[1]
	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, err
	}

	encodedSignature := splitted[2]
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil {
		return nil, err
	}

	headerAndPayload := []byte(encodedHeader + "." + encodedPayload)
	if err = alg.Verify(headerAndPayload, signature); err != nil {
		return nil, errors.New("Invalid signature")
	}

	var claims Claims
	err = json.Unmarshal(payload, &claims)
	if err != nil {
		return nil, err
	}

	var rawClaims map[string]interface{}
	err = json.Unmarshal(payload, &rawClaims)
	if err != nil {
		return nil, err
	}
	claims.Raw = rawClaims

	return &JwtToken{jwtHeader, claims, signature}, nil
}

func (t *JwtToken) IsExpired() bool {
	now := time.Now().Unix()
	return t.Claims.Expires < now
}
