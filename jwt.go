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

// Algorithm representing one of the supported JWT alogrithms:
// ECDSA-SHA:        ES256, ES348, ES512
// HMAC-SHA:         HS256, HS348, HS512
// RSASSA-PSS-SHA:   PS256, PS348, PS512
// RSASSA-PKCS1-SHA: RS256, RS384, RS512
// None is not supported
type Algorithm interface {
	Sign([]byte) ([]byte, error)
	Verify([]byte, []byte) error
	Name() string
}

// JwtCkaims represents JWT standard claims
type Claims struct {
	Expires   int64                  `json:"exp"`
	IssuedAt  int64                  `json:"iat"`
	NotBefore int64                  `json:"nbf"`
	Subject   string                 `json:"sub"`
	Audience  string                 `json:"aud"`
	Issuer    string                 `json:"iss"`
	Raw       map[string]interface{} `json:"-"`
}

// JwtHeader represents a JWT header
type JwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// JwtToken represents a JWT token
type JwtToken struct {
	Header    JwtHeader `json:"header"`
	Claims    Claims    `json:"claims"`
	signature []byte    `json:"-"`
}

// CreateToken returns a JWT. First argument is the claims, second the private key.
func Create(claims *Claims, algorithm Algorithm) (string, error) {
	if claims == nil {
		claims = &Claims{}
	}
	if algorithm == nil {
		return "", errors.New("Algorithm can't be nil")
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

// Parse parses a JWT token from a string.
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

// IsExpired checks if a token is expired.
func (t *JwtToken) IsExpired() bool {
	now := time.Now().Unix()
	return t.Claims.Expires < now
}
