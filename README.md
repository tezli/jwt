# JWT
![build](https://github.com/tezli/jwt/actions/workflows/main.yml/badge.svg)
[![codecov](https://codecov.io/gh/tezli/jwt/branch/main/graph/badge.svg?token=WDOECHPVZ0)](https://codecov.io/gh/tezli/jwt)

Feature complete, zero dependecy JWT library.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE OPEN GROUP BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Installation

```shell
$ go get github.com/tezli/jwt
```

# Usage

```go
package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/tezli/jwt"
)

func main() {
	key := os.Getenv("JWT_PRIVATE_KEY")
	privateKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		log.Fatalf("Could read private key: %s", err.Error())
	}

	// selecting an algoithm
	algorithm, err := jwt.NewES256(privateKey)
	if err != nil {
		log.Fatalf("Could not instantiate algorithm: %s", err.Error())
	}

	// creating a token
	then := time.Now().Add(time.Hour).Unix()
	claims := &jwt.Claims{
		Expires: then,
	}
	createdToken, err := jwt.Create(claims, algorithm)
	if err != nil {
		log.Fatalf("Could not create token: %s", err.Error())
	}

	// parsing a token
	parsedToken, err := jwt.Parse(createdToken, algorithm)
	if err != nil {
		log.Fatalf("Could not parse token: %s", err.Error())
	}

	// verifying a token
	if !parsedToken.IsValid() || parsedToken.IsExpired() {
		log.Fatal("Token ist not valid (anymore)")
	}
	fmt.Println("OK")
}

```
 
