// Example: sign a JWT with custom claims and extract them back.
package main

import (
	"fmt"
	"log"
	"time"

	libjwt "github.com/andywang2011/go-jwt"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

type loginClaims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	jwtlib.RegisteredClaims
}

func main() {
	client, err := libjwt.NewClient(libjwt.Config{Secret: "example-secret-at-least-32-bytes!!"})
	if err != nil {
		log.Fatal(err)
	}

	token, err := client.GenerateToken(&loginClaims{
		UserID:   42,
		Username: "alice",
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject: "user-42",
		},
	}, time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("token:", token)

	var parsed loginClaims
	if err := client.ExtractClaims(token, &parsed); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("user_id=%d username=%s subject=%s\n", parsed.UserID, parsed.Username, parsed.Subject)
}
