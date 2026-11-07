package jwt_test

import (
	"fmt"
	"time"

	"github.com/andywang2011/go-jwt"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

func ExampleNewClient() {
	client, err := jwt.NewClient(jwt.Config{Secret: "example-secret"})
	if err != nil {
		fmt.Println("config error")
		return
	}

	token, err := client.GenerateToken(&jwtlib.RegisteredClaims{
		Subject: "user-1",
	}, time.Hour)
	if err != nil {
		fmt.Println("sign error")
		return
	}

	var claims jwtlib.RegisteredClaims
	if err := client.ExtractClaims(token, &claims); err != nil {
		fmt.Println("parse error")
		return
	}
	fmt.Println(claims.Subject != "")
	// Output: true
}
