# go-jwt

HS256 JWT sign and parse helper with injectable config.

## Install

```bash
go get github.com/andywang2011/go-jwt@v0.1.0
```

## Quick start

```go
import (
	"fmt"
	"time"

	"github.com/andywang2011/go-jwt"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

client, err := jwt.NewClient(jwt.Config{Secret: "example-secret-at-least-32-bytes!!"})
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
```

## Examples

```bash
cd go-jwt/examples && go run .
```

## License

MIT — see [LICENSE](LICENSE).
