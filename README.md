# go-jwt

HS256 JWT helper for Go (`github.com/andywang2011/go-jwt`).

```bash
go get github.com/andywang2011/go-jwt@latest
```

## Quick start

### Create client

```go
import (
	"time"

	"github.com/andywang2011/go-jwt"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

client, err := jwt.NewClient(jwt.Config{Secret: "your-secret-key"})
if err != nil {
	return err
}
```

### Sign with standard claims

```go
token, err := client.GenerateToken(&jwtlib.RegisteredClaims{
	Subject: "user-1",
}, time.Hour)
// ExpiresAt / IssuedAt are filled automatically when unset
```

### Sign with custom claims

Define claims in your **application** (not in this library):

```go
type LoginClaims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwtlib.RegisteredClaims
}

claims := &LoginClaims{
	UserID:   100,
	Username: "alice",
	Role:     "admin",
}
token, err := client.GenerateToken(claims, 24*time.Hour)
```

### Parse and extract

```go
var parsed LoginClaims
if err := client.ExtractClaims(token, &parsed); err != nil {
	return err // expired / malformed / invalid signature
}
// use parsed.UserID, parsed.Username, ...
```

Or lower-level parse:

```go
var claims jwtlib.RegisteredClaims
tok, err := client.ParseToken(token, &claims)
if err != nil || !tok.Valid {
	return err
}
```

## Configuration

| Field | Description |
|-------|-------------|
| `Secret` | HMAC signing key (required, non-empty). |

In **demo-api**, map viper in `demo-api/wire/config.LoadJWTConfig()`:

```yaml
jwt:
  secret: your-secret-key
```

```go
cfg := config.LoadJWTConfig()
client := config.NewJWTClient(cfg)
```

## Examples

Runnable example (sign custom claims, then extract):

```bash
cd examples
go run .
```

Prints a JWT string and parsed `user_id` / `username` / `subject`.

## API

| Method | Description |
|--------|-------------|
| `NewClient(cfg)` | Create client; error if secret empty. |
| `GenerateToken(claims, ttl)` | Sign HS256 token; auto-fills `RegisteredClaims` timestamps. |
| `ParseToken(tokenStr, claims)` | Parse and validate; maps jwt/v5 errors to readable messages. |
| `ExtractClaims(tokenStr, claims)` | Parse + verify into `claims`. |

## Error messages

| Case | Error |
|------|-------|
| Expired | `token expired` |
| Bad format | `token malformed` |
| Wrong secret | `invalid signature` |
| Not yet valid | `token not valid yet` |

## Design

- Config injection only — viper stays in the application layer.
- No global singleton; inject `*jwt.Client` via Wire or constructor.
- Custom claim types belong in the app (e.g. `demo-api/pkg/auth/LoginClaims`).

## 中文摘要

HS256 JWT 签发与解析：`Config{Secret}` 注入，支持自定义 Claims。业务 Claims 放在应用层；demo-api 通过 `wire/config.LoadJWTConfig()` 读 `jwt.secret`。
