package jwt

import (
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

// Client signs and parses HS256 JWT tokens (mock-friendly).
type Client interface {
	// GenerateToken signs customClaims with ttl. RegisteredClaims get ExpiresAt/IssuedAt when unset.
	GenerateToken(customClaims jwtlib.Claims, ttl time.Duration) (string, error)
	// ParseToken validates and parses tokenStr into claims.
	ParseToken(tokenStr string, claims jwtlib.Claims) (*jwtlib.Token, error)
	// ExtractClaims parses tokenStr and verifies validity into claims.
	ExtractClaims(tokenStr string, claims jwtlib.Claims) error
}
