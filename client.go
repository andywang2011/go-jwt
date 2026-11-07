package jwt

import (
	"errors"
	"fmt"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

type hsClient struct {
	secretKey []byte
}

var _ Client = (*hsClient)(nil)

// NewClient creates a client from Config.
func NewClient(cfg Config) (Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &hsClient{secretKey: []byte(cfg.Secret)}, nil
}

// GenerateToken signs customClaims with ttl. RegisteredClaims get ExpiresAt/IssuedAt when unset.
func (client *hsClient) GenerateToken(customClaims jwtlib.Claims, ttl time.Duration) (string, error) {
	if claims, ok := customClaims.(*jwtlib.RegisteredClaims); ok {
		if claims.ExpiresAt == nil {
			claims.ExpiresAt = jwtlib.NewNumericDate(time.Now().Add(ttl))
		}
		if claims.IssuedAt == nil {
			claims.IssuedAt = jwtlib.NewNumericDate(time.Now())
		}
	}

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, customClaims)
	return token.SignedString(client.secretKey)
}

// ParseToken validates and parses tokenStr into claims.
func (client *hsClient) ParseToken(tokenStr string, claims jwtlib.Claims) (*jwtlib.Token, error) {
	token, err := jwtlib.ParseWithClaims(tokenStr, claims, func(token *jwtlib.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwtlib.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return client.secretKey, nil
	})
	if err != nil {
		switch {
		case errors.Is(err, jwtlib.ErrTokenExpired):
			return nil, fmt.Errorf("token expired")
		case errors.Is(err, jwtlib.ErrTokenMalformed):
			return nil, fmt.Errorf("token malformed")
		case errors.Is(err, jwtlib.ErrTokenSignatureInvalid):
			return nil, fmt.Errorf("invalid signature")
		case errors.Is(err, jwtlib.ErrTokenNotValidYet):
			return nil, fmt.Errorf("token not valid yet")
		default:
			return nil, fmt.Errorf("token invalid: %w", err)
		}
	}
	return token, nil
}

// ExtractClaims parses tokenStr and verifies validity into claims.
func (client *hsClient) ExtractClaims(tokenStr string, claims jwtlib.Claims) error {
	token, err := client.ParseToken(tokenStr, claims)
	if err != nil {
		return err
	}
	if !token.Valid {
		return fmt.Errorf("invalid token")
	}
	return nil
}
