package jwt

import (
	"errors"
	"fmt"
)

// MinSecretBytes is the minimum HMAC-SHA256 secret length in bytes.
const MinSecretBytes = 32

// Config holds JWT signing settings.
type Config struct {
	// Secret is the HMAC signing key; must be at least MinSecretBytes bytes.
	Secret string
	// Issuer, when set, is required as the "iss" claim when parsing and is
	// added to *jwt.RegisteredClaims on signing when empty.
	Issuer string
	// Audience, when set, must be present in the "aud" claim when parsing and
	// is added to *jwt.RegisteredClaims on signing when empty.
	Audience string
}

// ConfigDefault returns an empty Config; Secret must be set before NewClient.
func ConfigDefault() Config { return Config{} }

// Validate checks required fields.
func (c Config) Validate() error {
	if len(c.Secret) == 0 {
		return errors.New("jwt secret is not set")
	}
	if len(c.Secret) < MinSecretBytes {
		return fmt.Errorf("jwt secret must be at least %d bytes", MinSecretBytes)
	}
	return nil
}
