package jwt

import "errors"

// Config holds JWT signing settings.
type Config struct {
	// Secret is the HMAC signing key; must be non-empty.
	Secret string
}

// ConfigDefault returns an empty Config; Secret must be set before NewClient.
func ConfigDefault() Config { return Config{} }

// Validate checks required fields.
func (c Config) Validate() error {
	if len(c.Secret) == 0 {
		return errors.New("jwt secret is not set")
	}
	return nil
}
