package jwt

import "errors"

// Config holds JWT signing settings.
type Config struct {
	Secret string
}

// Validate checks required fields.
func (c Config) Validate() error {
	if len(c.Secret) == 0 {
		return errors.New("jwt secret is not set")
	}
	return nil
}
