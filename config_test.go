package jwt

import "testing"

func TestConfig_Validate(t *testing.T) {
	if err := (Config{Secret: "x"}).Validate(); err != nil {
		t.Errorf("Validate(has secret) = %v", err)
	}
	if err := (Config{}).Validate(); err == nil {
		t.Error("Validate(empty) expected error")
	}
}
