package jwt

import "testing"

func TestConfig_Validate(t *testing.T) {
	if err := (Config{Secret: testSecret}).Validate(); err != nil {
		t.Errorf("Validate(has secret) = %v", err)
	}
	if err := (Config{}).Validate(); err == nil {
		t.Error("Validate(empty) expected error")
	}
}

func TestConfig_Validate_ShortSecret(t *testing.T) {
	if err := (Config{Secret: "short"}).Validate(); err == nil {
		t.Error("expected error for short secret")
	}
}
