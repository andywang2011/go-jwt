package jwt

import (
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

func TestNewClient(t *testing.T) {
	client, err := NewClient(Config{Secret: "test-secret"})
	if err != nil {
		t.Fatalf("NewClient err = %v", err)
	}
	if client == nil {
		t.Fatal("client is nil")
	}
}

func TestNewClient_EmptySecret(t *testing.T) {
	_, err := NewClient(Config{})
	if err == nil {
		t.Error("expected error for empty secret")
	}
}

func TestClient_GenerateToken_ParseToken(t *testing.T) {
	client, _ := NewClient(Config{Secret: "secret"})
	claims := &jwtlib.RegisteredClaims{Subject: "user-1"}
	token, err := client.GenerateToken(claims, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken err = %v", err)
	}
	if token == "" {
		t.Fatal("token is empty")
	}
	var parsed jwtlib.RegisteredClaims
	_, err = client.ParseToken(token, &parsed)
	if err != nil {
		t.Fatalf("ParseToken err = %v", err)
	}
	if parsed.Subject != "user-1" {
		t.Errorf("Subject = %q", parsed.Subject)
	}
}

func TestClient_ExtractClaims(t *testing.T) {
	client, _ := NewClient(Config{Secret: "secret"})
	claims := &jwtlib.RegisteredClaims{Subject: "x"}
	token, _ := client.GenerateToken(claims, time.Hour)
	var out jwtlib.RegisteredClaims
	if err := client.ExtractClaims(token, &out); err != nil {
		t.Fatalf("ExtractClaims err = %v", err)
	}
	if out.Subject != "x" {
		t.Errorf("Subject = %q", out.Subject)
	}
}

func TestClient_ParseToken_Malformed(t *testing.T) {
	client, _ := NewClient(Config{Secret: "secret"})
	var claims jwtlib.RegisteredClaims
	_, err := client.ParseToken("not-a-jwt", &claims)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_ParseToken_WrongSecret(t *testing.T) {
	a, _ := NewClient(Config{Secret: "a"})
	b, _ := NewClient(Config{Secret: "b"})
	token, _ := a.GenerateToken(&jwtlib.RegisteredClaims{Subject: "u"}, time.Hour)
	var claims jwtlib.RegisteredClaims
	_, err := b.ParseToken(token, &claims)
	if err == nil {
		t.Fatal("expected signature error")
	}
}

func TestClient_ParseToken_NotValidYet(t *testing.T) {
	client, _ := NewClient(Config{Secret: "secret"})
	claims := &jwtlib.RegisteredClaims{
		NotBefore: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwtlib.NewNumericDate(time.Now()),
	}
	token, err := client.GenerateToken(claims, 0)
	if err != nil {
		t.Fatal(err)
	}
	var parsed jwtlib.RegisteredClaims
	_, err = client.ParseToken(token, &parsed)
	if err == nil {
		t.Fatal("expected not valid yet error")
	}
}

func TestClient_ExtractClaims_InvalidToken(t *testing.T) {
	client, _ := NewClient(Config{Secret: "secret"})
	var claims jwtlib.RegisteredClaims
	if err := client.ExtractClaims("bad", &claims); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_ParseToken_UnexpectedSigningMethod(t *testing.T) {
	// Token signed with none algorithm isn't valid HMAC — triggers unexpected method path via malformed flow
	client, _ := NewClient(Config{Secret: "secret"})
	var claims jwtlib.RegisteredClaims
	_, err := client.ParseToken("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.sig", &claims)
	if err == nil {
		t.Fatal("expected error")
	}
}
