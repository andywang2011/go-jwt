package jwt

import (
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

func TestNewClient(t *testing.T) {
	client, err := NewClient(Config{Secret: testSecret})
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
	client, _ := NewClient(Config{Secret: testSecret})
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
	client, _ := NewClient(Config{Secret: testSecret})
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
	client, _ := NewClient(Config{Secret: testSecret})
	var claims jwtlib.RegisteredClaims
	_, err := client.ParseToken("not-a-jwt", &claims)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_ParseToken_WrongSecret(t *testing.T) {
	a, _ := NewClient(Config{Secret: testSecret})
	b, _ := NewClient(Config{Secret: otherSecret})
	token, _ := a.GenerateToken(&jwtlib.RegisteredClaims{Subject: "u"}, time.Hour)
	var claims jwtlib.RegisteredClaims
	_, err := b.ParseToken(token, &claims)
	if err == nil {
		t.Fatal("expected signature error")
	}
}

func TestClient_ParseToken_NotValidYet(t *testing.T) {
	client, _ := NewClient(Config{Secret: testSecret})
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
	client, _ := NewClient(Config{Secret: testSecret})
	var claims jwtlib.RegisteredClaims
	if err := client.ExtractClaims("bad", &claims); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_ParseToken_UnexpectedSigningMethod(t *testing.T) {
	// Token signed with none algorithm isn't valid HMAC — triggers unexpected method path via malformed flow
	client, _ := NewClient(Config{Secret: testSecret})
	var claims jwtlib.RegisteredClaims
	_, err := client.ParseToken("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.sig", &claims)
	if err == nil {
		t.Fatal("expected error")
	}
}

const (
	testSecret  = "0123456789abcdef0123456789abcdef"
	otherSecret = "fedcba9876543210fedcba9876543210"
)

func TestNewClient_ShortSecret(t *testing.T) {
	_, err := NewClient(Config{Secret: "short"})
	if err == nil {
		t.Fatal("expected error for short secret")
	}
	if _, err := NewClient(Config{Secret: strings.Repeat("a", MinSecretBytes-1)}); err == nil {
		t.Fatal("expected error for 31-byte secret")
	}
	if _, err := NewClient(Config{Secret: strings.Repeat("a", MinSecretBytes)}); err != nil {
		t.Fatalf("32-byte secret rejected: %v", err)
	}
}

func signRaw(t *testing.T, method jwtlib.SigningMethod, key any, claims jwtlib.Claims) string {
	t.Helper()
	s, err := jwtlib.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestClient_ParseToken_RejectsNonHS256(t *testing.T) {
	client, _ := NewClient(Config{Secret: testSecret})
	claims := &jwtlib.RegisteredClaims{
		Subject:   "u",
		ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
	}
	for name, m := range map[string]jwtlib.SigningMethod{
		"HS384": jwtlib.SigningMethodHS384,
		"HS512": jwtlib.SigningMethodHS512,
	} {
		tok := signRaw(t, m, []byte(testSecret), claims)
		var out jwtlib.RegisteredClaims
		if _, err := client.ParseToken(tok, &out); err == nil {
			t.Errorf("%s token accepted", name)
		}
	}

	// alg=none must be rejected.
	none := signRaw(t, jwtlib.SigningMethodNone, jwtlib.UnsafeAllowNoneSignatureType, claims)
	var out jwtlib.RegisteredClaims
	if _, err := client.ParseToken(none, &out); err == nil {
		t.Error("alg=none token accepted")
	}
}

func TestClient_IssuerAudience(t *testing.T) {
	cfg := Config{Secret: testSecret, Issuer: "iss-a", Audience: "aud-a"}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Auto-filled on sign, accepted on parse.
	tok, err := client.GenerateToken(&jwtlib.RegisteredClaims{Subject: "u"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var parsed jwtlib.RegisteredClaims
	if _, err := client.ParseToken(tok, &parsed); err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if parsed.Issuer != "iss-a" || len(parsed.Audience) != 1 || parsed.Audience[0] != "aud-a" {
		t.Fatalf("claims = %+v", parsed)
	}

	exp := jwtlib.NewNumericDate(time.Now().Add(time.Hour))
	cases := []struct {
		name   string
		claims *jwtlib.RegisteredClaims
		want   string
	}{
		{"wrong issuer", &jwtlib.RegisteredClaims{Issuer: "other", Audience: jwtlib.ClaimStrings{"aud-a"}, ExpiresAt: exp}, "invalid issuer"},
		{"missing issuer", &jwtlib.RegisteredClaims{Audience: jwtlib.ClaimStrings{"aud-a"}, ExpiresAt: exp}, "required claim missing"},
		{"wrong audience", &jwtlib.RegisteredClaims{Issuer: "iss-a", Audience: jwtlib.ClaimStrings{"other"}, ExpiresAt: exp}, "invalid audience"},
		{"missing audience", &jwtlib.RegisteredClaims{Issuer: "iss-a", ExpiresAt: exp}, "required claim missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := signRaw(t, jwtlib.SigningMethodHS256, []byte(testSecret), tc.claims)
			var out jwtlib.RegisteredClaims
			_, err := client.ParseToken(raw, &out)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestClient_IssuerAudienceOptional(t *testing.T) {
	client, _ := NewClient(Config{Secret: testSecret})
	raw := signRaw(t, jwtlib.SigningMethodHS256, []byte(testSecret), &jwtlib.RegisteredClaims{
		Issuer: "anything", Audience: jwtlib.ClaimStrings{"whatever"},
		ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Hour)),
	})
	var out jwtlib.RegisteredClaims
	if _, err := client.ParseToken(raw, &out); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestClient_GenerateToken_KeepsExplicitIssuerAudience(t *testing.T) {
	client, _ := NewClient(Config{Secret: testSecret, Issuer: "iss-a", Audience: "aud-a"})
	tok, err := client.GenerateToken(&jwtlib.RegisteredClaims{Issuer: "x", Audience: jwtlib.ClaimStrings{"y"}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var out jwtlib.RegisteredClaims
	_, err = client.ParseToken(tok, &out)
	if err == nil || !strings.Contains(err.Error(), "invalid issuer") {
		t.Fatalf("err = %v", err)
	}
}
