package secure

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestSecretAuthenticationAndContext(t *testing.T) {
	v, e := New(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if e != nil {
		t.Fatal(e)
	}
	sealed := v.Seal("secret", "instance:1")
	if strings.Contains(sealed, "secret") {
		t.Fatal("plaintext leak")
	}
	if p, e := v.Open(sealed, "instance:1"); e != nil || p != "secret" {
		t.Fatal("roundtrip failed")
	}
	if _, e := v.Open(sealed, "instance:2"); e == nil {
		t.Fatal("ciphertext transplant accepted")
	}
	b, _ := base64.StdEncoding.DecodeString(sealed)
	b[len(b)-1] ^= 1
	if _, e := v.Open(base64.StdEncoding.EncodeToString(b), "instance:1"); e == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}
