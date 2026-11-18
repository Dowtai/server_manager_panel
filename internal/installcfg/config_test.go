package installcfg

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func validInput() Input {
	return Input{Username: "operator", Password: "not-stored-plaintext-123", Domain: "panel.example.org", Email: "ops+vpn@example.org", Port: 9443, RuntimeImage: "sha256:" + strings.Repeat("a", 64)}
}
func parse(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			out[key] = strings.Trim(value, "'")
		}
	}
	return out
}
func TestGeneratedConfigurationKeepsOnlyPasswordHash(t *testing.T) {
	in := validInput()
	data, e := Generate(in)
	if e != nil {
		t.Fatal(e)
	}
	values := parse(data)
	if strings.Contains(string(data), in.Password) {
		t.Fatal("plaintext password stored")
	}
	if e = bcrypt.CompareHashAndPassword([]byte(values["ADMIN_PASSWORD_HASH"]), []byte(in.Password)); e != nil {
		t.Fatal("incorrect password hash")
	}
	if values["ADMIN_USERNAME"] != in.Username || values["PUBLIC_URL"] != "https://panel.example.org:9443" || values["INSECURE_COOKIE"] != "false" || values["API_HOST_PORT"] != "0" {
		t.Fatal("incorrect public origin or insecure defaults")
	}
	for _, key := range []string{"ENCRYPTION_KEY", "SESSION_KEY", "SERVICE_TOKEN"} {
		b, e := base64.StdEncoding.DecodeString(values[key])
		if e != nil || len(b) != 32 {
			t.Fatal("invalid secret", key)
		}
	}
	b, e := hex.DecodeString(values["POSTGRES_PASSWORD"])
	if e != nil || len(b) != 32 {
		t.Fatal("invalid postgres password")
	}
	if values["SESSION_KEY"] == values["SERVICE_TOKEN"] {
		t.Fatal("shared service/session key")
	}
	if PublicURL(in.Domain, 443) != "https://panel.example.org" {
		t.Fatal("default HTTPS port must not break Origin matching")
	}
}
func TestRejectsInputThatCouldChangeConfigOrCaddyDirectives(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Input)
	}{
		{"username injection", func(i *Input) { i.Username = "admin\nINSECURE_COOKIE=true" }},
		{"short password", func(i *Input) { i.Password = "short" }},
		{"bcrypt truncation", func(i *Input) { i.Password = strings.Repeat("a", 73) }},
		{"ACME port", func(i *Input) { i.Port = 80 }},
		{"negative port", func(i *Input) { i.Port = -1 }},
		{"oversize port", func(i *Input) { i.Port = 65536 }},
		{"domain scheme", func(i *Input) { i.Domain = "https://panel.example.org" }},
		{"domain IP", func(i *Input) { i.Domain = "192.0.2.1" }},
		{"domain directive", func(i *Input) { i.Domain = "panel.example.org\n{admin :2019}" }},
		{"domain trailing dot", func(i *Input) { i.Domain = "panel.example.org." }},
		{"email injection", func(i *Input) { i.Email = "ops@example.org\nadmin :2019" }},
		{"quoted email", func(i *Input) { i.Email = "\"x'\"@example.org" }},
		{"image command", func(i *Input) { i.RuntimeImage = "sha256:a;id" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validInput()
			tc.change(&in)
			if _, e := Generate(in); e == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
}
