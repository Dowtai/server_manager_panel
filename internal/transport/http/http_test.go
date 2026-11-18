package httptransport

import (
	"awgpanel/internal/application"
	"awgpanel/internal/domain"
	"awgpanel/internal/secure"
	"awgpanel/internal/testutil"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthenticationCSRFAndAdapterIsolation(t *testing.T) {
	v, _ := secure.New(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	repo := testutil.New()
	_ = repo.Update(context.Background(), func(s *domain.State) error {
		s.Users["user"] = domain.User{ID: "user", Name: "Authorized"}
		s.Identities["id"] = domain.Identity{ID: "id", UserID: "user", Provider: "telegram", ExternalID: "123"}
		return nil
	})
	svc := &application.Service{Repo: repo, Vault: v}
	hash, _ := bcrypt.GenerateFromPassword([]byte("test-password-123"), bcrypt.MinCost)
	serviceToken := strings.Repeat("s", 32)
	handler, e := New(svc, Config{AdminUsername: "operator", AdminHash: string(hash), ServiceToken: serviceToken, SessionKey: strings.Repeat("k", 32), PublicURL: "http://localhost:8080", InsecureCookie: true, WebDir: t.TempDir()})
	if e != nil {
		t.Fatal(e)
	}
	call := func(method, path, body string, cookie *http.Cookie, csrf, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("X-Telegram-ID", "123")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := call("GET", "/api/admin/state", "", nil, "", ""); w.Code != 401 {
		t.Fatal("unauthenticated admin access", w.Code)
	}
	if w := call("GET", "/api/service/me", "", nil, "", ""); w.Code != 401 {
		t.Fatal("spoofed Telegram identity accepted")
	}
	if w := call("GET", "/api/service/me", "", nil, "", serviceToken); w.Code != 200 {
		t.Fatal("authenticated adapter denied", w.Body.String())
	}
	for _, body := range []string{`{"username":"admin","password":"test-password-123"}`, `{"username":"operator","password":"wrong-password"}`, `{"password":"test-password-123"}`} {
		if w := call("POST", "/api/login", body, nil, "", ""); w.Code != 401 {
			t.Fatal("username/password mismatch accepted", w.Code)
		}
	}
	login := call("POST", "/api/login", `{"username":"operator","password":"test-password-123"}`, nil, "", "")
	if login.Code != 200 {
		t.Fatal(login.Body.String())
	}
	var token struct {
		CSRF string `json:"csrf"`
	}
	_ = json.Unmarshal(login.Body.Bytes(), &token)
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("insecure session cookie")
	}
	command := `{"action":"save_pool","pool":{"name":"Personal"}}`
	if w := call("POST", "/api/admin/commands", command, cookies[0], "", ""); w.Code != 403 {
		t.Fatal("missing CSRF allowed")
	}
	if w := call("POST", "/api/admin/commands", command, cookies[0], token.CSRF, ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if len(repo.State.Pools) != 1 {
		t.Fatal("command not saved")
	}
	if w := call("POST", "/api/admin/commands", command, nil, "", serviceToken); w.Code != 401 {
		t.Fatal("adapter token allowed admin operation")
	}
}
