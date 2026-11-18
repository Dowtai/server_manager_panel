package httptransport

import (
	"awgpanel/internal/application"
	"awgpanel/internal/domain"
	"awgpanel/internal/installcfg"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	AdminUsername, AdminHash, ServiceToken, SessionKey, PublicURL, WebDir string
	InsecureCookie                                                        bool
}
type Handler struct {
	Service  *application.Service
	Config   Config
	mu       sync.Mutex
	failures map[string][]time.Time
}

func New(s *application.Service, c Config) (http.Handler, error) {
	if c.AdminUsername == "" {
		c.AdminUsername = "admin"
	}
	if !installcfg.ValidUsername(c.AdminUsername) {
		return nil, fmt.Errorf("invalid ADMIN_USERNAME")
	}
	if _, e := bcrypt.Cost([]byte(c.AdminHash)); e != nil {
		return nil, fmt.Errorf("ADMIN_PASSWORD_HASH must be bcrypt")
	}
	if len(c.ServiceToken) < 32 || len(c.SessionKey) < 32 || c.ServiceToken == c.SessionKey {
		return nil, fmt.Errorf("distinct SERVICE_TOKEN and SESSION_KEY of at least 32 chars required")
	}
	u, e := url.Parse(c.PublicURL)
	if e != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("valid PUBLIC_URL required")
	}
	if u.Scheme != "https" && !c.InsecureCookie {
		return nil, fmt.Errorf("HTTPS required unless INSECURE_COOKIE=true for localhost development")
	}
	h := &Handler{Service: s, Config: c, failures: map[string][]time.Time{}}
	r := chi.NewRouter()
	r.Use(h.headers)
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if e := s.Repo.View(ctx, func(_ *domain.State) error { return nil }); e != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		jsonOut(w, 200, map[string]bool{"ok": true})
	})
	r.Post("/api/login", h.login)
	r.Get("/api/session", h.session)
	r.Group(func(r chi.Router) {
		r.Use(h.admin)
		r.Post("/api/logout", func(w http.ResponseWriter, r *http.Request) {
			h.cookie(w, "", -1)
			jsonOut(w, 200, map[string]bool{"ok": true})
		})
		r.Get("/api/admin/state", func(w http.ResponseWriter, r *http.Request) { v, e := s.Snapshot(r.Context()); respond(w, v, e) })
		r.Post("/api/admin/commands", func(w http.ResponseWriter, r *http.Request) {
			var c application.Command
			if !decode(w, r, &c) {
				return
			}
			v, e := s.Execute(r.Context(), "admin", c)
			respond(w, v, e)
		})
		r.Post("/api/admin/devices", func(w http.ResponseWriter, r *http.Request) {
			var v deviceRequest
			if !decode(w, r, &v) {
				return
			}
			d, e := s.CreateDevice(r.Context(), "admin", "", v.UserID, v.InstanceID, v.Name, v.RequestID)
			respond(w, d, e)
		})
		r.Get("/api/admin/devices/{id}/profile", func(w http.ResponseWriter, r *http.Request) {
			v, e := s.Profile(r.Context(), "admin", "", chi.URLParam(r, "id"))
			respond(w, map[string]string{"url": v}, e)
		})
		r.Post("/api/admin/endpoints/{id}/check", func(w http.ResponseWriter, r *http.Request) {
			var v struct {
				Target string `json:"target_server_id"`
			}
			if !decode(w, r, &v) {
				return
			}
			ep, e := s.CheckDNS(r.Context(), "admin", chi.URLParam(r, "id"), v.Target)
			respond(w, ep, e)
		})
	})
	r.Route("/api/service", func(r chi.Router) {
		r.Use(h.service)
		r.Get("/me", func(w http.ResponseWriter, r *http.Request) {
			v, e := s.UserView(r.Context(), r.Header.Get("X-Telegram-ID"))
			respond(w, v, e)
		})
		r.Post("/devices", func(w http.ResponseWriter, r *http.Request) {
			var v deviceRequest
			if !decode(w, r, &v) {
				return
			}
			tg := r.Header.Get("X-Telegram-ID")
			d, e := s.CreateDevice(r.Context(), "telegram:"+tg, tg, "", v.InstanceID, v.Name, v.RequestID)
			respond(w, d, e)
		})
		r.Get("/devices/{id}/profile", func(w http.ResponseWriter, r *http.Request) {
			tg := r.Header.Get("X-Telegram-ID")
			v, e := s.Profile(r.Context(), "telegram:"+tg, tg, chi.URLParam(r, "id"))
			respond(w, map[string]string{"url": v}, e)
		})
		r.Delete("/devices/{id}", func(w http.ResponseWriter, r *http.Request) {
			e := s.RevokeOwn(r.Context(), r.Header.Get("X-Telegram-ID"), chi.URLParam(r, "id"))
			respond(w, map[string]bool{"ok": e == nil}, e)
		})
	})
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		clean := filepath.Clean("/" + r.URL.Path)
		path := filepath.Join(c.WebDir, clean)
		if info, e := os.Stat(path); e == nil && !info.IsDir() {
			http.ServeFile(w, r, path)
			return
		}
		http.ServeFile(w, r, filepath.Join(c.WebDir, "index.html"))
	})
	return r, nil
}

type deviceRequest struct {
	UserID     string `json:"user_id"`
	InstanceID string `json:"instance_id"`
	Name       string `json:"name"`
	RequestID  string `json:"request_id"`
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		jsonOut(w, 400, map[string]string{"error": "invalid JSON request"})
		return false
	}
	if e := d.Decode(new(any)); e != io.EOF {
		jsonOut(w, 400, map[string]string{"error": "one JSON object required"})
		return false
	}
	return true
}
func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func respond(w http.ResponseWriter, v any, e error) {
	if e == nil {
		jsonOut(w, 200, v)
		return
	}
	status := 400
	message := e.Error()
	switch {
	case errors.Is(e, application.ErrForbidden):
		status = 403
	case errors.Is(e, application.ErrNotFound):
		status = 404
	case errors.Is(e, application.ErrPending):
		status = 409
	default:
		if strings.Contains(message, "persist ") || strings.Contains(message, "conn") || strings.Contains(message, "SQL") || strings.Contains(message, "encrypted") {
			slog.Error("request failed", "error", e)
			message = "internal operation failed"
			status = 500
		}
	}
	jsonOut(w, status, map[string]string{"error": message})
}
func (h *Handler) mac(s string) string {
	m := hmac.New(sha256.New, []byte(h.Config.SessionKey))
	_, _ = m.Write([]byte(s))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
func (h *Handler) token(r *http.Request) (string, bool) {
	c, e := r.Cookie("awgp_session")
	if e != nil {
		return "", false
	}
	p := strings.Split(c.Value, ".")
	if len(p) != 3 {
		return "", false
	}
	exp, e := strconv.ParseInt(p[0], 10, 64)
	return c.Value, e == nil && exp > time.Now().Unix() && hmac.Equal([]byte(p[2]), []byte(h.mac(p[0]+"."+p[1])))
}
func (h *Handler) cookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: "awgp_session", Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: !h.Config.InsecureCookie, SameSite: http.SameSiteStrictMode})
}
func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	if o := r.Header.Get("Origin"); o != "" && o != h.Config.PublicURL {
		jsonOut(w, 403, map[string]string{"error": "invalid origin"})
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	h.mu.Lock()
	now := time.Now()
	attempts := h.failures[ip][:0]
	for _, t := range h.failures[ip] {
		if now.Sub(t) < time.Minute {
			attempts = append(attempts, t)
		}
	}
	if len(attempts) >= 5 {
		h.mu.Unlock()
		jsonOut(w, 429, map[string]string{"error": "too many attempts; retry in a minute"})
		return
	}
	h.failures[ip] = append(attempts, now)
	h.mu.Unlock()
	var v struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &v) {
		return
	}
	passwordErr := bcrypt.CompareHashAndPassword([]byte(h.Config.AdminHash), []byte(v.Password))
	if passwordErr != nil || subtle.ConstantTimeCompare([]byte(v.Username), []byte(h.Config.AdminUsername)) != 1 {
		jsonOut(w, 401, map[string]string{"error": "invalid credentials"})
		return
	}
	nonce := make([]byte, 24)
	if _, e := rand.Read(nonce); e != nil {
		jsonOut(w, 500, map[string]string{"error": "random source failed"})
		return
	}
	part := strconv.FormatInt(time.Now().Add(12*time.Hour).Unix(), 10) + "." + base64.RawURLEncoding.EncodeToString(nonce)
	token := part + "." + h.mac(part)
	h.cookie(w, token, 43200)
	jsonOut(w, 200, map[string]string{"csrf": h.mac("csrf:" + token)})
}
func (h *Handler) session(w http.ResponseWriter, r *http.Request) {
	token, ok := h.token(r)
	if !ok {
		jsonOut(w, 401, map[string]string{"error": "login required"})
		return
	}
	jsonOut(w, 200, map[string]string{"csrf": h.mac("csrf:" + token)})
}
func (h *Handler) admin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := h.token(r)
		if !ok {
			jsonOut(w, 401, map[string]string{"error": "login required"})
			return
		}
		if r.Method != "GET" {
			expected := h.mac("csrf:" + token)
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(expected)) != 1 || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != h.Config.PublicURL) {
				jsonOut(w, 403, map[string]string{"error": "invalid CSRF token or origin"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
func (h *Handler) service(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "Bearer " + h.Config.ServiceToken
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(expected)) != 1 {
			jsonOut(w, 401, map[string]string{"error": "invalid service credential"})
			return
		}
		id, e := strconv.ParseInt(r.Header.Get("X-Telegram-ID"), 10, 64)
		if e != nil || id <= 0 {
			jsonOut(w, 400, map[string]string{"error": "Telegram user identity required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (h *Handler) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		defer func() {
			if recover() != nil {
				slog.Error("HTTP handler panic")
				jsonOut(w, 500, map[string]string{"error": "internal server error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}
