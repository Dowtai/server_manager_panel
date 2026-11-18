package config

import (
	"awgpanel/internal/application"
	"awgpanel/internal/secure"
	"awgpanel/internal/storage"
	"context"
	"fmt"
	"os"
)

func Env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func Service(ctx context.Context) (*application.Service, *storage.Store, error) {
	v, e := secure.New(os.Getenv("ENCRYPTION_KEY"))
	if e != nil {
		return nil, nil, e
	}
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return nil, nil, fmt.Errorf("DATABASE_URL required")
	}
	s, e := storage.Open(ctx, url)
	if e != nil {
		return nil, nil, e
	}
	return &application.Service{Repo: s, Vault: v}, s, nil
}
