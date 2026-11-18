package main

import (
	"awgpanel/internal/config"
	"awgpanel/internal/storage"
	transport "awgpanel/internal/transport/http"
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e := storage.Migrate(ctx, os.Getenv("DATABASE_URL")); e != nil {
		slog.Error("migration failed", "error", e)
		os.Exit(1)
	}
	svc, store, e := config.Service(ctx)
	if e != nil {
		slog.Error("startup failed", "error", e)
		os.Exit(1)
	}
	defer store.Close()
	handler, e := transport.New(svc, transport.Config{AdminUsername: config.Env("ADMIN_USERNAME", "admin"), AdminHash: os.Getenv("ADMIN_PASSWORD_HASH"), ServiceToken: os.Getenv("SERVICE_TOKEN"), SessionKey: os.Getenv("SESSION_KEY"), PublicURL: config.Env("PUBLIC_URL", "http://localhost:8080"), WebDir: config.Env("WEB_DIR", "web/dist"), InsecureCookie: os.Getenv("INSECURE_COOKIE") == "true"})
	if e != nil {
		slog.Error("configuration failed", "error", e)
		os.Exit(1)
	}
	server := &http.Server{Addr: config.Env("LISTEN_ADDR", ":8080"), Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	slog.Info("API listening", "address", server.Addr)
	if e = server.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		slog.Error("server failed", "error", e)
		os.Exit(1)
	}
}
