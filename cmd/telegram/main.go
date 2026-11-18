package main

import (
	"awgpanel/internal/config"
	"awgpanel/internal/transport/telegram"
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	b := telegram.Bot{Token: os.Getenv("TELEGRAM_BOT_TOKEN"), API: config.Env("API_URL", "http://api:8080"), ServiceToken: os.Getenv("SERVICE_TOKEN"), OffsetFile: config.Env("TELEGRAM_OFFSET_FILE", "/data/telegram.offset")}
	if b.Token == "" || len(b.ServiceToken) < 32 {
		slog.Error("Telegram token and service credential required")
		os.Exit(1)
	}
	if e := b.Run(ctx); e != nil {
		slog.Error("Telegram stopped", "error", e)
		os.Exit(1)
	}
}
