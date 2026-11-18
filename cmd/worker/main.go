package main

import (
	"awgpanel/internal/application"
	"awgpanel/internal/config"
	"awgpanel/internal/deployment"
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	svc, store, e := config.Service(ctx)
	if e != nil {
		slog.Error("startup failed", "error", e)
		os.Exit(1)
	}
	defer store.Close()
	runner, e := deployment.NewSSHWithArchive(os.Getenv("AWG_RUNTIME_IMAGE"), os.Getenv("AWG_RUNTIME_ARCHIVE"))
	if e != nil {
		slog.Error("runtime configuration failed", "error", e)
		os.Exit(1)
	}
	worker := application.Worker{Store: store, Service: svc, Runner: runner}
	if e = worker.Run(ctx); e != nil {
		slog.Error("worker failed", "error", e)
		os.Exit(1)
	}
}
