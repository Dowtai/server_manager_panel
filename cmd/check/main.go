package main

import (
	"awgpanel/internal/installcfg"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"os"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "install" {
		port, e := strconv.Atoi(os.Getenv("PANEL_PORT"))
		if e != nil {
			fmt.Fprintln(os.Stderr, "invalid panel port")
			os.Exit(1)
		}
		data, e := installcfg.Generate(installcfg.Input{Username: os.Getenv("ADMIN_USERNAME"), Password: os.Getenv("ADMIN_PASSWORD"), Domain: os.Getenv("PANEL_DOMAIN"), Port: port, Email: os.Getenv("ACME_EMAIL"), RuntimeImage: os.Getenv("AWG_RUNTIME_IMAGE")})
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		if _, e = os.Stdout.Write(data); e != nil {
			os.Exit(1)
		}
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "password" {
		password := os.Getenv("ADMIN_PASSWORD")
		if len(password) < 12 {
			fmt.Fprintln(os.Stderr, "set ADMIN_PASSWORD to at least 12 characters")
			os.Exit(1)
		}
		h, e := bcrypt.GenerateFromPassword([]byte(password), 12)
		if e != nil {
			panic(e)
		}
		fmt.Println(string(h))
		return
	}
	for _, key := range []string{"ENCRYPTION_KEY", "SESSION_KEY", "SERVICE_TOKEN"} {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			panic(e)
		}
		fmt.Printf("%s='%s'\n", key, strings.TrimSpace(base64.StdEncoding.EncodeToString(b)))
	}
}
