package deployment

import (
	"awgpanel/internal/awg"
	"awgpanel/internal/domain"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGeneratedScriptsParseAndKeepIsolation(t *testing.T) {
	runner, e := NewSSH("registry.example/awg@sha256:" + strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	s := Snapshot{Deployment: domain.Deployment{ID: domain.ID()}, Server: domain.Server{ID: domain.ID(), SSHPort: 22}, Pool: domain.Pool{SSHSources: []string{"192.0.2.0/24"}}, Instance: domain.Instance{Subnet: "10.77.1.0/24", Port: 54321, PrivateKey: awg.RandomKey(), PublicKey: awg.RandomKey(), ProbePublicKey: awg.RandomKey(), ProbePSK: awg.RandomKey(), MTU: 1376, Params: awg.Parameters()}}
	for _, script := range []string{runner.applyScript(s), removeScript(s), firewallScript(s)} {
		if strings.Contains(script, "%!") {
			t.Fatal("broken template formatting")
		}
		cmd := exec.CommandContext(context.Background(), "bash", "-n")
		cmd.Stdin = strings.NewReader(script)
		if output, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("invalid shell script: %s", output)
		}
		if strings.Contains(script, "--privileged") || strings.Contains(script, "--network host") {
			t.Fatal("unnecessary container privilege")
		}
		if strings.Contains(script, "iptables -F INPUT") {
			t.Fatal("flushing foreign firewall")
		}
	}
	if !strings.Contains(runner.applyScript(s), "/validate.sh") || !strings.Contains(runner.applyScript(s), "/apply.sh") {
		t.Fatal("missing staged validation or runtime application")
	}
}

func TestLocalArchiveRequiresImmutableImageID(t *testing.T) {
	file := t.TempDir() + "/runtime.tar"
	if e := os.WriteFile(file, []byte("docker-save archive"), 0600); e != nil {
		t.Fatal(e)
	}
	id := "sha256:" + strings.Repeat("a", 64)
	r, e := NewSSHWithArchive(id, file)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(r.imageCommand(), "pull") {
		t.Fatal("archive mode unexpectedly depends on a registry")
	}
	if _, e = NewSSH(id); e == nil {
		t.Fatal("local ID without archive accepted")
	}
	if _, e = NewSSHWithArchive("image:latest", file); e == nil {
		t.Fatal("mutable archive identity accepted")
	}
	if _, e = NewSSHWithArchive(id, t.TempDir()); e == nil {
		t.Fatal("directory accepted as archive")
	}
}

func TestArchiveStreamUsesPinnedSSHAndSkipsLoadedImage(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Skipf("local sockets unavailable: %v", e)
	}
	defer listener.Close()
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := ssh.NewSignerFromKey(private)
	if e != nil {
		t.Fatal(e)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if string(password) != "test-ssh-password" {
			return nil, fmt.Errorf("denied")
		}
		return nil, nil
	}}
	cfg.AddHostKey(signer)
	var mu sync.Mutex
	loaded := false
	loads := 0
	var received []byte
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				server, channels, requests, e := ssh.NewServerConn(conn, cfg)
				if e != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					channel, requests, e := incoming.Accept()
					if e != nil {
						return
					}
					for req := range requests {
						if req.Type != "exec" {
							_ = req.Reply(false, nil)
							continue
						}
						var payload struct{ Command string }
						if e = ssh.Unmarshal(req.Payload, &payload); e != nil {
							return
						}
						_ = req.Reply(true, nil)
						data, _ := io.ReadAll(channel)
						code := uint32(0)
						mu.Lock()
						if strings.Contains(payload.Command, "docker load") {
							received = append([]byte(nil), data...)
							loaded = true
							loads++
						} else if strings.Contains(string(data), "docker image inspect") && !strings.Contains(string(data), "systemctl") && !loaded {
							code = 1
						}
						mu.Unlock()
						_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
						channel.Close()
					}
				}
			}()
		}
	}()
	data := []byte{0, 1, 2, 255, '\n', '\r', 0, '$', '\'', 'x'}
	path := t.TempDir() + "/runtime.tar"
	if e = os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	r, e := NewSSHWithArchive("sha256:"+strings.Repeat("a", 64), path)
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().(*net.TCPAddr)
	s := domain.Server{Host: "127.0.0.1", SSHPort: address.Port, SSHUser: "root", AuthType: "password", Credential: "test-ssh-password", HostKey: ssh.FingerprintSHA256(signer.PublicKey())}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for range 2 {
		if e = r.deliverArchive(ctx, s); e != nil {
			t.Fatal(e)
		}
	}
	mu.Lock()
	if loads != 1 || !bytes.Equal(received, data) {
		t.Error("archive was changed or redundantly reloaded")
	}
	mu.Unlock()
	s.HostKey = "SHA256:" + strings.Repeat("a", 43)
	if e = r.deliverArchive(ctx, s); e == nil {
		t.Fatal("incorrect pinned host key accepted")
	}
}
