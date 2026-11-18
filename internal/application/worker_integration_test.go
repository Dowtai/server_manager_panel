package application

import (
	"awgpanel/internal/deployment"
	"awgpanel/internal/domain"
	"awgpanel/internal/secure"
	"awgpanel/internal/storage"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeRunner struct {
	mu      sync.Mutex
	applied []deployment.Snapshot
	fail    bool
	hook    func()
}

func (f *fakeRunner) Apply(_ context.Context, s deployment.Snapshot) error {
	f.mu.Lock()
	f.applied = append(f.applied, s)
	hook := f.hook
	f.hook = nil
	fail := f.fail
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	if fail {
		return errors.New("VPS unreachable")
	}
	return nil
}
func (f *fakeRunner) Remove(context.Context, deployment.Snapshot) error { return nil }
func (f *fakeRunner) Probe(context.Context, deployment.Snapshot) error  { return nil }
func TestPostgresDurabilityAndWorkerRecovery(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set TEST_DATABASE_URL to a dedicated empty PostgreSQL database")
	}
	ctx := context.Background()
	if e := storage.Migrate(ctx, url); e != nil {
		t.Fatal(e)
	}
	st, e := storage.Open(ctx, url)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	var populated bool
	_ = st.View(ctx, func(s *domain.State) error { populated = len(s.Instances) > 0 || len(s.Pools) > 0; return nil })
	if populated {
		t.Fatal("integration test requires an empty database")
	}
	defer func() {
		_, _ = st.Pool.Exec(ctx, "TRUNCATE audit,operations,devices,grants,identities,users,deployments,placements,endpoints,instances,servers,pools")
	}()
	v, _ := secure.New(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	svc := &Service{Repo: st, Vault: v}
	exec := func(c Command) string {
		t.Helper()
		res, e := svc.Execute(ctx, "integration", c)
		if e != nil {
			t.Fatal(e)
		}
		return res.(map[string]any)["id"].(string)
	}
	pool := exec(Command{Action: "save_pool", Pool: domain.Pool{Name: "Pool"}})
	server := exec(Command{Action: "save_server", Server: domain.Server{Name: "VPS", PoolID: pool, Host: "127.0.0.1", PublicIP: "127.0.0.1", SSHPort: 22, SSHUser: "root", AuthType: "password", Credential: "test-secret", HostKey: "SHA256:" + strings.Repeat("a", 43)}})
	instance := exec(Command{Action: "save_instance", Instance: domain.Instance{Name: "Personal"}, Endpoint: domain.Endpoint{Host: "127.0.0.1"}})
	exec(Command{Action: "save_placement", Placement: domain.Placement{InstanceID: instance, PoolID: pool, Mode: "all_servers"}})
	user := exec(Command{Action: "save_user", User: domain.User{Name: "User"}})
	grant := exec(Command{Action: "save_grant", Grant: domain.Grant{UserID: user, InstanceID: instance, Enabled: true, Limit: 1}})
	exec(Command{Action: "save_identity", Identity: domain.Identity{UserID: user, Provider: "telegram", ExternalID: "123"}})
	runner := &fakeRunner{}
	worker := Worker{Store: st, Service: svc, Runner: runner}
	if e = worker.Once(ctx); e != nil {
		t.Fatal(e)
	}
	var endpoint string
	var dep string
	_ = st.View(ctx, func(s *domain.State) error {
		for id := range s.Endpoints {
			endpoint = id
		}
		for id := range s.Deployments {
			dep = id
		}
		return nil
	})
	if _, e = svc.CheckDNS(ctx, "integration", endpoint, server); e != nil {
		t.Fatal(e)
	}
	d, e := svc.CreateDevice(ctx, "test", "123", "", instance, "Phone", "request-integration-1")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = svc.Profile(ctx, "test", "123", d.ID); !errors.Is(e, ErrPending) {
		t.Fatal("issued before current revision")
	}
	// A revision arriving during SSH must force a second synchronization.
	runner.hook = func() {
		if e := st.Update(ctx, func(s *domain.State) error { Bump(s, instance, "during-apply"); return nil }); e != nil {
			t.Error(e)
		}
	}
	if e = worker.Once(ctx); e != nil {
		t.Fatal(e)
	}
	_ = st.View(ctx, func(s *domain.State) error {
		if s.Deployments[dep].Status == "ready" {
			t.Error("stale revision marked ready")
		}
		return nil
	})
	if e = worker.Once(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = svc.Profile(ctx, "test", "123", d.ID); e != nil {
		t.Fatal("profile after sync", e)
	}
	// The DB lock, not an in-process mutex, serializes device limits across services.
	otherStore, e := storage.Open(ctx, url)
	if e != nil {
		t.Fatal(e)
	}
	defer otherStore.Close()
	otherService := &Service{Repo: otherStore, Vault: v}
	var wg sync.WaitGroup
	for n := range 10 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := otherService.CreateDevice(ctx, "parallel", "123", "", instance, "Extra", "parallel-"+strings.Repeat("x", n+1))
			if err == nil {
				t.Error("quota bypass")
			}
		}(n)
	}
	wg.Wait()
	// An offline replica remains stale after revoke; retry applies the latest full configuration.
	runner.fail = true
	if e = svc.RevokeOwn(ctx, "123", d.ID); e != nil {
		t.Fatal(e)
	}
	if e = worker.Once(ctx); e != nil {
		t.Fatal(e)
	}
	_ = st.View(ctx, func(s *domain.State) error {
		if s.Deployments[dep].VerifiedRevision != 0 {
			t.Error("offline replica remains eligible")
		}
		if s.Grants[grant].Limit != 1 {
			t.Error("grant lost")
		}
		return nil
	})
	runner.fail = false
	// Simulate a crashed worker's persisted running operation with an expired lease.
	if e = st.Update(ctx, func(s *domain.State) error {
		for id, o := range s.Operations {
			if o.Status == "retry" {
				o.Status = "running"
				o.AvailableAt = time.Now().Add(-time.Hour)
				s.Operations[id] = o
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	restart := Worker{Store: otherStore, Service: otherService, Runner: runner}
	if e = restart.Once(ctx); e != nil {
		t.Fatal(e)
	}
	_ = st.View(ctx, func(s *domain.State) error {
		dd := s.Deployments[dep]
		if dd.AppliedRevision != s.Instances[instance].Revision || dd.Status != "ready" {
			t.Error("crash recovery did not converge")
		}
		return nil
	})
	last := runner.applied[len(runner.applied)-1]
	if len(last.Devices) != 0 {
		t.Fatal("revoked peer sent to VPS")
	}
	if last.Instance.PrivateKey == "" || last.Instance.ProbePrivateKey == "" {
		t.Fatal("runtime secrets not decrypted")
	}
	for _, snapshot := range runner.applied {
		for _, device := range snapshot.Devices {
			if device.PrivateKey != "" {
				t.Fatal("client private key passed to deployment runner")
			}
		}
	}
	// Idempotent retry of a delivered request does not create another peer.
	again, e := otherService.CreateDevice(ctx, "test", "123", "", instance, "Phone", "request-integration-1")
	if e != nil || again.ID != d.ID {
		t.Fatal("persistent idempotency lost", e)
	}
	// An older failed attempt must not suppress periodic checks after a later successful sync.
	if e = st.Update(ctx, func(s *domain.State) error {
		old := time.Now().Add(-time.Hour)
		o := domain.Operation{ID: domain.ID(), DeploymentID: dep, InstanceID: instance, Status: "failed", CreatedAt: old, UpdatedAt: old}
		s.Operations[o.ID] = o
		dd := s.Deployments[dep]
		dd.CheckedAt = old
		s.Deployments[dep] = dd
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = restart.Sweep(ctx); e != nil {
		t.Fatal(e)
	}
	_ = st.View(ctx, func(s *domain.State) error {
		queued := 0
		for _, o := range s.Operations {
			if o.DeploymentID == dep && o.Status == "queued" {
				queued++
			}
		}
		if queued != 1 {
			t.Error("old failure suppressed periodic convergence")
		}
		return nil
	})
}
