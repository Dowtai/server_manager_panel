package application

import (
	"awgpanel/internal/domain"
	"awgpanel/internal/secure"
	"awgpanel/internal/testutil"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Service, *testutil.Memory, string, string, string) {
	t.Helper()
	r := testutil.New()
	v, e := secure.New(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if e != nil {
		t.Fatal(e)
	}
	svc := &Service{Repo: r, Vault: v}
	res, e := svc.Execute(context.Background(), "admin", Command{Action: "save_instance", Instance: domain.Instance{Name: "Personal"}, Endpoint: domain.Endpoint{Host: "vpn.example"}})
	if e != nil {
		t.Fatal(e)
	}
	i := res.(map[string]any)["id"].(string)
	u := domain.ID()
	g := domain.ID()
	dep := domain.ID()
	server := domain.ID()
	_ = r.Update(context.Background(), func(s *domain.State) error {
		s.Users[u] = domain.User{ID: u, Name: "User"}
		s.Grants[g] = domain.Grant{ID: g, UserID: u, InstanceID: i, Enabled: true, Limit: 1}
		s.Identities["tg"] = domain.Identity{ID: "tg", UserID: u, Provider: "telegram", ExternalID: "1234567890123"}
		s.Deployments[dep] = domain.Deployment{ID: dep, InstanceID: i, ServerID: server, DesiredRevision: 1, AppliedRevision: 1, VerifiedRevision: 1, Status: "ready"}
		for k, ep := range s.Endpoints {
			ep.DNSMatches = true
			ep.CheckedAt = time.Now()
			ep.TargetServerID = server
			s.Endpoints[k] = ep
		}
		return nil
	})
	return svc, r, i, u, g
}
func markReady(r *testutil.Memory) {
	_ = r.Update(context.Background(), func(s *domain.State) error {
		for k, d := range s.Deployments {
			d.Status = "ready"
			d.AppliedRevision = s.Instances[d.InstanceID].Revision
			d.VerifiedRevision = d.AppliedRevision
			s.Deployments[k] = d
		}
		return nil
	})
}
func TestDeviceIdempotencyPermissionsAndLimit(t *testing.T) {
	svc, r, i, u, g := fixture(t)
	ctx := context.Background()
	d, e := svc.CreateDevice(ctx, "test", "", u, i, "Phone", "request-1")
	if e != nil {
		t.Fatal(e)
	}
	again, e := svc.CreateDevice(ctx, "test", "", u, i, "Phone", "request-1")
	if e != nil || d.ID != again.ID {
		t.Fatal("retry created a duplicate or failed", e)
	}
	if _, e = svc.Profile(ctx, "test", "1234567890123", d.ID); !errors.Is(e, ErrPending) {
		t.Fatal("profile issued before sync")
	}
	markReady(r)
	if _, e = svc.CreateDevice(ctx, "test", "", u, i, "Laptop", "request-2"); e == nil {
		t.Fatal("device quota bypassed")
	}
	if _, e = svc.Profile(ctx, "test", "999999", d.ID); !errors.Is(e, ErrForbidden) {
		t.Fatal("cross-user download allowed")
	}
	url, e := svc.Profile(ctx, "test", "1234567890123", d.ID)
	if e != nil || !strings.HasPrefix(url, "vpn://") {
		t.Fatal("own profile unavailable", e)
	}
	_ = r.Update(ctx, func(s *domain.State) error {
		grant := s.Grants[g]
		grant.Enabled = false
		s.Grants[g] = grant
		return nil
	})
	if _, e = svc.Profile(ctx, "test", "1234567890123", d.ID); e != nil {
		t.Fatal("removing creation grant implicitly revoked existing device", e)
	}
	if e = svc.RevokeOwn(ctx, "1234567890123", d.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = svc.Profile(ctx, "test", "1234567890123", d.ID); !errors.Is(e, ErrForbidden) {
		t.Fatal("revoked profile served")
	}
}
func TestUnlimitedGrantAndSecretRedaction(t *testing.T) {
	svc, r, i, u, g := fixture(t)
	ctx := context.Background()
	_ = r.Update(ctx, func(s *domain.State) error { grant := s.Grants[g]; grant.Limit = 0; s.Grants[g] = grant; return nil })
	for n := range 8 {
		markReady(r)
		if _, e := svc.CreateDevice(ctx, "test", "", u, i, fmt.Sprint(n), fmt.Sprintf("request-%d", n)); e != nil {
			t.Fatal("unlimited grant rejected", e)
		}
	}
	v, e := svc.Snapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(v)
	for _, key := range []string{"private_key", "header_key", "probe_private_key", "probe_psk", "\"psk\""} {
		if strings.Contains(string(b), key) {
			t.Fatal("snapshot contains secret", key)
		}
	}
	if len(v.Devices) != 8 {
		t.Fatal("device count")
	}
}
func TestConcurrentIdempotentDeviceRequests(t *testing.T) {
	svc, r, i, u, _ := fixture(t)
	var wg sync.WaitGroup
	ids := make(chan string, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, e := svc.CreateDevice(context.Background(), "test", "", u, i, "Phone", "same-request")
			if e != nil {
				t.Error(e)
				return
			}
			ids <- d.ID
		}()
	}
	wg.Wait()
	close(ids)
	first := ""
	for id := range ids {
		if first == "" {
			first = id
		}
		if id != first {
			t.Fatal("non-idempotent concurrent requests")
		}
	}
	if len(r.State.Devices) != 1 {
		t.Fatal("duplicates")
	}
}
func TestPlacementsUnionAndPreviewRollback(t *testing.T) {
	svc, r, i, _, _ := fixture(t)
	ctx := context.Background()
	pool := domain.ID()
	server := domain.ID()
	_ = r.Update(ctx, func(s *domain.State) error {
		s.Pools[pool] = domain.Pool{ID: pool}
		s.Servers[server] = domain.Server{ID: server, PoolID: pool}
		s.Deployments = map[string]domain.Deployment{}
		return nil
	})
	cmd := Command{Action: "save_placement", Placement: domain.Placement{InstanceID: i, PoolID: pool, Mode: "all_servers"}, Preview: true}
	if _, e := svc.Execute(ctx, "admin", cmd); e != nil {
		t.Fatal(e)
	}
	if len(r.State.Placements) != 0 || len(r.State.Deployments) != 0 {
		t.Fatal("preview persisted")
	}
	cmd.Preview = false
	if _, e := svc.Execute(ctx, "admin", cmd); e != nil {
		t.Fatal(e)
	}
	cmd.Placement.Mode = "selected_servers"
	cmd.Placement.ServerIDs = []string{server}
	if _, e := svc.Execute(ctx, "admin", cmd); e != nil {
		t.Fatal(e)
	}
	if len(r.State.Deployments) != 1 {
		t.Fatal("overlapping placements duplicated deployments")
	}
	_ = r.Update(ctx, func(s *domain.State) error {
		v := domain.Server{ID: domain.ID(), PoolID: pool}
		s.Servers[v.ID] = v
		_, e := Reconcile(s, "test")
		return e
	})
	if len(r.State.Deployments) != 2 {
		t.Fatal("all_servers did not expand")
	}
}

func TestRetireEndpointRequiresConfirmedRevocations(t *testing.T) {
	svc, r, i, u, _ := fixture(t)
	ctx := context.Background()
	var endpoint string
	_ = r.Update(ctx, func(s *domain.State) error {
		pool := domain.ID()
		s.Pools[pool] = domain.Pool{ID: pool}
		for _, d := range s.Deployments {
			s.Servers[d.ServerID] = domain.Server{ID: d.ServerID, PoolID: pool}
		}
		p := domain.Placement{ID: domain.ID(), InstanceID: i, PoolID: pool, Mode: "all_servers"}
		s.Placements[p.ID] = p
		for id := range s.Endpoints {
			endpoint = id
		}
		return nil
	})
	d, e := svc.CreateDevice(ctx, "test", "", u, i, "Phone", "request-retire")
	if e != nil {
		t.Fatal(e)
	}
	cmd := Command{Action: "retire_endpoint", ID: endpoint, Confirm: true}
	if _, e = svc.Execute(ctx, "admin", cmd); e == nil {
		t.Fatal("retired endpoint with active device")
	}
	if _, e = svc.Execute(ctx, "admin", Command{Action: "revoke_device", ID: d.ID}); e != nil {
		t.Fatal(e)
	}
	if _, e = svc.Execute(ctx, "admin", cmd); e == nil {
		t.Fatal("retired before remote revocation confirmed")
	}
	markReady(r)
	if _, e = svc.Execute(ctx, "admin", cmd); e != nil {
		t.Fatal(e)
	}
	if !r.State.Instances[i].Disabled || r.State.Endpoints[endpoint].TargetServerID != "" {
		t.Fatal("endpoint not retired")
	}
}
