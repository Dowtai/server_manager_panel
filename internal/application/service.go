package application

import (
	"awgpanel/internal/awg"
	"awgpanel/internal/domain"
	"awgpanel/internal/secure"
	"awgpanel/internal/storage"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
)

var ErrForbidden = errors.New("access denied")
var ErrNotFound = errors.New("not found")
var ErrPending = errors.New("endpoint deployment is not verified at the current revision; retry profile retrieval after sync and VPN probe")
var errPreview = errors.New("preview")

type Service struct {
	Repo  storage.Repository
	Vault *secure.Vault
}
type Command struct {
	Action         string           `json:"action"`
	ID             string           `json:"id"`
	Confirm        bool             `json:"confirm"`
	Preview        bool             `json:"preview"`
	RevokeExisting bool             `json:"revoke_existing"`
	Pool           domain.Pool      `json:"pool"`
	Server         domain.Server    `json:"server"`
	Instance       domain.Instance  `json:"instance"`
	Endpoint       domain.Endpoint  `json:"endpoint"`
	Placement      domain.Placement `json:"placement"`
	User           domain.User      `json:"user"`
	Identity       domain.Identity  `json:"identity"`
	Grant          domain.Grant     `json:"grant"`
}
type Change struct {
	InstanceID string `json:"instance_id"`
	ServerID   string `json:"server_id"`
	Action     string `json:"action"`
}

func validName(n string) bool { return len(strings.TrimSpace(n)) > 0 && len(n) <= 120 }
func audit(s *domain.State, actor, action, id string) {
	v := domain.Audit{ID: domain.ID(), Actor: actor, Action: action, ObjectID: id, At: time.Now().UTC()}
	s.Audit[v.ID] = v
}
func queue(s *domain.State, d domain.Deployment, actor string) {
	for _, o := range s.Operations {
		if o.DeploymentID == d.ID && (o.Status == "queued" || o.Status == "running" || o.Status == "retry") {
			return
		}
	}
	now := time.Now().UTC()
	o := domain.Operation{ID: domain.ID(), DeploymentID: d.ID, InstanceID: d.InstanceID, Actor: actor, Status: "queued", Stage: "waiting", CreatedAt: now, UpdatedAt: now, AvailableAt: now}
	s.Operations[o.ID] = o
}
func Bump(s *domain.State, id, actor string) {
	i := s.Instances[id]
	i.Revision++
	s.Instances[id] = i
	for k, d := range s.Deployments {
		if d.InstanceID == id && !d.Remove {
			d.DesiredRevision = i.Revision
			d.Status = "syncing"
			d.VerifiedRevision = 0
			s.Deployments[k] = d
			queue(s, d, actor)
		}
	}
}
func Reconcile(s *domain.State, actor string) ([]Change, error) {
	changes := []Change{}
	for id, i := range s.Instances {
		targets := domain.Targets(s, id)
		for _, serverID := range targets {
			sv := s.Servers[serverID]
			for _, other := range s.Deployments {
				if other.ServerID == serverID && !other.Remove && other.InstanceID != id {
					oi := s.Instances[other.InstanceID]
					a := netip.MustParsePrefix(oi.Subnet)
					b := netip.MustParsePrefix(i.Subnet)
					if oi.Port == i.Port || a.Overlaps(b) {
						return nil, fmt.Errorf("port or subnet conflicts with instance %s on %s", oi.Name, sv.Name)
					}
				}
			}
			exists := false
			for k, d := range s.Deployments {
				if d.InstanceID == id && d.ServerID == serverID {
					exists = true
					if d.Remove {
						d.Remove = false
						d.Status = "syncing"
						d.DesiredRevision = i.Revision
						s.Deployments[k] = d
						queue(s, d, actor)
						changes = append(changes, Change{id, serverID, "create"})
					}
				}
			}
			if !exists {
				d := domain.Deployment{ID: domain.ID(), InstanceID: id, ServerID: serverID, DesiredRevision: i.Revision, Status: "syncing"}
				s.Deployments[d.ID] = d
				queue(s, d, actor)
				changes = append(changes, Change{id, serverID, "create"})
			}
		}
		for k, d := range s.Deployments {
			if d.InstanceID != id || d.Remove || slices.Contains(targets, d.ServerID) {
				continue
			}
			ep, _ := s.Endpoint(id)
			if ep.TargetServerID == d.ServerID {
				return nil, fmt.Errorf("switch and verify endpoint before removing its target deployment")
			}
			d.Remove = true
			d.Status = "removing"
			d.VerifiedRevision = 0
			s.Deployments[k] = d
			queue(s, d, actor)
			changes = append(changes, Change{id, d.ServerID, "remove"})
		}
	}
	return changes, nil
}
func (svc *Service) Execute(ctx context.Context, actor string, c Command) (any, error) {
	var result any
	err := svc.Repo.Update(ctx, func(s *domain.State) error {
		var objectID string
		switch c.Action {
		case "save_pool":
			p := c.Pool
			if !validName(p.Name) {
				return fmt.Errorf("pool name required")
			}
			for _, v := range p.SSHSources {
				if prefix, e := netip.ParsePrefix(v); e != nil || !prefix.Addr().Is4() {
					return fmt.Errorf("invalid SSH source CIDR")
				}
			}
			if p.ID == "" {
				p.ID = domain.ID()
			} else {
				if _, ok := s.Pools[p.ID]; !ok {
					return ErrNotFound
				}
			}
			s.Pools[p.ID] = p
			objectID = p.ID
		case "save_server":
			v := c.Server
			if !validName(v.Name) || !awg.ValidHost(v.Host) || v.SSHPort < 1 || v.SSHPort > 65535 || v.SSHUser != "root" {
				return fmt.Errorf("valid name, SSH host/port and root user required for Ubuntu MVP")
			}
			ip, e := netip.ParseAddr(v.PublicIP)
			if e != nil || !ip.Is4() {
				return fmt.Errorf("valid public IPv4 required")
			}
			if _, ok := s.Pools[v.PoolID]; !ok {
				return ErrNotFound
			}
			if !strings.HasPrefix(v.HostKey, "SHA256:") || len(v.HostKey) != 50 {
				return fmt.Errorf("pinned ED25519 SSH SHA256 host fingerprint required")
			}
			if v.AuthType != "password" && v.AuthType != "key" {
				return fmt.Errorf("auth_type must be password or key")
			}
			if v.ID == "" {
				v.ID = domain.ID()
				if v.Credential == "" {
					return fmt.Errorf("SSH credential required")
				}
			} else {
				old, ok := s.Servers[v.ID]
				if !ok {
					return ErrNotFound
				}
				for _, d := range s.Deployments {
					if d.ServerID == v.ID && (old.Host != v.Host || old.SSHPort != v.SSHPort || old.PublicIP != v.PublicIP) {
						return fmt.Errorf("remove deployments before changing server addresses")
					}
				}
				if v.Credential == "" {
					if old.AuthType != v.AuthType {
						return fmt.Errorf("new credential required for new auth_type")
					}
					v.Credential = old.Credential
				} else {
					v.Credential = svc.Vault.Seal(v.Credential, v.ID+":ssh")
				}
				s.Servers[v.ID] = v
				objectID = v.ID
				break
			}
			v.Credential = svc.Vault.Seal(v.Credential, v.ID+":ssh")
			s.Servers[v.ID] = v
			objectID = v.ID
		case "save_instance":
			i := c.Instance
			ep := c.Endpoint
			if !validName(i.Name) {
				return fmt.Errorf("instance name required")
			}
			if i.ID == "" {
				i.ID = domain.ID()
				i.Revision = 1
				i.Params = awg.Parameters()
				priv, pub, e := awg.KeyPair()
				if e != nil {
					return e
				}
				i.PrivateKey = svc.Vault.Seal(priv, i.ID+":private")
				i.PublicKey = pub
				probePriv, probePub, e := awg.KeyPair()
				if e != nil {
					return e
				}
				i.ProbePrivateKey = svc.Vault.Seal(probePriv, i.ID+":probe")
				i.ProbePublicKey = probePub
				i.ProbePSK = svc.Vault.Seal(awg.RandomKey(), i.ID+":probe_psk")
				i.Params.HeaderKey = svc.Vault.Seal(i.Params.HeaderKey, i.ID+":header")
				ep.ID = domain.ID()
				ep.InstanceID = i.ID
				ep.TargetServerID = ""
				ep.CheckedAt = time.Time{}
				ep.DNSMatches = false
				if i.MTU == 0 {
					i.MTU = 1376
				}
				if len(i.DNS) == 0 {
					i.DNS = []string{"1.1.1.1", "9.9.9.9"}
				}
				if len(i.AllowedIPs) == 0 {
					i.AllowedIPs = []string{"0.0.0.0/0"}
				}
				if i.Keepalive == 0 {
					i.Keepalive = 25
				}
				if i.Subnet == "" {
					for x := 1; x < 255; x++ {
						candidate := fmt.Sprintf("10.77.%d.0/24", x)
						used := false
						for _, other := range s.Instances {
							if other.Subnet == candidate {
								used = true
							}
						}
						if !used {
							i.Subnet = candidate
							break
						}
					}
				}
				if i.Port == 0 {
					start := int(time.Now().UnixNano() % 10000)
					for n := range 10000 {
						candidate := 50000 + (start+n)%10000
						used := false
						for _, other := range s.Instances {
							if other.Port == candidate {
								used = true
								break
							}
						}
						if !used {
							i.Port = candidate
							break
						}
					}
				}
			} else {
				old, ok := s.Instances[i.ID]
				if !ok {
					return ErrNotFound
				}
				prev, _ := s.Endpoint(i.ID)
				if ep.Host == "" {
					ep.Host = prev.Host
				}
				connectionChanged := old.Subnet != i.Subnet || old.Port != i.Port || old.MTU != i.MTU || !reflect.DeepEqual(old.DNS, i.DNS) || !reflect.DeepEqual(old.AllowedIPs, i.AllowedIPs) || old.Keepalive != i.Keepalive || ep.Host != prev.Host
				if connectionChanged {
					for _, d := range s.Devices {
						if d.InstanceID == i.ID && !d.Revoked {
							return fmt.Errorf("connection parameters require reissuing profiles: revoke active devices first")
						}
					}
					if len(domain.Targets(s, i.ID)) > 0 {
						return fmt.Errorf("remove placements before changing connection parameters")
					}
					for _, d := range s.Deployments {
						if d.InstanceID == i.ID {
							return fmt.Errorf("wait for remote cleanup before changing connection parameters")
						}
					}
				}
				i.PrivateKey = old.PrivateKey
				i.PublicKey = old.PublicKey
				i.ProbePrivateKey = old.ProbePrivateKey
				i.ProbePublicKey = old.ProbePublicKey
				i.ProbePSK = old.ProbePSK
				i.Params = old.Params
				i.Revision = old.Revision
				if connectionChanged {
					i.Revision++
				}
				prev.Host = ep.Host
				ep = prev
				if connectionChanged {
					ep.CheckedAt = time.Time{}
					ep.DNSMatches = false
				}
			}
			if e := awg.Validate(i, ep); e != nil {
				return e
			}
			for _, other := range s.Instances {
				if other.ID != i.ID && netip.MustParsePrefix(other.Subnet).Overlaps(netip.MustParsePrefix(i.Subnet)) {
					return fmt.Errorf("subnet already reserved")
				}
			}
			s.Instances[i.ID] = i
			s.Endpoints[ep.ID] = ep
			objectID = i.ID
		case "save_placement":
			p := c.Placement
			if _, ok := s.Instances[p.InstanceID]; !ok {
				return ErrNotFound
			}
			if _, ok := s.Pools[p.PoolID]; !ok {
				return ErrNotFound
			}
			if p.Mode != "all_servers" && p.Mode != "selected_servers" {
				return fmt.Errorf("invalid placement mode")
			}
			for _, id := range p.ServerIDs {
				v, ok := s.Servers[id]
				if !ok || v.PoolID != p.PoolID {
					return fmt.Errorf("selected server is not in pool")
				}
			}
			if p.ID == "" {
				p.ID = domain.ID()
			} else {
				if _, ok := s.Placements[p.ID]; !ok {
					return ErrNotFound
				}
			}
			s.Placements[p.ID] = p
			objectID = p.ID
		case "delete_placement":
			if _, ok := s.Placements[c.ID]; !ok {
				return ErrNotFound
			}
			delete(s.Placements, c.ID)
			objectID = c.ID
		case "delete_server":
			v, ok := s.Servers[c.ID]
			if !ok {
				return ErrNotFound
			}
			for _, d := range s.Deployments {
				if d.ServerID == v.ID {
					return fmt.Errorf("remove placements and wait for remote cleanup before deleting server")
				}
			}
			for _, p := range s.Placements {
				if p.PoolID == v.PoolID && p.Mode == "all_servers" {
					return fmt.Errorf("change all_servers placement before deleting server")
				}
			}
			delete(s.Servers, c.ID)
			objectID = c.ID
		case "delete_pool":
			if _, ok := s.Pools[c.ID]; !ok {
				return ErrNotFound
			}
			for _, v := range s.Servers {
				if v.PoolID == c.ID {
					return fmt.Errorf("pool still has servers")
				}
			}
			for _, v := range s.Placements {
				if v.PoolID == c.ID {
					return fmt.Errorf("pool still has placements")
				}
			}
			delete(s.Pools, c.ID)
			objectID = c.ID
		case "delete_instance":
			if _, ok := s.Instances[c.ID]; !ok {
				return ErrNotFound
			}
			for _, d := range s.Deployments {
				if d.InstanceID == c.ID {
					return fmt.Errorf("remove placements and wait for cleanup first")
				}
			}
			for _, p := range s.Placements {
				if p.InstanceID == c.ID {
					return fmt.Errorf("remove placements first")
				}
			}
			for id, d := range s.Devices {
				if d.InstanceID == c.ID {
					if !d.Revoked {
						return fmt.Errorf("revoke devices first")
					}
					delete(s.Devices, id)
				}
			}
			for id, g := range s.Grants {
				if g.InstanceID == c.ID {
					delete(s.Grants, id)
				}
			}
			for id, e := range s.Endpoints {
				if e.InstanceID == c.ID {
					delete(s.Endpoints, id)
				}
			}
			delete(s.Instances, c.ID)
			objectID = c.ID
		case "retire_endpoint":
			ep, ok := s.Endpoints[c.ID]
			if !ok {
				return ErrNotFound
			}
			if !c.Preview && !c.Confirm {
				return fmt.Errorf("confirm retiring the endpoint")
			}
			for _, d := range s.Devices {
				if d.InstanceID == ep.InstanceID && !d.Revoked {
					return fmt.Errorf("revoke all devices before retiring endpoint")
				}
			}
			for _, d := range s.Deployments {
				if d.InstanceID == ep.InstanceID && (d.Remove || d.AppliedRevision != s.Instances[ep.InstanceID].Revision || d.Status != "ready") {
					return fmt.Errorf("wait for every replica to confirm revocations before retiring endpoint")
				}
			}
			ep.TargetServerID = ""
			ep.DNSMatches = false
			ep.CheckedAt = time.Time{}
			s.Endpoints[ep.ID] = ep
			i := s.Instances[ep.InstanceID]
			i.Disabled = true
			s.Instances[i.ID] = i
			objectID = ep.ID
		case "save_user":
			u := c.User
			if !validName(u.Name) {
				return fmt.Errorf("user name required")
			}
			if u.ID == "" {
				u.ID = domain.ID()
			} else {
				if _, ok := s.Users[u.ID]; !ok {
					return ErrNotFound
				}
			}
			s.Users[u.ID] = u
			objectID = u.ID
			if u.Blocked && c.RevokeExisting {
				revoke(s, u.ID, "", actor)
			}
		case "save_identity":
			v := c.Identity
			if _, ok := s.Users[v.UserID]; !ok {
				return ErrNotFound
			}
			tg, e := strconv.ParseInt(v.ExternalID, 10, 64)
			if v.Provider != "telegram" || e != nil || tg <= 0 {
				return fmt.Errorf("positive 64-bit Telegram ID required")
			}
			v.ExternalID = strconv.FormatInt(tg, 10)
			for _, other := range s.Identities {
				if other.Provider == v.Provider && other.ExternalID == v.ExternalID && other.ID != v.ID {
					return fmt.Errorf("identity already assigned")
				}
			}
			if v.ID == "" {
				v.ID = domain.ID()
			} else {
				if _, ok := s.Identities[v.ID]; !ok {
					return ErrNotFound
				}
			}
			s.Identities[v.ID] = v
			objectID = v.ID
		case "save_grant":
			g := c.Grant
			if _, ok := s.Users[g.UserID]; !ok {
				return ErrNotFound
			}
			if _, ok := s.Instances[g.InstanceID]; !ok {
				return ErrNotFound
			}
			if g.Limit < 0 {
				return fmt.Errorf("limit must be >=0; zero means unlimited")
			}
			for _, old := range s.Grants {
				if old.UserID == g.UserID && old.InstanceID == g.InstanceID {
					g.ID = old.ID
				}
			}
			if g.ID == "" {
				g.ID = domain.ID()
			}
			s.Grants[g.ID] = g
			objectID = g.ID
			if !g.Enabled && c.RevokeExisting {
				revoke(s, g.UserID, g.InstanceID, actor)
			}
		case "revoke_device":
			d, ok := s.Devices[c.ID]
			if !ok {
				return ErrNotFound
			}
			if !d.Revoked {
				d.Revoked = true
				s.Devices[d.ID] = d
				Bump(s, d.InstanceID, actor)
			}
			objectID = d.ID
		case "retry_operation":
			o, ok := s.Operations[c.ID]
			if !ok {
				return ErrNotFound
			}
			if o.Status != "failed" && o.Status != "retry" {
				return fmt.Errorf("operation is not failed")
			}
			o.Status = "queued"
			o.Attempts = 0
			o.AvailableAt = time.Now().UTC()
			o.Error = ""
			s.Operations[o.ID] = o
			objectID = o.ID
		case "sync_deployment":
			d, ok := s.Deployments[c.ID]
			if !ok {
				return ErrNotFound
			}
			d.Status = "syncing"
			d.VerifiedRevision = 0
			s.Deployments[d.ID] = d
			queue(s, d, actor)
			objectID = d.ID
		default:
			return fmt.Errorf("unknown action")
		}
		changes, e := Reconcile(s, actor)
		if e != nil {
			return e
		}
		for _, change := range changes {
			if change.Action == "remove" && !c.Confirm && !c.Preview {
				return fmt.Errorf("preview deployment removals and confirm")
			}
		}
		result = map[string]any{"id": objectID, "changes": changes}
		if c.Preview {
			return errPreview
		}
		if c.Action == "save_pool" || c.Action == "save_server" {
			for _, d := range s.Deployments {
				sv := s.Servers[d.ServerID]
				if (c.Action == "save_pool" && sv.PoolID == objectID) || (c.Action == "save_server" && sv.ID == objectID) {
					queue(s, d, actor)
				}
			}
		}
		audit(s, actor, c.Action, objectID)
		return nil
	})
	if errors.Is(err, errPreview) {
		err = nil
	}
	return result, err
}
func revoke(s *domain.State, user, instance, actor string) {
	changed := map[string]bool{}
	for id, d := range s.Devices {
		if d.UserID == user && (instance == "" || instance == d.InstanceID) && !d.Revoked {
			d.Revoked = true
			s.Devices[id] = d
			changed[d.InstanceID] = true
		}
	}
	for id := range changed {
		Bump(s, id, actor)
	}
}
func (svc *Service) Snapshot(ctx context.Context) (domain.State, error) {
	var v domain.State
	e := svc.Repo.View(ctx, func(s *domain.State) error {
		v = *s
		for id, x := range v.Servers {
			x.Credential = ""
			v.Servers[id] = x
		}
		for id, x := range v.Instances {
			x.PrivateKey = ""
			x.ProbePrivateKey = ""
			x.ProbePSK = ""
			x.Params.HeaderKey = ""
			v.Instances[id] = x
		}
		for id, x := range v.Devices {
			x.PrivateKey = ""
			x.PSK = ""
			x.RequestID = ""
			v.Devices[id] = x
		}
		return nil
	})
	return v, e
}
func resolveUser(s *domain.State, telegram string) (domain.User, error) {
	for _, v := range s.Identities {
		if v.Provider == "telegram" && v.ExternalID == telegram {
			u, ok := s.Users[v.UserID]
			if ok && !u.Blocked {
				return u, nil
			}
		}
	}
	return domain.User{}, ErrForbidden
}
func allowed(s *domain.State, user, instance string) (domain.Grant, error) {
	u, ok := s.Users[user]
	if !ok || u.Blocked {
		return domain.Grant{}, ErrForbidden
	}
	for _, g := range s.Grants {
		if g.UserID == user && g.InstanceID == instance && g.Enabled {
			return g, nil
		}
	}
	return domain.Grant{}, ErrForbidden
}
func (svc *Service) UserView(ctx context.Context, telegram string) (any, error) {
	var result any
	e := svc.Repo.View(ctx, func(s *domain.State) error {
		u, e := resolveUser(s, telegram)
		if e != nil {
			return e
		}
		instances := []any{}
		for _, g := range s.Grants {
			if g.UserID == u.ID && g.Enabled {
				v := s.Instances[g.InstanceID]
				if !v.Disabled {
					instances = append(instances, map[string]any{"id": v.ID, "name": v.Name, "limit": g.Limit, "ready": s.Ready(v.ID)})
				}
			}
		}
		devices := []domain.Device{}
		for _, d := range s.Devices {
			if d.UserID == u.ID {
				d.PrivateKey = ""
				d.PSK = ""
				d.RequestID = ""
				devices = append(devices, d)
			}
		}
		result = map[string]any{"user": u, "instances": instances, "devices": devices}
		return nil
	})
	return result, e
}
func (svc *Service) CreateDevice(ctx context.Context, actor, telegram, user, instance, name, request string) (domain.Device, error) {
	var result domain.Device
	e := svc.Repo.Update(ctx, func(s *domain.State) error {
		if telegram != "" {
			u, e := resolveUser(s, telegram)
			if e != nil {
				return e
			}
			user = u.ID
		}
		g, e := allowed(s, user, instance)
		if e != nil {
			return e
		}
		if !validName(name) || len(request) < 8 || len(request) > 160 {
			return fmt.Errorf("device name and stable request_id (8–160 chars) required")
		}
		for _, d := range s.Devices {
			if d.UserID == user && d.RequestID == request {
				if d.InstanceID != instance || d.Name != name {
					return fmt.Errorf("request_id already used for another request")
				}
				result = d
				result.PrivateKey = ""
				result.PSK = ""
				return nil
			}
		}
		i, ok := s.Instances[instance]
		if !ok || i.Disabled {
			return ErrForbidden
		}
		if !s.Ready(instance) {
			return ErrPending
		}
		count := 0
		for _, d := range s.Devices {
			if d.InstanceID == instance && d.UserID == user && !d.Revoked {
				count++
			}
		}
		if g.Limit > 0 && count >= g.Limit {
			return fmt.Errorf("device limit reached")
		}
		address, e := domain.NextAddress(s, i)
		if e != nil {
			return e
		}
		priv, pub, e := awg.KeyPair()
		if e != nil {
			return e
		}
		d := domain.Device{ID: domain.ID(), UserID: user, InstanceID: instance, Name: name, Address: address, PublicKey: pub, RequestID: request, CreatedAt: time.Now().UTC(), Revision: i.Revision + 1}
		d.PrivateKey = svc.Vault.Seal(priv, d.ID+":private")
		d.PSK = svc.Vault.Seal(awg.RandomKey(), d.ID+":psk")
		s.Devices[d.ID] = d
		Bump(s, instance, actor)
		audit(s, actor, "create_device", d.ID)
		result = d
		result.PrivateKey = ""
		result.PSK = ""
		return nil
	})
	return result, e
}
func (svc *Service) Profile(ctx context.Context, actor, telegram, device string) (string, error) {
	var url string
	e := svc.Repo.Update(ctx, func(s *domain.State) error {
		d, ok := s.Devices[device]
		if !ok {
			return ErrNotFound
		}
		if telegram != "" {
			u, e := resolveUser(s, telegram)
			if e != nil {
				return e
			}
			if d.UserID != u.ID {
				return ErrForbidden
			}
		}
		u := s.Users[d.UserID]
		if u.Blocked || d.Revoked {
			return ErrForbidden
		}
		if !s.Ready(d.InstanceID) {
			return ErrPending
		}
		i := s.Instances[d.InstanceID]
		ep, _ := s.Endpoint(i.ID)
		var e error
		if i.Params.HeaderKey, e = svc.Vault.Open(i.Params.HeaderKey, i.ID+":header"); e != nil {
			return e
		}
		if d.PrivateKey, e = svc.Vault.Open(d.PrivateKey, d.ID+":private"); e != nil {
			return e
		}
		if d.PSK, e = svc.Vault.Open(d.PSK, d.ID+":psk"); e != nil {
			return e
		}
		url, e = awg.URL(i, ep, d)
		if e != nil {
			return e
		}
		audit(s, actor, "get_profile", device)
		return nil
	})
	return url, e
}
func (svc *Service) RevokeOwn(ctx context.Context, telegram, id string) error {
	return svc.Repo.Update(ctx, func(s *domain.State) error {
		u, e := resolveUser(s, telegram)
		if e != nil {
			return e
		}
		d, ok := s.Devices[id]
		if !ok {
			return ErrNotFound
		}
		if d.UserID != u.ID {
			return ErrForbidden
		}
		if !d.Revoked {
			d.Revoked = true
			s.Devices[id] = d
			Bump(s, d.InstanceID, "telegram:"+telegram)
			audit(s, "telegram:"+telegram, "revoke_device", id)
		}
		return nil
	})
}
func (svc *Service) CheckDNS(ctx context.Context, actor, endpoint, target string) (domain.Endpoint, error) {
	var ep domain.Endpoint
	var server domain.Server
	e := svc.Repo.View(ctx, func(s *domain.State) error {
		var ok bool
		ep, ok = s.Endpoints[endpoint]
		if !ok {
			return ErrNotFound
		}
		server, ok = s.Servers[target]
		if !ok {
			return ErrNotFound
		}
		ready := false
		for _, d := range s.Deployments {
			if d.InstanceID == ep.InstanceID && d.ServerID == target && !d.Remove && d.Status == "ready" && d.VerifiedRevision == s.Instances[ep.InstanceID].Revision {
				ready = true
			}
		}
		if !ready {
			return ErrPending
		}
		return nil
	})
	if e != nil {
		return ep, e
	}
	ips, e := net.DefaultResolver.LookupHost(ctx, ep.Host)
	if e != nil {
		return ep, fmt.Errorf("DNS lookup failed")
	}
	slices.Sort(ips)
	matches := len(ips) == 1 && ips[0] == server.PublicIP
	e = svc.Repo.Update(ctx, func(s *domain.State) error {
		cur := s.Endpoints[endpoint]
		if cur.Host != ep.Host {
			return fmt.Errorf("endpoint changed; retry")
		}
		valid := false
		for _, d := range s.Deployments {
			if d.InstanceID == cur.InstanceID && d.ServerID == target && !d.Remove && d.Status == "ready" && d.VerifiedRevision == s.Instances[cur.InstanceID].Revision {
				valid = true
			}
		}
		if !valid {
			return ErrPending
		}
		cur.ObservedIPs = ips
		cur.DNSMatches = matches
		cur.CheckedAt = time.Now().UTC()
		if matches {
			cur.TargetServerID = target
		}
		s.Endpoints[cur.ID] = cur
		ep = cur
		audit(s, actor, "check_dns", endpoint)
		return nil
	})
	return ep, e
}
