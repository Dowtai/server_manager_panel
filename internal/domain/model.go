package domain

import (
	"crypto/rand"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

func ID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

type Pool struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	SSHSources []string `json:"ssh_sources"`
}
type Server struct {
	ID         string `json:"id"`
	PoolID     string `json:"pool_id"`
	Name       string `json:"name"`
	Host       string `json:"host"`
	SSHPort    int    `json:"ssh_port"`
	SSHUser    string `json:"ssh_user"`
	PublicIP   string `json:"public_ip"`
	Credential string `json:"credential,omitempty"`
	AuthType   string `json:"auth_type"`
	HostKey    string `json:"host_key"`
}
type Parameters struct {
	Jc             int       `json:"jc"`
	Jmin           int       `json:"jmin"`
	Jmax           int       `json:"jmax"`
	S              [4]int    `json:"s"`
	H              [4]uint32 `json:"h"`
	HeaderKey      string    `json:"header_key,omitempty"`
	Padding        string    `json:"padding"`
	RandomTrailers bool      `json:"random_trailers"`
}
type Instance struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Description     string     `json:"description"`
	Subnet          string     `json:"subnet"`
	Port            int        `json:"port"`
	PrivateKey      string     `json:"private_key,omitempty"`
	PublicKey       string     `json:"public_key"`
	ProbePrivateKey string     `json:"probe_private_key,omitempty"`
	ProbePublicKey  string     `json:"probe_public_key"`
	ProbePSK        string     `json:"probe_psk,omitempty"`
	Params          Parameters `json:"params"`
	DNS             []string   `json:"dns"`
	MTU             int        `json:"mtu"`
	AllowedIPs      []string   `json:"allowed_ips"`
	Keepalive       int        `json:"keepalive"`
	Revision        int64      `json:"revision"`
	Disabled        bool       `json:"disabled"`
}
type Endpoint struct {
	ID             string    `json:"id"`
	InstanceID     string    `json:"instance_id"`
	Host           string    `json:"host"`
	TargetServerID string    `json:"target_server_id"`
	ObservedIPs    []string  `json:"observed_ips"`
	DNSMatches     bool      `json:"dns_matches"`
	CheckedAt      time.Time `json:"checked_at"`
}
type Placement struct {
	ID         string   `json:"id"`
	InstanceID string   `json:"instance_id"`
	PoolID     string   `json:"pool_id"`
	Mode       string   `json:"mode"`
	ServerIDs  []string `json:"server_ids"`
}
type Deployment struct {
	ID               string    `json:"id"`
	InstanceID       string    `json:"instance_id"`
	ServerID         string    `json:"server_id"`
	DesiredRevision  int64     `json:"desired_revision"`
	AppliedRevision  int64     `json:"applied_revision"`
	Remove           bool      `json:"remove"`
	Status           string    `json:"status"`
	Error            string    `json:"error"`
	CheckedAt        time.Time `json:"checked_at"`
	VerifiedRevision int64     `json:"verified_revision"`
	VerifiedAt       time.Time `json:"verified_at"`
}
type User struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Blocked bool   `json:"blocked"`
}
type Identity struct {
	ID         string `json:"id"`
	UserID     string `json:"user_id"`
	Provider   string `json:"provider"`
	ExternalID string `json:"external_id"`
}
type Grant struct {
	ID         string `json:"id"`
	UserID     string `json:"user_id"`
	InstanceID string `json:"instance_id"`
	Limit      int    `json:"limit"`
	Enabled    bool   `json:"enabled"`
}
type Device struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	InstanceID string    `json:"instance_id"`
	Name       string    `json:"name"`
	Address    string    `json:"address"`
	PrivateKey string    `json:"private_key,omitempty"`
	PublicKey  string    `json:"public_key"`
	PSK        string    `json:"psk,omitempty"`
	Revoked    bool      `json:"revoked"`
	Revision   int64     `json:"revision"`
	RequestID  string    `json:"request_id"`
	CreatedAt  time.Time `json:"created_at"`
}
type Operation struct {
	ID           string    `json:"id"`
	DeploymentID string    `json:"deployment_id"`
	InstanceID   string    `json:"instance_id"`
	Actor        string    `json:"actor"`
	Status       string    `json:"status"`
	Stage        string    `json:"stage"`
	Attempts     int       `json:"attempts"`
	Error        string    `json:"error"`
	AvailableAt  time.Time `json:"available_at"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
type Audit struct {
	ID       string    `json:"id"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	ObjectID string    `json:"object_id"`
	At       time.Time `json:"at"`
}
type State struct {
	Pools       map[string]Pool       `json:"pools"`
	Servers     map[string]Server     `json:"servers"`
	Instances   map[string]Instance   `json:"instances"`
	Endpoints   map[string]Endpoint   `json:"endpoints"`
	Placements  map[string]Placement  `json:"placements"`
	Deployments map[string]Deployment `json:"deployments"`
	Users       map[string]User       `json:"users"`
	Identities  map[string]Identity   `json:"identities"`
	Grants      map[string]Grant      `json:"grants"`
	Devices     map[string]Device     `json:"devices"`
	Operations  map[string]Operation  `json:"operations"`
	Audit       map[string]Audit      `json:"audit"`
}

func NewState() State {
	return State{map[string]Pool{}, map[string]Server{}, map[string]Instance{}, map[string]Endpoint{}, map[string]Placement{}, map[string]Deployment{}, map[string]User{}, map[string]Identity{}, map[string]Grant{}, map[string]Device{}, map[string]Operation{}, map[string]Audit{}}
}
func Targets(s *State, instance string) []string {
	set := map[string]bool{}
	for _, p := range s.Placements {
		if p.InstanceID != instance {
			continue
		}
		for id, v := range s.Servers {
			if v.PoolID == p.PoolID && (p.Mode == "all_servers" || slices.Contains(p.ServerIDs, id)) {
				set[id] = true
			}
		}
	}
	ids := []string{}
	for id := range set {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}
func NextAddress(s *State, i Instance) (string, error) {
	n, e := netip.ParsePrefix(i.Subnet)
	if e != nil {
		return "", e
	}
	used := map[string]bool{}
	for _, d := range s.Devices {
		if d.InstanceID == i.ID {
			used[d.Address] = true
		}
	}
	for a := n.Addr().Next().Next(); n.Contains(a) && n.Contains(a.Next().Next()); a = a.Next() {
		if !used[a.String()] {
			return a.String(), nil
		}
	}
	return "", fmt.Errorf("subnet exhausted")
}
func (s *State) Endpoint(instance string) (Endpoint, bool) {
	for _, e := range s.Endpoints {
		if e.InstanceID == instance {
			return e, true
		}
	}
	return Endpoint{}, false
}
func (s *State) Ready(instance string) bool {
	i, ok := s.Instances[instance]
	if !ok || i.Disabled {
		return false
	}
	e, ok := s.Endpoint(instance)
	if !ok || !e.DNSMatches || time.Since(e.CheckedAt) > 5*time.Minute {
		return false
	}
	for _, d := range s.Deployments {
		if d.InstanceID == instance && d.ServerID == e.TargetServerID && !d.Remove && d.Status == "ready" && d.AppliedRevision == i.Revision && d.VerifiedRevision == i.Revision {
			return true
		}
	}
	return false
}
