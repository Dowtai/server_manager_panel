package awg

import (
	"awgpanel/internal/domain"
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestProfileMatchesOfficialClientShape(t *testing.T) {
	priv, pub, e := KeyPair()
	if e != nil {
		t.Fatal(e)
	}
	i := domain.Instance{Name: "Личный", PrivateKey: priv, PublicKey: pub, Port: 54321, Subnet: "10.77.1.0/24", MTU: 1376, DNS: []string{"1.1.1.1", "9.9.9.9"}, AllowedIPs: []string{"0.0.0.0/0"}, Keepalive: 25, Params: Parameters()}
	d := domain.Device{Name: "Телефон", PrivateKey: RandomKey(), PSK: RandomKey(), Address: "10.77.1.2"}
	url, e := URL(i, domain.Endpoint{Host: "vpn.example.org"}, d)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(url, "vpn://"))
	if e != nil {
		t.Fatal(e)
	}
	r, e := zlib.NewReader(bytes.NewReader(raw[4:]))
	if e != nil {
		t.Fatal(e)
	}
	data, e := io.ReadAll(r)
	if e != nil {
		t.Fatal(e)
	}
	r.Close()
	if binary.BigEndian.Uint32(raw[:4]) != uint32(len(data)) {
		t.Fatal("Qt length mismatch")
	}
	var v struct {
		Host       string `json:"hostName"`
		Container  string `json:"defaultContainer"`
		Containers []struct {
			AWG struct {
				Last  string `json:"last_config"`
				Third bool   `json:"isThirdPartyConfig"`
			} `json:"awg"`
		} `json:"containers"`
	}
	if e = json.Unmarshal(data, &v); e != nil {
		t.Fatal(e)
	}
	if v.Host != "vpn.example.org" || v.Container != "amnezia-awg" || !v.Containers[0].AWG.Third {
		t.Fatalf("bad client shape: %+v", v)
	}
	var last map[string]any
	if e = json.Unmarshal([]byte(v.Containers[0].AWG.Last), &last); e != nil {
		t.Fatal(e)
	}
	for _, key := range []string{"client_priv_key", "client_ip", "server_pub_key", "psk_key", "HeaderProtectionKey", "RandomTrailers", "allowed_ips", "persistent_keep_alive"} {
		if last[key] == nil {
			t.Fatalf("missing official client field %s", key)
		}
	}
	if last["port"] != float64(54321) || !strings.Contains(last["config"].(string), "Endpoint = vpn.example.org:54321") {
		t.Fatal("domain or numeric port lost")
	}
	for _, forbidden := range []string{"password", "userName", priv} {
		if strings.Contains(string(data), forbidden) {
			t.Fatal("profile leaked management or server secret")
		}
	}
}
func TestServerConfigDoesNotContainClientPrivateKeys(t *testing.T) {
	i := domain.Instance{PrivateKey: RandomKey(), Subnet: "10.77.1.0/24", Params: Parameters(), ProbePublicKey: RandomKey(), ProbePSK: RandomKey()}
	d := domain.Device{PrivateKey: "CLIENT-PRIVATE-MUST-NOT-LEAK", PublicKey: RandomKey(), PSK: RandomKey(), Address: "10.77.1.2"}
	revoked := domain.Device{PublicKey: "REVOKED-PEER", Revoked: true}
	c := ServerConfig(i, []domain.Device{d, revoked})
	if strings.Contains(c, d.PrivateKey) || strings.Contains(c, revoked.PublicKey) {
		t.Fatal("server contains client private key or revoked peer")
	}
	if !strings.Contains(c, d.PublicKey) || !strings.Contains(c, "10.77.1.254/32") {
		t.Fatal("peer or probe missing")
	}
}
func TestRejectMalformedEndpointAndJunkRange(t *testing.T) {
	for _, h := range []string{"example.com\nPostUp=bad", "a:123", "-bad.example", "bad..example", "1.2.3.4;echo"} {
		if ValidHost(h) {
			t.Fatalf("accepted %q", h)
		}
	}
	i := domain.Instance{Subnet: "10.77.1.0/24", Port: 54321, MTU: 1376, DNS: []string{"1.1.1.1"}, AllowedIPs: []string{"0.0.0.0/0"}, Params: Parameters()}
	i.Params.Jmin = 1000
	i.Params.Jmax = 10
	if Validate(i, domain.Endpoint{Host: "vpn.example"}) == nil {
		t.Fatal("invalid junk range accepted")
	}
}
