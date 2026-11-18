package awg

import (
	"awgpanel/internal/domain"
	"bytes"
	"compress/zlib"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func KeyPair() (string, string, error) {
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return "", "", e
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}
func RandomKey() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.StdEncoding.EncodeToString(b)
}
func Parameters() domain.Parameters {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	h := [4]uint32{}
	for i := range h {
		h[i] = uint32(i+1)*100000000 + binary.BigEndian.Uint32(b[i*4:])%90000000
	}
	return domain.Parameters{Jc: 6, Jmin: 40, Jmax: 100, S: [4]int{32, 32, 32, 32}, H: h, HeaderKey: RandomKey(), Padding: "10-100", RandomTrailers: true}
}
func ValidHost(h string) bool {
	if ip, e := netip.ParseAddr(h); e == nil {
		return ip.Is4()
	}
	if len(h) > 253 || len(h) < 1 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func Validate(i domain.Instance, e domain.Endpoint) error {
	n, err := netip.ParsePrefix(i.Subnet)
	if err != nil || !n.Addr().Is4() || !n.Addr().IsPrivate() || n.Bits() != 24 || n != n.Masked() {
		return fmt.Errorf("subnet must be a canonical private IPv4 /24")
	}
	if i.Port < 50000 || i.Port > 59999 {
		return fmt.Errorf("port must be 50000–59999")
	}
	if !ValidHost(e.Host) {
		return fmt.Errorf("invalid endpoint hostname")
	}
	if i.MTU < 1280 || i.MTU > 1420 || i.Keepalive < 0 || i.Keepalive > 65535 {
		return fmt.Errorf("invalid MTU or keepalive")
	}
	if len(i.DNS) == 0 || len(i.AllowedIPs) == 0 {
		return fmt.Errorf("DNS and AllowedIPs required")
	}
	for _, a := range i.DNS {
		if _, err := netip.ParseAddr(a); err != nil {
			return fmt.Errorf("invalid DNS IP")
		}
	}
	for _, a := range i.AllowedIPs {
		if _, err := netip.ParsePrefix(a); err != nil {
			return fmt.Errorf("invalid AllowedIPs")
		}
	}
	p := i.Params
	if p.Jc < 0 || p.Jc > 128 || p.Jmin < 0 || p.Jmin > p.Jmax || p.Jmax > 1280 {
		return fmt.Errorf("invalid junk packet parameters")
	}
	seen := map[uint32]bool{}
	for x, h := range p.H {
		if h == 0 || seen[h] || p.S[x] < 12 || p.S[x] > 1024 {
			return fmt.Errorf("invalid AWG headers or padding")
		}
		seen[h] = true
	}
	if p.Padding != "10-100" {
		return fmt.Errorf("unsupported content padding range")
	}
	return nil
}
func params(p domain.Parameters) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Jc = %d\nJmin = %d\nJmax = %d\n", p.Jc, p.Jmin, p.Jmax)
	for x := range 4 {
		fmt.Fprintf(&b, "S%d = %d\nH%d = %d\n", x+1, p.S[x], x+1, p.H[x])
	}
	fmt.Fprintf(&b, "HeaderProtectionKey = %s\nContentPaddingAddition = %s\nRandomTrailers = %s\nDisableCookies = off\n", p.HeaderKey, p.Padding, map[bool]string{true: "on", false: "off"}[p.RandomTrailers])
	return b.String()
}

// Secret fields supplied to renderers must already be decrypted. Device private keys never enter ServerConfig.
func ServerConfig(i domain.Instance, devices []domain.Device) string {
	n := netip.MustParsePrefix(i.Subnet)
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nAddress = %s/%d\nListenPort = %d\nPrivateKey = %s\nMTU = %d\n%s", n.Addr().Next(), n.Bits(), i.Port, i.PrivateKey, i.MTU, params(i.Params))
	for _, d := range devices {
		if !d.Revoked {
			fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", d.PublicKey, d.PSK, d.Address)
		}
	}
	if i.ProbePublicKey != "" {
		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", i.ProbePublicKey, i.ProbePSK, ProbeAddress(i))
	}
	return b.String()
}
func ClientConfig(i domain.Instance, e domain.Endpoint, d domain.Device) string {
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\nDNS = %s\nMTU = %d\n%s\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = %d\n", d.PrivateKey, d.Address, strings.Join(i.DNS, ", "), i.MTU, params(i.Params), i.PublicKey, d.PSK, net.JoinHostPort(e.Host, strconv.Itoa(i.Port)), strings.Join(i.AllowedIPs, ", "), i.Keepalive)
}

// Qt qCompress = big endian uncompressed length + zlib. The client stores last_config as a JSON string.
func URL(i domain.Instance, e domain.Endpoint, d domain.Device) (string, error) {
	native := ClientConfig(i, e, d)
	last := map[string]any{"config": native, "hostName": e.Host, "port": i.Port, "isThirdPartyConfig": true, "client_ip": d.Address + "/32", "client_priv_key": d.PrivateKey, "client_pub_key": d.PublicKey, "server_pub_key": i.PublicKey, "psk_key": d.PSK, "mtu": strconv.Itoa(i.MTU)}
	last["allowed_ips"] = i.AllowedIPs
	last["persistent_keep_alive"] = strconv.Itoa(i.Keepalive)
	for _, line := range strings.Split(params(i.Params), "\n") {
		if k, v, ok := strings.Cut(line, " = "); ok {
			last[k] = v
		}
	}
	raw, e1 := json.Marshal(last)
	if e1 != nil {
		return "", e1
	}
	payload := map[string]any{"containers": []any{map[string]any{"container": "amnezia-awg", "awg": map[string]any{"last_config": string(raw), "isThirdPartyConfig": true, "port": strconv.Itoa(i.Port), "transport_proto": "udp"}}}, "defaultContainer": "amnezia-awg", "description": i.Name + " / " + d.Name, "hostName": e.Host, "dns1": i.DNS[0]}
	if len(i.DNS) > 1 {
		payload["dns2"] = i.DNS[1]
	}
	raw, e1 = json.Marshal(payload)
	if e1 != nil {
		return "", e1
	}
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint32(len(raw)))
	w, _ := zlib.NewWriterLevel(&b, 8)
	if _, e1 = w.Write(raw); e1 != nil {
		return "", e1
	}
	if e1 = w.Close(); e1 != nil {
		return "", e1
	}
	return "vpn://" + base64.RawURLEncoding.EncodeToString(b.Bytes()), nil
}

func ProbeAddress(i domain.Instance) string {
	n := netip.MustParsePrefix(i.Subnet).Addr().As4()
	n[3] = 254
	return netip.AddrFrom4(n).String()
}
