package deployment

import (
	"awgpanel/internal/awg"
	"awgpanel/internal/domain"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Snapshot struct {
	Deployment domain.Deployment
	Server     domain.Server
	Pool       domain.Pool
	Instance   domain.Instance
	Devices    []domain.Device
}
type Runner interface {
	Apply(context.Context, Snapshot) error
	Remove(context.Context, Snapshot) error
	Probe(context.Context, Snapshot) error
}
type SSH struct {
	Image   string
	Archive string
}

var digestImage = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9./:_-]*@sha256:[a-f0-9]{64}$`)
var localImageID = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func NewSSH(image string) (*SSH, error) { return NewSSHWithArchive(image, "") }
func NewSSHWithArchive(image, archive string) (*SSH, error) {
	if archive == "" {
		if !digestImage.MatchString(image) {
			return nil, fmt.Errorf("AWG_RUNTIME_IMAGE requires a repository@sha256 digest, or a local image ID with AWG_RUNTIME_ARCHIVE")
		}
	} else {
		if !localImageID.MatchString(image) {
			return nil, fmt.Errorf("archive delivery requires a Docker sha256 image ID")
		}
		info, e := os.Stat(archive)
		if e != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return nil, fmt.Errorf("AWG_RUNTIME_ARCHIVE must be a readable nonempty regular docker-save archive")
		}
	}
	return &SSH{Image: image, Archive: archive}, nil
}
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func (r *SSH) run(ctx context.Context, s domain.Server, script string) error {
	return r.runInput(ctx, s, "bash -se", strings.NewReader(script))
}
func (r *SSH) runInput(ctx context.Context, s domain.Server, command string, input io.Reader) error {
	var auth ssh.AuthMethod
	if s.AuthType == "key" {
		key, e := ssh.ParsePrivateKey([]byte(s.Credential))
		if e != nil {
			return fmt.Errorf("invalid SSH private key")
		}
		auth = ssh.PublicKeys(key)
	} else {
		auth = ssh.Password(s.Credential)
	}
	config := &ssh.ClientConfig{User: s.SSHUser, Auth: []ssh.AuthMethod{auth}, Timeout: 15 * time.Second, HostKeyAlgorithms: []string{ssh.KeyAlgoED25519}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if ssh.FingerprintSHA256(key) != s.HostKey {
			return fmt.Errorf("SSH host fingerprint mismatch")
		}
		return nil
	}}
	conn, e := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(s.Host, strconv.Itoa(s.SSHPort)))
	if e != nil {
		return fmt.Errorf("SSH connection failed")
	}
	defer conn.Close()
	deadline := time.Now().Add(3 * time.Minute)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	c, ch, req, e := ssh.NewClientConn(conn, s.Host, config)
	if e != nil {
		return fmt.Errorf("SSH authentication or host fingerprint verification failed")
	}
	client := ssh.NewClient(c, ch, req)
	defer client.Close()
	session, e := client.NewSession()
	if e != nil {
		return fmt.Errorf("SSH session failed")
	}
	defer session.Close()
	session.Stdin = input
	session.Stdout = io.Discard
	session.Stderr = io.Discard
	if e = session.Run(command); e != nil {
		return fmt.Errorf("remote command failed; inspect managed deployment on VPS (secret output suppressed)")
	}
	return nil
}
func names(d domain.Deployment) (string, string) {
	compact := strings.ReplaceAll(d.ID, "-", "")
	return "awgp-" + compact, "/opt/awg-panel/" + compact
}
func (r *SSH) Apply(ctx context.Context, s Snapshot) error {
	if r.Archive != "" {
		if e := r.deliverArchive(ctx, s.Server); e != nil {
			return e
		}
	}
	return r.run(ctx, s.Server, r.applyScript(s))
}
func (r *SSH) applyScript(s Snapshot) string {
	name, root := names(s.Deployment)
	i := s.Instance
	config := awg.ServerConfig(i, s.Devices)
	encoded := base64.StdEncoding.EncodeToString([]byte(config))
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(config)))
	peers := []string{i.ProbePublicKey}
	for _, d := range s.Devices {
		if !d.Revoked {
			peers = append(peers, d.PublicKey)
		}
	}
	slices.Sort(peers)
	script := fmt.Sprintf(`set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
. /etc/os-release
[ "$ID" = ubuntu ]
if ! command -v docker >/dev/null; then apt-get update -qq; apt-get install -y docker.io iproute2 python3 util-linux; fi
command -v python3 >/dev/null
command -v flock >/dev/null
systemctl enable --now docker
install -d -m 700 /opt/awg-panel %s
exec 8>/opt/awg-panel/reconcile.lock
flock -w 90 8
name=%s
root=%s
port=%d
if ! docker inspect "$name" >/dev/null 2>&1; then
 if ss -H -lun | awk '{print $5}' | grep -Eq ":${port}$"; then exit 21; fi
 ip -j -4 route show table all | python3 -c %s
 docker network inspect $(docker network ls -q) | python3 -c %s
fi
%s
umask 077
printf %%s %s | base64 -d > "$root/awg0.next.conf"
docker run --rm --network none --cap-add NET_ADMIN --device /dev/net/tun -v "$root:/data" --entrypoint /validate.sh %s /data/awg0.next.conf
mv "$root/awg0.next.conf" "$root/awg0.conf"
if ! docker inspect "$name" >/dev/null 2>&1; then
 docker run -d --name "$name" --label awg-panel.managed=true --restart unless-stopped --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 -p "${port}:${port}/udp" -v "$root:/data" %s >/dev/null
else
 [ "$(docker inspect -f '{{index .Config.Labels "awg-panel.managed"}}' "$name")" = true ]
 [ "$(docker inspect -f '{{.Config.Image}}' "$name")" = %s ]
 docker start "$name" >/dev/null
fi
for attempt in $(seq 1 30); do docker exec "$name" awg show awg0 public-key >/dev/null 2>&1 && break; sleep 1; done
docker exec "$name" /apply.sh
[ "$(docker exec "$name" awg show awg0 public-key)" = %s ]
[ "$(docker exec "$name" awg show awg0 listen-port)" = "$port" ]
[ "$(sha256sum "$root/awg0.conf" | cut -d ' ' -f 1)" = %s ]
actual=$(docker exec "$name" awg show awg0 peers | sort)
[ "$actual" = %s ]
`, quote(root), quote(name), quote(root), i.Port,
		quote("import sys,json,ipaddress; n=ipaddress.ip_network('"+i.Subnet+"'); routes=json.load(sys.stdin); assert not any(r.get('dst','default')!='default' and n.overlaps(ipaddress.ip_network(r['dst'],strict=False)) for r in routes if 'dst' in r)"),
		quote("import sys,json,ipaddress; n=ipaddress.ip_network('"+i.Subnet+"'); nets=json.load(sys.stdin); assert not any(n.overlaps(ipaddress.ip_network(c['Subnet'])) for v in nets for c in (v.get('IPAM',{}).get('Config') or []) if c.get('Subnet') and ':' not in c['Subnet'])"),
		r.imageCommand(), quote(encoded), quote(r.Image), quote(r.Image), quote(r.Image), quote(i.PublicKey), quote(hash), quote(strings.Join(peers, "\n")))
	script += firewallScript(s)

	return script
}
func (r *SSH) Remove(ctx context.Context, s Snapshot) error {
	return r.run(ctx, s.Server, removeScript(s))
}
func removeScript(s Snapshot) string {
	name, root := names(s.Deployment)
	script := fmt.Sprintf("set -eu\ninstall -d -m700 /opt/awg-panel\nexec 8>/opt/awg-panel/reconcile.lock\nflock -w 90 8\ndocker info >/dev/null\nif docker inspect %s >/dev/null 2>&1; then [ \"$(docker inspect -f '{{index .Config.Labels \"awg-panel.managed\"}}' %s)\" = true ]; docker rm -f %s >/dev/null; fi\nrm -f -- %s/awg0.conf %s/awg0.next.conf\nrmdir -- %s 2>/dev/null || true\n", quote(name), quote(name), quote(name), quote(root), quote(root), quote(root))
	short := strings.ReplaceAll(s.Server.ID, "-", "")[:12]
	chain := "AWGP_" + short
	unit := "awgp-firewall-" + short + ".service"
	script += fmt.Sprintf(`
if [ -z "$(docker ps -a --filter label=awg-panel.managed=true -q)" ]; then
 systemctl disable --now %s 2>/dev/null || true
 while iptables -C INPUT -p tcp --dport %d -j %s 2>/dev/null; do iptables -D INPUT -p tcp --dport %d -j %s; done
 iptables -F %s 2>/dev/null || true
 iptables -X %s 2>/dev/null || true
 rm -f -- %s %s
 systemctl daemon-reload
fi
`, quote(unit), s.Server.SSHPort, quote(chain), s.Server.SSHPort, quote(chain), quote(chain), quote(chain), quote("/opt/awg-panel/firewall-"+short+".sh"), quote("/etc/systemd/system/"+unit))
	return script
}
func (r *SSH) Probe(ctx context.Context, s Snapshot) error {
	if e := r.ensureLocalRuntime(ctx); e != nil {
		return e
	}
	i := s.Instance
	n := strings.Split(i.Subnet, ".")
	serverIP := strings.Join(n[:3], ".") + ".1"
	i.AllowedIPs = []string{serverIP + "/32", "1.1.1.1/32"}
	ep := domain.Endpoint{Host: s.Server.PublicIP}
	d := domain.Device{PrivateKey: i.ProbePrivateKey, PublicKey: i.ProbePublicKey, PSK: i.ProbePSK, Address: awg.ProbeAddress(i)}
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "-i", "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--device", "/dev/net/tun", "--entrypoint", "/probe.sh", r.Image, serverIP)
	cmd.Stdin = strings.NewReader(awg.ClientConfig(i, ep, d))
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e := cmd.Run(); e != nil {
		return fmt.Errorf("AWG handshake/traffic probe failed; controller requires Docker, TUN and runtime image")
	}
	return nil
}

// The policy is stored independently of the AWG containers and restored before SSH at boot.
func firewallScript(s Snapshot) string {
	short := strings.ReplaceAll(s.Server.ID, "-", "")[:12]
	chain := "AWGP_" + short
	path := "/opt/awg-panel/firewall-" + short + ".sh"
	unit := "awgp-firewall-" + short + ".service"
	body := "chain=" + quote(chain) + "\niptables -N \"$chain\" 2>/dev/null || true\niptables -F \"$chain\"\n"
	if len(s.Pool.SSHSources) > 0 {
		body += "iptables -A \"$chain\" -s \"$controller_ip/32\" -j ACCEPT\n"
		for _, cidr := range s.Pool.SSHSources {
			body += "iptables -A \"$chain\" -s " + quote(cidr) + " -j ACCEPT\n"
		}
		body += "iptables -A \"$chain\" -j DROP\n"
	} else {
		body += "iptables -A \"$chain\" -j RETURN\n"
	}
	body += fmt.Sprintf("iptables -C INPUT -p tcp --dport %d -j \"$chain\" 2>/dev/null || iptables -I INPUT -p tcp --dport %d -j \"$chain\"\n", s.Server.SSHPort, s.Server.SSHPort)
	unitBody := "[Unit]\nDescription=AWG Panel managed SSH policy\nDefaultDependencies=no\nAfter=local-fs.target\nBefore=network-pre.target ssh.service docker.service\nWants=network-pre.target\n[Service]\nType=oneshot\nExecStart=" + path + "\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n"
	return fmt.Sprintf(`
source_ip=${SSH_CONNECTION%%%% *}
[[ "$source_ip" =~ ^[0-9.]+$ ]]
printf '#!/bin/bash\nset -euo pipefail\ncontroller_ip=%%q\n' "$source_ip" > %s
printf %%s %s | base64 -d >> %s
chmod 700 %s
mv %s %s
printf %%s %s | base64 -d > %s
systemctl daemon-reload
systemctl enable %s
systemctl restart %s
`, quote(path+".tmp"), quote(base64.StdEncoding.EncodeToString([]byte(body))), quote(path+".tmp"), quote(path+".tmp"), quote(path+".tmp"), quote(path), quote(base64.StdEncoding.EncodeToString([]byte(unitBody))), quote("/etc/systemd/system/"+unit), quote(unit), quote(unit))
}

func (r *SSH) imageCommand() string {
	command := "docker image inspect " + quote(r.Image) + " >/dev/null 2>&1"
	if r.Archive == "" {
		command += " || docker pull " + quote(r.Image)
	}
	return command
}
func (r *SSH) deliverArchive(ctx context.Context, server domain.Server) error {
	bootstrap := `set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
. /etc/os-release
[ "$ID" = ubuntu ]
if ! command -v docker >/dev/null; then apt-get update -qq; apt-get install -y docker.io iproute2 python3 util-linux; fi
systemctl enable --now docker
docker info >/dev/null
`
	if e := r.run(ctx, server, bootstrap); e != nil {
		return e
	}
	if e := r.run(ctx, server, "docker image inspect "+quote(r.Image)+" >/dev/null 2>&1"); e == nil {
		return nil
	}
	f, e := os.Open(r.Archive)
	if e != nil {
		return fmt.Errorf("cannot read runtime archive")
	}
	defer f.Close()
	// SSH authenticates the destination; Docker checks layer content and the expected immutable image ID.
	command := "sh -c " + quote("docker load >/dev/null && docker image inspect "+quote(r.Image)+" >/dev/null")
	if e = r.runInput(ctx, server, command, f); e != nil {
		return fmt.Errorf("runtime archive delivery failed: %w", e)
	}
	return nil
}
func (r *SSH) ensureLocalRuntime(ctx context.Context) error {
	if r.Archive == "" {
		return nil
	}
	if e := exec.CommandContext(ctx, "docker", "image", "inspect", r.Image).Run(); e == nil {
		return nil
	}
	f, e := os.Open(r.Archive)
	if e != nil {
		return fmt.Errorf("cannot read local runtime archive")
	}
	defer f.Close()
	cmd := exec.CommandContext(ctx, "docker", "load")
	cmd.Stdin = f
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e = cmd.Run(); e != nil {
		return fmt.Errorf("cannot load runtime archive on controller")
	}
	if e = exec.CommandContext(ctx, "docker", "image", "inspect", r.Image).Run(); e != nil {
		return fmt.Errorf("runtime archive does not contain expected image ID")
	}
	return nil
}
