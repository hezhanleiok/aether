//go:build wgtun

package wgtun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/aethergui/aethergui/internal/logx"
)

// This file provides the transport half of the Cfon-equivalent design proved
// by the 2026-10-07 controlled experiment
// (.codebuddy/audit/aether-psiphon-config-overlay-verification-phase3.md):
//
//	Aether Core is told, through --psiphon-config / AETHER_PSIPHON_CONFIG, that
//	Psiphon's upstream proxy is socks5://127.0.0.1:<port>. Psiphon then dials
//	every TCP tunnel through that SOCKS server (psiphon logs it as
//	proxiedTcpDial -> "socks connect"). Xiaohe owns the other end, so the only
//	question that matters is WHERE this server's own sockets go.
//
// They go out through the tunnel, and nowhere else:
//
//   - every dial binds its SOURCE address to the address assigned to the wintun
//     adapter (172.16.0.2 / the WARP v6). A packet carrying that source can only
//     be routed by the interface that owns it, i.e. the tunnel. If the tunnel is
//     down the address is not assigned any more and the bind fails, so the dial
//     fails — there is no "silently fell back to the physical NIC" state.
//   - DNS is resolved through the same bound dialer, so a name lookup cannot
//     leak out of another interface either.
//   - Alive() is checked before every dial; when the session is gone the dial is
//     refused outright instead of being attempted.
//
// Deliberately NOT here: UDP ASSOCIATE. Psiphon's UpstreamProxyURL is not used
// by UDPDial (psiphon/net.go), so a UDP path could only ever bypass the tunnel
// and must not be offered.

const (
	socksVer = 0x05

	socksCmdConnect = 0x01

	socksRepSuccess         = 0x00
	socksRepGeneralFailure  = 0x01
	socksRepCmdUnsupported  = 0x07
	socksRepAddrUnsupported = 0x08

	socksATypIPv4   = 0x01
	socksATypDomain = 0x03
	socksATypIPv6   = 0x04

	// tunnelDialTimeout bounds one CONNECT. It is not a Psiphon budget (the
	// core has AETHER_PSIPHON_READY_SECS for that); it only stops one stalled
	// dial from pinning a relay goroutine forever.
	tunnelDialTimeout = 15 * time.Second

	// tunnelDNSTimeout bounds the name lookup that happens INSIDE a dial.
	tunnelDNSTimeout = 5 * time.Second
)

// DialFunc is the seam that lets tests prove the SOCKS server dials through the
// tunnel instead of through net.Dial.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// TunnelDialer dials TCP with its source address pinned to the native tunnel.
type TunnelDialer struct {
	// SrcIPv4 / SrcIPv6 are the addresses assigned to the wintun adapter. At
	// least one must be set: a dial with no tunnel address is a dial that would
	// leave through the physical link, so it is refused (fail-closed).
	SrcIPv4 net.IP
	SrcIPv6 net.IP

	// DNSServer is the resolver the tunnel configured (cfg.DNS). It is the same
	// value routeManager was given, so the SOCKS upstream and the system
	// takeover can never drift apart. Name resolution inside a dial goes to
	// THIS server and nowhere else; nil means "no DNS configured" and any name
	// lookup fails closed.
	DNSServer net.IP

	// Alive reports whether the native session is still up. Nil means "assume
	// up"; production always passes Manager.Running.
	Alive func() bool

	// dnsDial is a test-only seam. When non-nil, dnsTransport calls it instead
	// of dialing a real socket; it receives the fully-resolved transport
	// (udp4/udp6/tcp4/tcp6), the "host:53" target and the tunnel source the
	// real dialer would bind. Production always leaves it nil.
	dnsDial func(ctx context.Context, netw, target string, src net.IP) (net.Conn, error)
}

// errTunnelDown is returned instead of dialing when the tunnel is gone. It is
// intentionally a hard error: continuing would send Psiphon's traffic out of
// the physical NIC with the UI still showing a live session.
var errTunnelDown = errors.New("wgtun: native tunnel is down; refusing to dial (fail-closed)")

// DialContext implements the net.Dialer-shaped seam the SOCKS server calls.
func (d *TunnelDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		// UDP would bypass the tunnel entirely: Psiphon's UpstreamProxyURL is
		// not applied to UDPDial, so there is no correct UDP path here.
		return nil, fmt.Errorf("wgtun: tunnel dialer is TCP-only, refusing %q", network)
	}
	if d.Alive != nil && !d.Alive() {
		return nil, errTunnelDown
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("wgtun: bad dial address %q: %w", addr, err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		ip, err = d.lookup(ctx, network, host)
		if err != nil {
			return nil, err
		}
	}

	family := "tcp4"
	src := d.SrcIPv4
	if ip.To4() == nil {
		family = "tcp6"
		src = d.SrcIPv6
	}
	if network == "tcp4" && family != "tcp4" {
		return nil, fmt.Errorf("wgtun: %s resolved to %s but tcp4 was requested", host, ip)
	}
	if network == "tcp6" && family != "tcp6" {
		return nil, fmt.Errorf("wgtun: %s resolved to %s but tcp6 was requested", host, ip)
	}
	if src == nil {
		// No address on the tunnel for this family: dialing would leave through
		// the physical link.
		return nil, fmt.Errorf("wgtun: no tunnel source address for %s (fail-closed)", family)
	}

	dialer := &net.Dialer{
		Timeout:   tunnelDialTimeout,
		LocalAddr: &net.TCPAddr{IP: src},
	}
	return dialer.DialContext(ctx, family, net.JoinHostPort(ip.String(), port))
}

// resolverDial is the Dial callback handed to net.Resolver. It deliberately
// ignores the address the resolver chose — that comes from the SYSTEM config
// (on Windows, the router's DNS from GetNetworkParams) and must never be used —
// and always queries the tunnel's own DNS server instead.
func (d *TunnelDialer) resolverDial(ctx context.Context, netw, address string) (net.Conn, error) {
	_ = address // system-chosen DNS server is never used
	return d.dnsTransport(ctx, netw)
}

// dnsTransport dials d.DNSServer:53 for the resolver. It coerces the transport
// family to the DNS server's family and pins the socket's source to the
// matching tunnel address. Any missing piece fails closed: a bare socket here
// would leave through the physical NIC.
func (d *TunnelDialer) dnsTransport(ctx context.Context, netw string) (net.Conn, error) {
	if d.DNSServer == nil {
		return nil, errors.New("wgtun: no tunnel DNS server configured (fail-closed)")
	}
	dnsIs4 := d.DNSServer.To4() != nil
	var src net.IP
	switch netw {
	case "udp4", "tcp4":
		if !dnsIs4 {
			return nil, fmt.Errorf("wgtun: tunnel DNS server %s is not IPv4 but %q transport was requested", d.DNSServer, netw)
		}
		src = d.SrcIPv4
	case "udp6", "tcp6":
		if dnsIs4 {
			return nil, fmt.Errorf("wgtun: tunnel DNS server %s is not IPv6 but %q transport was requested", d.DNSServer, netw)
		}
		src = d.SrcIPv6
	case "udp", "tcp":
		// The resolver did not pick a family; derive it from the DNS server so
		// the socket family and the source always match.
		if dnsIs4 {
			netw, src = netw+"4", d.SrcIPv4
		} else {
			netw, src = netw+"6", d.SrcIPv6
		}
	default:
		return nil, fmt.Errorf("wgtun: unsupported DNS transport %q", netw)
	}
	if src == nil {
		// No tunnel address for this family. Do NOT fall back to an unbound
		// socket: that is exactly the path that leaks a lookup out of the
		// physical NIC.
		return nil, fmt.Errorf("wgtun: no tunnel source address for %s DNS (fail-closed)", netw)
	}
	if d.dnsDial != nil {
		return d.dnsDial(ctx, netw, net.JoinHostPort(d.DNSServer.String(), "53"), src)
	}
	return d.dialDNS(ctx, netw, src)
}

// dialDNS performs the real tunnel-bound socket dial to the DNS server.
func (d *TunnelDialer) dialDNS(ctx context.Context, netw string, src net.IP) (net.Conn, error) {
	dn := &net.Dialer{Timeout: tunnelDNSTimeout}
	switch netw {
	case "udp4", "udp6":
		dn.LocalAddr = &net.UDPAddr{IP: src}
	default:
		dn.LocalAddr = &net.TCPAddr{IP: src}
	}
	return dn.DialContext(ctx, netw, net.JoinHostPort(d.DNSServer.String(), "53"))
}

// lookup resolves a name through the tunnel's own DNS server, using a socket
// pinned to the tunnel source. It exists so a name lookup can neither leak out
// of another interface nor use a DNS server the tunnel cannot reach.
func (d *TunnelDialer) lookup(ctx context.Context, network, host string) (net.IP, error) {
	resolver := &net.Resolver{PreferGo: true, Dial: d.resolverDial}
	ctx, cancel := context.WithTimeout(ctx, tunnelDNSTimeout)
	defer cancel()

	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("wgtun: resolving %q through the tunnel: %w", host, err)
	}
	if network == "tcp6" {
		for _, candidate := range ips {
			if candidate.IP.To4() == nil {
				return candidate.IP, nil
			}
		}
	} else {
		for _, candidate := range ips {
			if candidate.IP.To4() != nil {
				return candidate.IP, nil
			}
		}
	}
	if len(ips) > 0 {
		return ips[0].IP, nil
	}
	return nil, fmt.Errorf("wgtun: %q resolved to no address", host)
}

// TunnelSocks is a minimal SOCKS5 server (CONNECT only) whose outbound side is
// the tunnel-bound dialer.
type TunnelSocks struct {
	ln   net.Listener
	dial DialFunc

	closed    chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup

	// mu guards conns, the set of live client/upstream connections Close must
	// interrupt. A torn-down tunnel must not leave an established relay running
	// until the remote side times out.
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// StartTunnelSocks listens on 127.0.0.1 with an OS-chosen port and returns the
// port so the caller can build UpstreamProxyURL from it. Port 0 is used on
// purpose: a fixed port would collide with the core's own listeners (1819/1820)
// and with a previous session that has not been reaped yet.
func StartTunnelSocks(dial DialFunc) (*TunnelSocks, int, error) {
	if dial == nil {
		return nil, 0, errors.New("wgtun: tunnel socks needs a dialer")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, fmt.Errorf("wgtun: listening tunnel socks: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	s := &TunnelSocks{
		ln:     ln,
		dial:   dial,
		closed: make(chan struct{}),
		conns:  make(map[net.Conn]struct{}),
	}
	s.wg.Add(1)
	go s.serve()
	logx.Infof("[wgtun] tunnel socks listening on 127.0.0.1:%d", port)
	return s, port, nil
}

func (s *TunnelSocks) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				logx.Warnf("[wgtun] tunnel socks accept: %v", err)
				return
			}
		}
		// Add before addConn so a concurrent Close's wg.Wait can never observe
		// a zero counter while this connection is being registered.
		s.wg.Add(1)
		if !s.addConn(conn) {
			// Close already ran and snapshotted: the conn was closed by addConn.
			s.wg.Done()
			continue
		}
		go func() {
			defer s.wg.Done()
			defer s.removeConn(conn)
			s.handleConn(conn)
		}()
	}
}

// addConn registers a connection so Close can interrupt it. It reports whether
// the connection was registered; a false result means Close already ran and the
// connection has been closed by this call instead.
func (s *TunnelSocks) addConn(c net.Conn) bool {
	select {
	case <-s.closed:
		_ = c.Close()
		return false
	default:
	}
	s.mu.Lock()
	if s.conns == nil {
		s.conns = make(map[net.Conn]struct{})
	}
	s.conns[c] = struct{}{}
	s.mu.Unlock()
	return true
}

func (s *TunnelSocks) removeConn(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

// Close stops the listener, interrupts every active connection and waits for
// the relays to finish. It is idempotent: the rollback path, the disconnect
// path and the reconnect path all close it, and a second close must not panic
// or block.
//
// The active connections are snapshotted under s.mu and then closed WITHOUT
// holding s.mu, so a relay that calls removeConn concurrently never deadlocks;
// wg.Wait is also called outside the lock for the same reason.
func (s *TunnelSocks) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		if s.ln != nil {
			_ = s.ln.Close()
		}
	})

	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	for _, c := range conns {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetDeadline(time.Now())
		}
		_ = c.Close()
	}

	s.wg.Wait()
	return nil
}

// handleConn runs one SOCKS5 session: greeting, one request, relay.
func (s *TunnelSocks) handleConn(conn net.Conn) {
	defer conn.Close()

	if err := s.greet(conn); err != nil {
		logx.Debugf("[wgtun] tunnel socks greeting failed: %v", err)
		return
	}
	target, err := readRequest(conn)
	if err != nil {
		logx.Debugf("[wgtun] tunnel socks request failed: %v", err)
		writeReply(conn, socksRepGeneralFailure, net.IPv4zero, 0)
		return
	}

	up, err := s.dial(context.Background(), "tcp", target)
	if err != nil {
		// Fail closed and say so: a Psiphon that keeps running against a dead
		// upstream is worse than one that reports the failure.
		logx.Warnf("[wgtun] tunnel socks dial %s failed: %v", target, err)
		writeReply(conn, socksRepGeneralFailure, net.IPv4zero, 0)
		return
	}
	// Track the upstream too, so Close interrupts both ends of an established
	// relay. addConn returning false means Close already ran and closed it.
	if s.addConn(up) {
		defer s.removeConn(up)
	}
	defer up.Close()

	if err := writeReply(conn, socksRepSuccess, net.IPv4zero, 0); err != nil {
		return
	}
	relay(conn, up)
}

// greet performs the method negotiation and accepts "no authentication" only.
func (s *TunnelSocks) greet(conn net.Conn) error {
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return err
	}
	if head[0] != socksVer {
		return fmt.Errorf("unsupported socks version %d", head[0])
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	// 0x05 0x00 = version 5, no authentication required.
	_, err := conn.Write([]byte{socksVer, 0x00})
	return err
}

// readRequest parses one SOCKS5 request and returns "host:port".
func readRequest(conn net.Conn) (string, error) {
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return "", err
	}
	if head[0] != socksVer {
		return "", fmt.Errorf("unsupported socks version %d", head[0])
	}
	if head[1] != socksCmdConnect {
		// BIND and UDP ASSOCIATE are refused: the latter in particular would
		// give Psiphon a UDP path that does not honour UpstreamProxyURL.
		_ = writeReply(conn, socksRepCmdUnsupported, net.IPv4zero, 0)
		return "", fmt.Errorf("unsupported socks command %d", head[1])
	}

	var host string
	switch head[3] {
	case socksATypIPv4:
		b := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case socksATypIPv6:
		b := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case socksATypDomain:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return "", err
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		_ = writeReply(conn, socksRepAddrUnsupported, net.IPv4zero, 0)
		return "", fmt.Errorf("unsupported address type %d", head[3])
	}

	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", int(port[0])<<8|int(port[1]))), nil
}

func writeReply(conn net.Conn, rep byte, ip net.IP, port int) error {
	v4 := ip.To4()
	if v4 == nil {
		v4 = net.IPv4zero
	}
	_, err := conn.Write([]byte{socksVer, rep, 0x00, socksATypIPv4,
		v4[0], v4[1], v4[2], v4[3],
		byte(port >> 8), byte(port)})
	return err
}

// relay copies both ways and half-closes the peer when one side is done, so a
// Psiphon that shuts down its write side is not left waiting on a read.
func relay(down, up net.Conn) {
	done := make(chan struct{}, 2)
	copyAndCloseWrite := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}
	go copyAndCloseWrite(up, down)
	go copyAndCloseWrite(down, up)
	<-done
}

// TunnelAddrs returns the addresses assigned to the live wintun adapter. Both
// are nil when no session is running; callers must treat that as "down".
func (m *Manager) TunnelAddrs() (net.IP, net.IP) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tunnel == nil {
		return nil, nil
	}
	return net.ParseIP(m.tunnel.cfg.IPv4), net.ParseIP(m.tunnel.cfg.IPv6)
}

// TunnelDNS returns the DNS server the live session configures, or nil when
// none is set (or the session is down). It is the same value routeManager was
// handed, so the SOCKS upstream and the system takeover cannot drift apart.
func (m *Manager) TunnelDNS() net.IP {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tunnel == nil || len(m.tunnel.cfg.DNS) == 0 {
		return nil
	}
	// cfg.DNS carries dotted-quad servers (e.g. 1.1.1.1). A non-IP entry is
	// treated as "no DNS": a lookup against it cannot be pinned to the tunnel.
	return net.ParseIP(m.tunnel.cfg.DNS[0])
}

// NewTunnelDialer builds the tunnel-bound dialer for the live session.
func (m *Manager) NewTunnelDialer() *TunnelDialer {
	v4, v6 := m.TunnelAddrs()
	return &TunnelDialer{
		SrcIPv4:   v4,
		SrcIPv6:   v6,
		DNSServer: m.TunnelDNS(),
		Alive:     m.Running,
	}
}

// StartTunnelSocks starts the tunnel-bound SOCKS server for the live session,
// records it as the manager's child resource, and returns the port to put in
// UpstreamProxyURL. Stop closes it: after Stop returns the listener is gone and
// no active relay survives.
func (m *Manager) StartTunnelSocks() (*TunnelSocks, int, error) {
	d := m.NewTunnelDialer()
	if d.SrcIPv4 == nil && d.SrcIPv6 == nil {
		return nil, 0, errors.New("wgtun: no tunnel address assigned; refusing to expose a socks upstream")
	}
	s, port, err := StartTunnelSocks(d.DialContext)
	if err != nil {
		return nil, 0, err
	}
	m.replaceSocks(s)
	return s, port, nil
}

// replaceSocks records s as the manager's child SOCKS, closing any previous one
// first. The reference swap happens under m.mu, but the close of the old server
// runs after the lock is released: TunnelSocks.Close blocks on its relay
// goroutines, and holding m.mu across that is how Stop/Start deadlock against a
// relay whose dialer calls m.Running().
func (m *Manager) replaceSocks(s *TunnelSocks) {
	m.mu.Lock()
	old := m.socks
	m.socks = s
	m.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
}
