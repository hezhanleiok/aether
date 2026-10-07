//go:build wgtun

package wgtun

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// These tests exist to pin one safety boundary, the one the whole Cfon design
// rests on:
//
//	SOCKS CONNECT -> tunnel-bound dialer -> target TCP
//
// and never
//
//	SOCKS CONNECT -> net.Dial -> physical NIC.
//
// They are hermetic on purpose: every connection is a net.Pipe, so nothing
// touches loopback, the routing table or the network. The dialer is injected,
// which is what makes "which dialer did the server use?" directly assertable.

// fakeUpstream is the connection the injected dialer hands back, so the relay
// path can be exercised without a real socket.
func fakeUpstream() (client, server net.Conn) {
	return net.Pipe()
}

func TestTunnelDialerRejectsNonTCP(t *testing.T) {
	d := &TunnelDialer{SrcIPv4: net.ParseIP("172.16.0.2"), Alive: func() bool { return true }}
	if _, err := d.DialContext(context.Background(), "udp", "1.1.1.1:53"); err == nil {
		t.Fatal("UDP must be refused: Psiphon's UpstreamProxyURL is not applied to UDPDial, so a UDP path would bypass the tunnel")
	}
}

func TestTunnelDialerFailClosedWhenTunnelDown(t *testing.T) {
	d := &TunnelDialer{SrcIPv4: net.ParseIP("172.16.0.2"), Alive: func() bool { return false }}
	_, err := d.DialContext(context.Background(), "tcp", "1.1.1.1:443")
	if !errors.Is(err, errTunnelDown) {
		t.Fatalf("expected errTunnelDown, got %v", err)
	}
}

// TestTunnelDialerFailClosedWithoutSourceAddress is the core fail-closed case:
// with no address on the tunnel there is nothing to pin the socket to, so the
// dial must be refused instead of falling through to the physical link.
func TestTunnelDialerFailClosedWithoutSourceAddress(t *testing.T) {
	d := &TunnelDialer{Alive: func() bool { return true }}
	_, err := d.DialContext(context.Background(), "tcp", "1.1.1.1:443")
	if err == nil || !contains(err.Error(), "fail-closed") {
		t.Fatalf("expected a fail-closed error, got %v", err)
	}
}

func TestTunnelDialerRejectsMalformedAddress(t *testing.T) {
	d := &TunnelDialer{SrcIPv4: net.ParseIP("172.16.0.2"), Alive: func() bool { return true }}
	if _, err := d.DialContext(context.Background(), "tcp", "no-port-here"); err == nil {
		t.Fatal("expected an error for an address with no port")
	}
}

// TestTunnelSocksDialsThroughTheInjectedDialer proves the direction of the
// arrow: what the SOCKS server calls is the tunnel dialer, not net.Dial.
func TestTunnelSocksDialsThroughTheInjectedDialer(t *testing.T) {
	upClient, upServer := fakeUpstream()

	var gotNetwork, gotAddr string
	s := &TunnelSocks{
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			gotNetwork, gotAddr = network, addr
			return upServer, nil
		},
		closed: make(chan struct{}),
	}

	cli, srv := net.Pipe()
	served := make(chan struct{})
	go func() {
		s.handleConn(srv)
		close(served)
	}()

	if err := socksGreet(t, cli); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	socksRequest(cli, "example.com", 443)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(cli, rep); err != nil {
		t.Fatalf("reading reply: %v", err)
	}
	if rep[1] != socksRepSuccess {
		t.Fatalf("reply code = %d, want %d", rep[1], socksRepSuccess)
	}

	if gotNetwork != "tcp" {
		t.Errorf("dial network = %q, want tcp", gotNetwork)
	}
	if gotAddr != "example.com:443" {
		t.Errorf("dial addr = %q, want example.com:443", gotAddr)
	}

	// The relay must actually carry bytes both ways.
	go func() {
		_, _ = upClient.Write([]byte("from-upstream"))
	}()
	buf := make([]byte, len("from-upstream"))
	if _, err := io.ReadFull(cli, buf); err != nil {
		t.Fatalf("relay upstream->client: %v", err)
	}
	if string(buf) != "from-upstream" {
		t.Errorf("relayed payload = %q", buf)
	}

	_ = cli.Close()
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConn did not return after the client closed")
	}
}

// TestTunnelSocksRefusesUDPAssociate pins the second half of the boundary: a
// UDP association would hand Psiphon a path that ignores UpstreamProxyURL.
func TestTunnelSocksRefusesUDPAssociate(t *testing.T) {
	called := false
	s := &TunnelSocks{
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			called = true
			return nil, errors.New("must not be called")
		},
		closed: make(chan struct{}),
	}

	cli, srv := net.Pipe()
	go s.handleConn(srv)

	if err := socksGreet(t, cli); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	// cmd 0x03 = UDP ASSOCIATE.
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0x01, 0xbb}
	go func() { _, _ = cli.Write(req) }()
	rep := make([]byte, 10)
	if _, err := io.ReadFull(cli, rep); err != nil {
		t.Fatalf("reading reply: %v", err)
	}
	if rep[1] != socksRepCmdUnsupported {
		t.Errorf("reply code = %d, want %d (command unsupported)", rep[1], socksRepCmdUnsupported)
	}
	if called {
		t.Error("dialer must not be called for UDP ASSOCIATE")
	}
	_ = cli.Close()
}

// TestTunnelSocksReportsDialFailure covers the fail-closed path the rollback
// depends on: a dead tunnel must surface as a failed CONNECT, not as a session
// that quietly keeps running.
func TestTunnelSocksReportsDialFailure(t *testing.T) {
	s := &TunnelSocks{
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errTunnelDown
		},
		closed: make(chan struct{}),
	}
	cli, srv := net.Pipe()
	go s.handleConn(srv)

	if err := socksGreet(t, cli); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	socksRequest(cli, "example.com", 443)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(cli, rep); err != nil {
		t.Fatalf("reading reply: %v", err)
	}
	if rep[1] == socksRepSuccess {
		t.Fatal("a failed dial must not be reported as success")
	}
	_ = cli.Close()
}

func TestTunnelSocksCloseIsIdempotent(t *testing.T) {
	s := &TunnelSocks{
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errTunnelDown
		},
		closed: make(chan struct{}),
	}
	for i := 0; i < 3; i++ {
		if err := s.Close(); err != nil {
			t.Fatalf("Close #%d: %v", i+1, err)
		}
	}
}

// TestStartTunnelSocksReturnsALoopbackPort checks the listener side only: it
// binds and reports a port, and Close stops it. It never connects anywhere.
func TestStartTunnelSocksReturnsALoopbackPort(t *testing.T) {
	s, port, err := StartTunnelSocks(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errTunnelDown
	})
	if err != nil {
		t.Fatalf("StartTunnelSocks: %v", err)
	}
	if port <= 0 {
		t.Fatalf("port = %d, want > 0", port)
	}
	addr := s.ln.Addr().(*net.TCPAddr)
	if !addr.IP.IsLoopback() {
		t.Errorf("listener bound to %v, want loopback", addr.IP)
	}
	// The reported port must be the listener's actual port (never the "0" that
	// was requested): that is the value UpstreamProxyURL is built from.
	if port != addr.Port {
		t.Errorf("reported port = %d, actual listener port = %d", port, addr.Port)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestStartTunnelSocksRequiresADialer(t *testing.T) {
	if _, _, err := StartTunnelSocks(nil); err == nil {
		t.Fatal("a nil dialer must be refused")
	}
}

// TestTunnelSocksCloseRejectsNewConnections pins the "DOWN ⇒ no new listeners"
// half of the child-resource invariant: after Close the listener is gone and a
// late connection is refused (addConn returns false and closes it).
func TestTunnelSocksCloseRejectsNewConnections(t *testing.T) {
	s, port, err := StartTunnelSocks(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errTunnelDown
	})
	if err != nil {
		t.Fatalf("StartTunnelSocks: %v", err)
	}
	if port <= 0 {
		t.Fatalf("port = %d, want > 0", port)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The listener must be gone.
	if _, err := s.ln.Accept(); err == nil {
		t.Fatal("Accept after Close must fail")
	}

	// A connection that arrives after Close must be refused and closed, not
	// registered into a stale relay.
	c, _ := net.Pipe()
	if s.addConn(c) {
		t.Fatal("addConn after Close must refuse (return false)")
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("the late connection should have been closed by addConn")
	}
}

// TestTunnelSocksRestartAfterClose covers the reconnect half: a fresh
// StartTunnelSocks after Close yields a working listener with its own port.
func TestTunnelSocksRestartAfterClose(t *testing.T) {
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errTunnelDown
	}
	s1, p1, err := StartTunnelSocks(dial)
	if err != nil {
		t.Fatalf("first StartTunnelSocks: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	s2, p2, err := StartTunnelSocks(dial)
	if err != nil {
		t.Fatalf("second StartTunnelSocks: %v", err)
	}
	defer s2.Close()
	if p2 <= 0 {
		t.Fatalf("second port = %d, want > 0", p2)
	}
	if p1 <= 0 {
		t.Fatalf("first port = %d, want > 0", p1)
	}
	if addr := s2.ln.Addr().(*net.TCPAddr); !addr.IP.IsLoopback() {
		t.Errorf("second listener bound to %v, want loopback", addr.IP)
	}
}

// --- DNS transport (D1 / D2 / D5) ---
//
// These exercise dnsTransport/resolverDial through the dnsDial seam, so nothing
// touches a real resolver or the network.

func TestTunnelDialerDNSUsesConfiguredServer(t *testing.T) {
	d := &TunnelDialer{
		SrcIPv4:   net.ParseIP("172.16.0.2"),
		DNSServer: net.ParseIP("1.1.1.1"),
	}
	var gotNetw, gotTarget string
	var gotSrc net.IP
	d.dnsDial = func(ctx context.Context, netw, target string, src net.IP) (net.Conn, error) {
		gotNetw, gotTarget, gotSrc = netw, target, src
		return nil, errors.New("seam: stop before any network")
	}

	// The resolver hands over a fake SYSTEM DNS address; it must be ignored in
	// favour of the tunnel's own server.
	_, err := d.resolverDial(context.Background(), "udp", "192.0.2.53:53")
	if err == nil {
		t.Fatal("expected the seam error")
	}
	if gotNetw != "udp4" {
		t.Errorf("transport = %q, want udp4", gotNetw)
	}
	if gotTarget != "1.1.1.1:53" {
		t.Errorf("target = %q, want 1.1.1.1:53 (system DNS address must be ignored)", gotTarget)
	}
	if !gotSrc.Equal(net.ParseIP("172.16.0.2")) {
		t.Errorf("source = %v, want 172.16.0.2", gotSrc)
	}
}

func TestTunnelDialerDNSRefusesMissingServer(t *testing.T) {
	d := &TunnelDialer{SrcIPv4: net.ParseIP("172.16.0.2")}
	if _, err := d.dnsTransport(context.Background(), "udp"); err == nil || !contains(err.Error(), "fail-closed") {
		t.Fatalf("expected fail-closed for a missing DNS server, got %v", err)
	}
}

func TestTunnelDialerDNSRefusesMissingSourceIPv4(t *testing.T) {
	// DNS server is IPv4 but no tunnel IPv4 source exists: must fail closed, not
	// dial unbound.
	d := &TunnelDialer{DNSServer: net.ParseIP("1.1.1.1")}
	if _, err := d.dnsTransport(context.Background(), "udp"); err == nil || !contains(err.Error(), "fail-closed") {
		t.Fatalf("expected fail-closed for missing IPv4 source, got %v", err)
	}
}

func TestTunnelDialerDNSRefusesMissingSourceIPv6(t *testing.T) {
	// DNS server is IPv6 but no tunnel IPv6 source exists.
	d := &TunnelDialer{
		SrcIPv4:   net.ParseIP("172.16.0.2"),
		DNSServer: net.ParseIP("2606:4700:4700::1111"),
	}
	if _, err := d.dnsTransport(context.Background(), "udp"); err == nil || !contains(err.Error(), "fail-closed") {
		t.Fatalf("expected fail-closed for missing IPv6 source, got %v", err)
	}
}

func TestTunnelDialerDNSFamilyMismatch(t *testing.T) {
	d4 := &TunnelDialer{DNSServer: net.ParseIP("1.1.1.1"), SrcIPv4: net.ParseIP("172.16.0.2")}
	if _, err := d4.dnsTransport(context.Background(), "udp6"); err == nil {
		t.Fatal("an IPv4 DNS server must not run over udp6")
	}
	if _, err := d4.dnsTransport(context.Background(), "tcp6"); err == nil {
		t.Fatal("an IPv4 DNS server must not run over tcp6")
	}

	d6 := &TunnelDialer{
		DNSServer: net.ParseIP("2606:4700:4700::1111"),
		SrcIPv6:   net.ParseIP("2606:4700:110::1"),
	}
	if _, err := d6.dnsTransport(context.Background(), "udp4"); err == nil {
		t.Fatal("an IPv6 DNS server must not run over udp4")
	}
	if _, err := d6.dnsTransport(context.Background(), "tcp4"); err == nil {
		t.Fatal("an IPv6 DNS server must not run over tcp4")
	}
}

// TestTunnelDialerDNSTCPAlsoBound pins that the TCP fallback is held to the
// same source-binding constraint as UDP — not only the UDP path is guarded.
func TestTunnelDialerDNSTCPAlsoBound(t *testing.T) {
	d := &TunnelDialer{
		SrcIPv4:   net.ParseIP("172.16.0.2"),
		DNSServer: net.ParseIP("1.1.1.1"),
	}
	var gotNetw, gotTarget string
	var gotSrc net.IP
	d.dnsDial = func(ctx context.Context, netw, target string, src net.IP) (net.Conn, error) {
		gotNetw, gotTarget, gotSrc = netw, target, src
		return nil, errors.New("seam")
	}
	if _, err := d.resolverDial(context.Background(), "tcp", "192.0.2.53:53"); err == nil {
		t.Fatal("expected the seam error")
	}
	if gotNetw != "tcp4" || gotTarget != "1.1.1.1:53" || !gotSrc.Equal(net.ParseIP("172.16.0.2")) {
		t.Fatalf("tcp DNS dial = (%q, %q, %v), want (tcp4, 1.1.1.1:53, 172.16.0.2)", gotNetw, gotTarget, gotSrc)
	}
}

// --- D4: Close interrupts an established relay ---

func TestTunnelSocksCloseInterruptsActiveRelay(t *testing.T) {
	upClient, upServer := net.Pipe()
	s := &TunnelSocks{
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return upServer, nil
		},
		closed: make(chan struct{}),
		conns:  make(map[net.Conn]struct{}),
	}

	cli, srv := net.Pipe()
	s.addConn(srv) // what serve() does after Accept
	served := make(chan struct{})
	go func() {
		s.handleConn(srv)
		close(served)
	}()

	if err := socksGreet(t, cli); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	socksRequest(cli, "example.com", 443)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(cli, rep); err != nil {
		t.Fatalf("reading reply: %v", err)
	}
	if rep[1] != socksRepSuccess {
		t.Fatalf("reply code = %d, want success", rep[1])
	}

	// The relay is now live. Close must interrupt it, not wait for the remote
	// side to time out.
	closed := make(chan struct{})
	go func() {
		_ = s.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return; the active relay was not interrupted")
	}
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConn did not return after Close")
	}

	_ = cli.Close()
	_ = upClient.Close()
}

// --- Manager ownership (Step 3.1) ---
//
// These pin the child-resource invariant at the Manager level: StartTunnelSocks
// retains the server, and Stop closes it (listener down, relays interrupted)
// without holding m.mu across the blocking Close.

// fakeLiveTunnel is a *tunnel whose cfg is enough for TunnelAddrs/TunnelDNS to
// return real addresses. It never touches a device or the OS: dev is nil and up
// is false, so Down() is a no-op.
func fakeLiveTunnel() *tunnel {
	return &tunnel{cfg: Config{IPv4: "172.16.0.2", DNS: []string{"1.1.1.1"}}}
}

func TestManagerStartTunnelSocksSavesChild(t *testing.T) {
	m := &Manager{tunnel: fakeLiveTunnel()}
	s, port, err := m.StartTunnelSocks()
	if err != nil {
		t.Fatalf("StartTunnelSocks: %v", err)
	}
	if port <= 0 {
		t.Fatalf("port = %d, want > 0", port)
	}
	if m.socks != s {
		t.Fatal("manager did not retain the SOCKS child")
	}
	_ = m.Stop()
}

func TestManagerStopClosesSocks(t *testing.T) {
	m := &Manager{tunnel: fakeLiveTunnel()}
	s, _, err := m.StartTunnelSocks()
	if err != nil {
		t.Fatalf("StartTunnelSocks: %v", err)
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if m.socks != nil {
		t.Fatal("SOCKS child not cleared by Stop")
	}
	if _, err := s.ln.Accept(); err == nil {
		t.Fatal("listener still accepting after Stop")
	}
	c, _ := net.Pipe()
	if s.addConn(c) {
		t.Fatal("addConn after Stop must refuse (return false)")
	}
}

func TestManagerStopIdempotent(t *testing.T) {
	m := &Manager{tunnel: fakeLiveTunnel()}
	if _, _, err := m.StartTunnelSocks(); err != nil {
		t.Fatalf("StartTunnelSocks: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := m.Stop(); err != nil {
			t.Fatalf("Stop #%d: %v", i+1, err)
		}
	}
}

func TestManagerStopInterruptsActiveRelay(t *testing.T) {
	upClient, upServer := net.Pipe()
	s := &TunnelSocks{
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return upServer, nil
		},
		closed: make(chan struct{}),
		conns:  make(map[net.Conn]struct{}),
	}
	m := &Manager{socks: s}

	cli, srv := net.Pipe()
	s.addConn(srv)
	served := make(chan struct{})
	go func() {
		s.handleConn(srv)
		close(served)
	}()

	if err := socksGreet(t, cli); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	socksRequest(cli, "example.com", 443)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(cli, rep); err != nil {
		t.Fatalf("reading reply: %v", err)
	}
	if rep[1] != socksRepSuccess {
		t.Fatalf("reply code = %d, want success", rep[1])
	}

	done := make(chan struct{})
	go func() {
		_ = m.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Manager.Stop did not return; the relay was not interrupted")
	}
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not exit after Manager.Stop")
	}

	_ = cli.Close()
	_ = upClient.Close()
}

// TestFailoverLeavesSocksAlone covers the audit finding that failover reuses the
// same tunnel object and must not rebuild or close the SOCKS child. With no
// routes it returns false immediately, and the child is untouched.
func TestFailoverLeavesSocksAlone(t *testing.T) {
	s := &TunnelSocks{closed: make(chan struct{}), conns: map[net.Conn]struct{}{}}
	m := &Manager{socks: s, tunnel: fakeLiveTunnel()}
	if m.failover() {
		t.Fatal("failover without routes must return false")
	}
	if m.socks != s {
		t.Fatal("failover must not replace or close the SOCKS child")
	}
}

// --- helpers ---

func socksGreet(t *testing.T, cli net.Conn) error {
	t.Helper()
	if _, err := cli.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(cli, buf); err != nil {
		return err
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		t.Fatalf("greeting reply = %v, want [5 0]", buf)
	}
	return nil
}

// socksRequest writes one CONNECT request for host:port.
//
// The write runs on its own goroutine because net.Pipe is unbuffered: the
// server may answer (or refuse) before this side has finished writing, and a
// synchronous write would then deadlock against the reply.
func socksRequest(cli net.Conn, host string, port uint16) {
	req := []byte{0x05, socksCmdConnect, 0x00, socksATypDomain, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	go func() { _, _ = cli.Write(req) }()
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
