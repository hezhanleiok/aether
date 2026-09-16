package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ProbeColo asks a Cloudflare edge which datacentre answered it.
//
// Every Cloudflare edge serves the generic /cdn-cgi/trace endpoint for
// cloudflare.com, and its "colo" field names the datacentre that handled the
// request (NRT, LAX, FRA, …). Because these edges are anycast, the answer says
// where *this* machine's traffic lands — which is exactly what the node list
// wants to show, and something no offline geo database can tell (ip-api only
// reports Cloudflare's registration in Canada for every one of them).
func ProbeColo(ctx context.Context, addr string, timeout time.Duration) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}

	// We dial a bare IP while the certificate is issued to cloudflare.com, so
	// hostname verification cannot apply. The chain is still verified against
	// the system roots, which is what makes this safe.
	cfg := &tls.Config{
		ServerName: "cloudflare.com",
		MinVersion: tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no peer certificate")
			}
			opts := x509.VerifyOptions{Intermediates: x509.NewCertPool()}
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
	}
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return "", err
	}
	req := "GET /cdn-cgi/trace HTTP/1.1\r\n" +
		"Host: cloudflare.com\r\n" +
		"User-Agent: AetherVPN\r\n" +
		"Accept: text/plain\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := io.WriteString(tlsConn, req); err != nil {
		return "", err
	}
	body, err := io.ReadAll(io.LimitReader(tlsConn, 8192))
	if err != nil && len(body) == 0 {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		if v, ok := strings.CutPrefix(line, "colo="); ok {
			colo := strings.TrimSpace(v)
			if colo == "" {
				continue
			}
			return strings.ToUpper(colo), nil
		}
	}
	return "", fmt.Errorf("no colo in trace response")
}
