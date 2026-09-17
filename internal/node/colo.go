package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ProbeColo asks a Cloudflare edge which datacentre answered it and which
// country that datacentre sits in.
//
// Every Cloudflare edge serves the generic /cdn-cgi/trace endpoint for
// cloudflare.com; its "colo" field names the datacentre that handled the
// request (NRT, LAX, FRA, …) and "loc" carries the ISO country code. Because
// these edges are anycast, the answer says where *this* machine's traffic
// lands — which is exactly what the node list wants to show, and something no
// offline geo database can tell (ip-api only reports Cloudflare's
// registration in Canada for every one of them).
func ProbeColo(ctx context.Context, addr string, timeout time.Duration) (colo, loc string, err error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", "", err
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
		return "", "", err
	}
	req := "GET /cdn-cgi/trace HTTP/1.1\r\n" +
		"Host: cloudflare.com\r\n" +
		"User-Agent: AetherVPN\r\n" +
		"Accept: text/plain\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := io.WriteString(tlsConn, req); err != nil {
		return "", "", err
	}
	body, err := io.ReadAll(io.LimitReader(tlsConn, 8192))
	if err != nil && len(body) == 0 {
		return "", "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		if v, ok := strings.CutPrefix(line, "colo="); ok {
			colo = strings.ToUpper(strings.TrimSpace(v))
		} else if v, ok := strings.CutPrefix(line, "loc="); ok {
			loc = strings.ToUpper(strings.TrimSpace(v))
		}
	}
	if colo == "" {
		return "", "", fmt.Errorf("no colo in trace response")
	}
	return colo, loc, nil
}

// SpeedTest measures real download throughput from a specific edge by pulling
// Cloudflare's speed-test payload through that IP. It returns bytes per
// second; the transfer stops early once the budget elapses, so slow edges do
// not stall the sweep.
func SpeedTest(ctx context.Context, addr string, timeout time.Duration) (int64, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}
	cfg := &tls.Config{
		ServerName: "speed.cloudflare.com",
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
		return 0, err
	}
	// 8 MB is enough to separate fast edges from congested ones; the deadline
	// above caps the transfer, and partial transfers still yield a honest bps.
	req := "GET /__down?bytes=8000000 HTTP/1.1\r\n" +
		"Host: speed.cloudflare.com\r\n" +
		"User-Agent: AetherVPN\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n\r\n"
	start := time.Now()
	if _, err := io.WriteString(tlsConn, req); err != nil {
		return 0, err
	}
	// Skip the response header, then count body bytes only.
	buf := make([]byte, 32*1024)
	var hdr []byte
	total := int64(0)
	for {
		n, err := tlsConn.Read(buf)
		if n > 0 {
			hdr = append(hdr, buf[:n]...)
			if i := bytes.Index(hdr, []byte("\r\n\r\n")); i >= 0 {
				total = int64(len(hdr) - i - 4)
				hdr = nil
				break
			}
			if len(hdr) > 16*1024 {
				return 0, fmt.Errorf("oversized header")
			}
		}
		if err != nil {
			return 0, err
		}
	}
	for {
		n, err := tlsConn.Read(buf)
		total += int64(n)
		if err != nil {
			break
		}
	}
	elapsed := time.Since(start)
	if elapsed <= 0 || total == 0 {
		return 0, fmt.Errorf("no data")
	}
	return total * int64(time.Second) / int64(elapsed), nil
}
