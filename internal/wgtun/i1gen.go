//go:build wgtun

package wgtun

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"strings"
)

// ---------------------------------------------------------------------------
// AmneziaWG "fake first packet" (I1) generators.
//
// Why this file exists: AmneziaWG obfuscation has two halves, and upstream
// tooling (warpscout's README) is explicit that they are NOT equally
// effective:
//
//	junk packets (Jc/Jmin/Jmax)  ... on their own rarely unblock anything
//	I1, the fake first packet    ... does most of the work
//
// because a DPI tends to judge a flow by how it OPENS. A session that starts
// with something that looks like QUIC/DNS/STUN often passes where one starting
// with a bare 148-byte WireGuard initiation does not. So the honest order of
// operations when a network blocks WireGuard is: change I1 first, and treat
// the junk sizes as a last resort.
//
// Scope (stated plainly, because an over-claimed anti-DPI feature is worse
// than none): these generators produce SHAPES, not protocol-valid sessions.
// Each one emits a UDP payload whose header bytes are what a classifier keys
// on; none of them completes a real exchange with the remote. In particular
// the QUIC profile emits a structurally correct Initial long header but NOT a
// real encrypted CRYPTO frame (that needs QUIC key derivation + AEAD), so a
// validating QUIC stack would drop it. These are meant to defeat
// header-shape-based classification, not a decrypting parser. For a
// byte-accurate packet, generate it externally (e.g. warpscout's -i1 PKT) and
// feed it in as raw hex — ParseI1 accepts that verbatim.
// ---------------------------------------------------------------------------

// I1 profiles understood by GenerateI1. "" and "none" mean "no fake packet".
const (
	I1None   = "none"
	I1QUIC   = "quic"
	I1DNS    = "dns"
	I1STUN   = "stun"
	I1SIP    = "sip"
	I1Random = "random"
)

// I1Profiles lists the selectable profiles in the order tools show them.
var I1Profiles = []string{I1None, I1QUIC, I1DNS, I1STUN, I1SIP, I1Random}

// maxI1Size is the largest fake first packet we will build. The device refuses
// anything at or above MaxSegmentSize (2016 on Windows); staying well under it
// keeps room for the junk decoys that follow.
const maxI1Size = 512

// defaultI1SNI is the hostname the QUIC/SIP profiles mention when none was
// given: a name nobody blocks, and the same default warpscout documents.
const defaultI1SNI = "www.apple.com"

// GenerateI1 builds the fake first packet for a profile. rnd supplies the
// per-packet randomness (nil = crypto/rand), so tests can pin the shape while
// a connect gets a fresh-looking packet each time. An unknown profile is an
// error rather than a silent fallback: a typo must not look like a working
// obfuscation setting.
func GenerateI1(profile, sni string, rnd *rand.ChaCha8) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "", I1None:
		return nil, nil
	case I1QUIC:
		return quicInitial(sni, rnd)
	case I1DNS:
		return dnsQuery(rnd)
	case I1STUN:
		return stunBinding(rnd)
	case I1SIP:
		return sipInvite(sni, rnd)
	case I1Random:
		return randomPacket(rnd)
	}
	return nil, fmt.Errorf("unknown I1 profile %q (want one of: %s)", profile, strings.Join(I1Profiles, ", "))
}

// ParseI1 accepts an already-built packet: either a profile name (which is
// generated) or raw hex (with or without a 0x prefix, and tolerating the
// "<b 0x..>" wrapper AmneziaWG configs use). The hex path is the accurate one
// — it lets an externally generated packet go out byte-for-byte.
func ParseI1(value, sni string, rnd *rand.ChaCha8) ([]byte, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil, nil
	}
	// Amnezia writes the packet as "<b 0xc100000001...>"; strip the wrapper.
	v = strings.TrimSuffix(strings.TrimPrefix(v, "<b"), ">")
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "0x"), "0X")
	if b, err := hex.DecodeString(v); err == nil && len(b) > 0 {
		if len(b) > maxI1Size {
			return nil, fmt.Errorf("I1 packet is %d bytes, max is %d", len(b), maxI1Size)
		}
		return b, nil
	}
	return GenerateI1(value, sni, rnd)
}

// randomBytes draws from the caller's generator, or from crypto/rand.
func randomBytes(rnd *rand.ChaCha8, n int) []byte {
	b := make([]byte, n)
	if rnd != nil {
		_, _ = rnd.Read(b)
		return b
	}
	_, _ = crand.Read(b)
	return b
}

// quicInitial builds a QUIC Initial-shaped packet: long header (0xC0 =
// Initial with a 4-byte packet number), version 1, token length 0, a length
// field matching the payload, then a CRYPTO-frame header and random bytes.
// See the file note: a shape, not a decryptable Initial.
func quicInitial(sni string, rnd *rand.ChaCha8) ([]byte, error) {
	if strings.TrimSpace(sni) == "" {
		sni = defaultI1SNI
	}
	dcid := randomBytes(rnd, 8)
	scid := randomBytes(rnd, 8)
	payload := randomBytes(rnd, 256)

	// CRYPTO frame (type 0x06) with a 2-byte varint length of 256.
	body := make([]byte, 0, 3+len(payload)+len(sni))
	body = append(body, 0x06, 0x41, 0x00)
	body = append(body, payload...)
	// Not QUIC framing: a classifier that string-matches the SNI inside the
	// packet is what this is for. A parser that cannot account for the
	// trailing bytes ignores them.
	body = append(body, sni...)

	pkt := make([]byte, 0, 5+1+len(dcid)+1+len(scid)+1+2+4+len(body))
	pkt = append(pkt, 0xC0, 0x00, 0x00, 0x00, 0x01) // long header + version 1
	pkt = append(pkt, uint8(len(dcid)))
	pkt = append(pkt, dcid...)
	pkt = append(pkt, uint8(len(scid)))
	pkt = append(pkt, scid...)
	pkt = append(pkt, 0x00) // token length 0
	// Payload length as a 2-byte QUIC varint, covering the packet number too.
	total := len(body) + 4
	pkt = append(pkt, 0x40|uint8(total>>8), uint8(total))
	pkt = append(pkt, randomBytes(rnd, 4)...) // packet number
	pkt = append(pkt, body...)
	if len(pkt) > maxI1Size {
		return nil, fmt.Errorf("QUIC I1 is %d bytes, max is %d", len(pkt), maxI1Size)
	}
	return pkt, nil
}

// dnsQuery builds a plausible DNS query: a 12-byte header (random transaction
// id, standard recursive query, QDCOUNT=1), a label-encoded name, then QTYPE A
// / QCLASS IN. It is UDP-port-53-shaped; nothing here is sent to a resolver —
// the packet leaves through the WireGuard socket towards the WARP endpoint.
func dnsQuery(rnd *rand.ChaCha8) ([]byte, error) {
	name := randomLabel(rnd)
	q := make([]byte, 0, 12+len(name)+4)
	q = append(q, randomBytes(rnd, 2)...) // transaction id
	q = append(q, 0x01, 0x00)             // flags: standard query, RD set
	q = append(q, 0x00, 0x01)             // QDCOUNT
	q = append(q, 0x00, 0x00)             // ANCOUNT
	q = append(q, 0x00, 0x00)             // NSCOUNT
	q = append(q, 0x00, 0x00)             // ARCOUNT
	q = append(q, name...)
	q = append(q, 0x00, 0x01) // QTYPE A
	q = append(q, 0x00, 0x01) // QCLASS IN
	return q, nil
}

// randomLabel returns one DNS name in wire format (length-prefixed labels):
// two random labels under .com.
func randomLabel(rnd *rand.ChaCha8) []byte {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := randomBytes(rnd, 18)
	var sb strings.Builder
	sb.WriteByte(10)
	for i := 0; i < 10; i++ {
		sb.WriteByte(alphabet[int(b[i])%len(alphabet)])
	}
	sb.WriteByte(8)
	for i := 10; i < 18; i++ {
		sb.WriteByte(alphabet[int(b[i])%len(alphabet)])
	}
	sb.WriteByte(3)
	sb.WriteString("com")
	sb.WriteByte(0)
	return []byte(sb.String())
}

// stunBinding builds a STUN binding request: type 0x0001, length, the magic
// cookie 0x2112A442 every STUN classifier keys on, and a transaction id.
func stunBinding(rnd *rand.ChaCha8) ([]byte, error) {
	attr := randomBytes(rnd, 24) // stands in for the attribute block
	pkt := make([]byte, 0, 20+len(attr))
	pkt = append(pkt, 0x00, 0x01) // binding request
	pkt = append(pkt, uint8(len(attr)>>8), uint8(len(attr)))
	pkt = append(pkt, 0x21, 0x12, 0xa4, 0x42) // magic cookie
	pkt = append(pkt, randomBytes(rnd, 12)...) // transaction id
	pkt = append(pkt, attr...)
	return pkt, nil
}

// sipInvite builds a SIP INVITE request: real SIP over UDP opens with exactly
// this kind of plain-text request line, which is why the profile exists.
func sipInvite(host string, rnd *rand.ChaCha8) ([]byte, error) {
	if strings.TrimSpace(host) == "" {
		host = "sip.example.com"
	}
	branch := randomBytes(rnd, 8)
	tag := randomBytes(rnd, 6)
	call := randomBytes(rnd, 8)
	body := fmt.Sprintf("INVITE sip:user@%s SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK%x\r\n"+
		"Max-Forwards: 70\r\n"+
		"To: <sip:user@%s>\r\n"+
		"From: <sip:caller@%s>;tag=%x\r\n"+
		"Call-ID: %x@192.0.2.1\r\n"+
		"CSeq: 1 INVITE\r\n"+
		"Contact: <sip:caller@192.0.2.1:5060>\r\n"+
		"Content-Length: 0\r\n\r\n",
		host, branch, host, host, tag, call)
	return []byte(body), nil
}

// randomPacket is the control profile: random bytes of a size typical for a
// UDP probe. It is what "junk without a shape" looks like, kept so an A/B can
// separate "a first packet at all" from "a first packet that looks like
// something".
func randomPacket(rnd *rand.ChaCha8) ([]byte, error) {
	return randomBytes(rnd, 128), nil
}
