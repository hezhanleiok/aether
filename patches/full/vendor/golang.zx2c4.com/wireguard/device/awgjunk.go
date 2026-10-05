/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 *
 * Xiaohe patch: AmneziaWG junk packets (anti-DPI decoys).
 */

package device

import (
	crand "crypto/rand"
	"fmt"
	"math/rand/v2"
	"sync"
)

// awgJunkParams is the raw (unvalidated) form of the junk parameters.
type awgJunkParams struct {
	count   int
	minSize int
	maxSize int
	// i1 is the AmneziaWG "fake first packet": one canned packet sent BEFORE
	// the junk decoys and before the initiation itself. AmneziaWG ships I1..I5;
	// only I1 is implemented here — see the note below.
	i1 []byte
}

// awgJunk holds the AmneziaWG "junk packet" configuration. Before every
// handshake initiation the device sends count random packets sized between
// minSize and maxSize out of the SAME UDP socket, so the first packets of a
// flow are no longer a bare 148-byte WireGuard initiation.
//
// This is deliberately the ONE-SIDED subset of AmneziaWG: the handshake message
// itself is byte-for-byte unchanged (no S1/S2 junk inside the packet, no
// H1-H4 magic headers). A standard WireGuard peer — Cloudflare WARP included —
// therefore still completes the handshake and simply drops the decoys, which is
// the whole point: everything here must be invisible to the peer. S1/S2/H1-H4
// are the parts that require an AmneziaWG-capable peer and are NOT implemented.
//
// I1 (the fake first packet) is the half that actually matters against DPI:
// upstream tooling (warpscout) reports that a filter judges a flow by how it
// OPENS, so a session starting with a QUIC/DNS/STUN-looking packet often passes
// where one starting with a bare 148-byte WireGuard initiation does not — while
// changing the junk sizes alone rarely helps. It is sent first, then the junk
// decoys, then the (unchanged) initiation. I2..I5 are just more canned packets
// in AmneziaWG; a single I1 is what the reference clients and warpscout's
// -i1 flag configure, so that is the subset implemented here.
//
// Concurrency: all fields are guarded by mu. create() takes the write lock
// because it advances the ChaCha8 stream (math/rand's sources are not safe for
// concurrent use), which is fine — handshakes are rare (once per ~120s rekey).
type awgJunk struct {
	mu      sync.Mutex
	count   int
	minSize int
	maxSize int
	i1      []byte
	rand    *rand.ChaCha8
}

// enabled reports whether anything should precede the next handshake: either
// the fake first packet (which is useful on its own, even with Jc=0) or the
// junk decoys.
func (j *awgJunk) enabled() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return (j.count > 0 && j.rand != nil) || len(j.i1) > 0
}

// configure validates the three parameters together (so key order in the UAPI
// stream does not matter) and installs them. It mirrors the reference
// implementation's rules: a non-positive count disables junk entirely, and the
// sizes must form a usable range below MaxSegmentSize (2016 on Windows).
func (j *awgJunk) configure(p awgJunkParams) error {
	if p.count < 0 {
		return fmt.Errorf("junk packet count must be non-negative, got %d", p.count)
	}
	if p.minSize < 0 || p.maxSize < 0 {
		return fmt.Errorf("junk packet sizes must be non-negative, got min=%d max=%d", p.minSize, p.maxSize)
	}
	if p.maxSize >= MaxSegmentSize {
		return fmt.Errorf("junk packet max size %d must be smaller than max segment size %d", p.maxSize, MaxSegmentSize)
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	if len(p.i1) >= MaxSegmentSize {
		return fmt.Errorf("fake first packet (%d bytes) must be smaller than max segment size %d", len(p.i1), MaxSegmentSize)
	}
	j.count = p.count
	j.minSize = p.minSize
	j.maxSize = p.maxSize
	// Copy: the caller owns the slice it staged (UAPI reuses its buffer).
	j.i1 = append([]byte(nil), p.i1...)
	j.rand = nil
	if j.count == 0 {
		return nil // no junk: I1 alone still stands, but needs no generator
	}
	// The reference bumps max when it equals min so its size generator can draw
	// from a non-empty range; keep the same leniency instead of rejecting a
	// config an Amnezia client would happily emit.
	if j.maxSize <= j.minSize {
		j.maxSize = j.minSize + 1
	}
	var seed [32]byte
	if _, err := crand.Read(seed[:]); err != nil {
		j.count = 0
		return fmt.Errorf("seeding junk generator: %w", err)
	}
	j.rand = rand.NewChaCha8(seed)
	return nil
}

// create builds the decoy packets for one handshake initiation. It returns nil
// when junk is disabled, so callers can treat "nothing to send" and "error"
// distinctly.
func (j *awgJunk) create() ([][]byte, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.count <= 0 || j.rand == nil {
		// No junk decoys configured — but the fake first packet is useful on
		// its own (Jc=0 + I1 is a normal AmneziaWG shape), so still send it.
		if len(j.i1) == 0 {
			return nil, nil
		}
		return [][]byte{append([]byte(nil), j.i1...)}, nil
	}
	out := make([][]byte, 0, j.count+1)
	// Order matters: I1 first, then the random decoys, then (in the caller)
	// the untouched handshake initiation.
	if len(j.i1) > 0 {
		out = append(out, append([]byte(nil), j.i1...))
	}
	for range j.count {
		size := int(j.rand.Uint64()%uint64(j.maxSize-j.minSize)) + j.minSize
		packet := make([]byte, size)
		if _, err := j.rand.Read(packet); err != nil {
			return out, fmt.Errorf("generating junk packet: %w", err)
		}
		out = append(out, packet)
	}
	return out, nil
}
