//go:build wgtun

package wgtun

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aethergui/aethergui/internal/logx"
	"golang.org/x/crypto/curve25519"
)

// Cloudflare WARP registration (the Aether Core normally does this; this is a
// local fallback so a second, independent WARP account can be minted for
// warp-in-warp). API format follows wgcf (ViRb3/wgcf): the account's tunnel
// protocol is chosen AT REGISTRATION TIME by the request body's `tunnel_type`
// field — set it to "wireguard" (and `key_type` to "curve25519") or Cloudflare
// defaults the account to MASQUE, which the WireGuard handshake then rejects.
//
// The endpoint is a private, undocumented Cloudflare API and may change. Version
// segment is wgcf's current one (v0a5641); warpscout uses v0a4005, but that
// older path is not what pins the protocol — the tunnel_type field is.
const (
	regBaseURL  = "https://api.cloudflareclient.com/v0a5641/reg"
	cfUserAgent = "okhttp/3.12.1"
)

// WarpAccount is a full, ready-to-use WARP identity: local keypair + Cloudflare's
// assigned peer/addresses/client-id. It maps 1:1 onto what identity.go turns into
// a wgtun.Config.
type WarpAccount struct {
	PrivateKey    string    `json:"private_key"`
	PublicKey     string    `json:"public_key"`
	PeerPublicKey string    `json:"peer_public_key"`
	AddressV4     string    `json:"address_v4"`
	AddressV6     string    `json:"address_v6"`
	Reserved      [3]byte   `json:"reserved"`
	AccountID     string    `json:"account_id"`
	Token         string    `json:"token"`
	TunnelType    string    `json:"tunnel_type,omitempty"` // "wireguard" once the request pins it
	RegisteredAt  time.Time `json:"registered_at"`
}

type regResponse struct {
	ID         string `json:"id"`
	Token      string `json:"token"`
	KeyType    string `json:"key_type"`
	TunnelType string `json:"tunnel_type"`
	Config     struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

// generateKeypair produces a clamped X25519 keypair, base64-encoded, exactly as
// WireGuard expects (and as both references do).
func generateKeypair() (privB64, pubB64 string, err error) {
	var priv [32]byte
	if _, err = rand.Read(priv[:]); err != nil {
		return "", "", err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub), nil
}

// RegisterAccount mints a fresh WARP account. client and baseURL are injectable
// so tests can point at a mock server. Logs only a key fingerprint, never the
// private key.
func RegisterAccount(client *http.Client, baseURL string) (*WarpAccount, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	if baseURL == "" {
		baseURL = regBaseURL
	}

	priv, pub, err := generateKeypair()
	if err != nil {
		return nil, err
	}

	// wgcf's request body: tunnel_type=wireguard + key_type=curve25519 pin the
	// account to the WireGuard protocol at registration time. Omitting them made
	// Cloudflare default the account to MASQUE (policy.tunnel_protocol="masque"),
	// whose handshake is rejected — the exact failure seen before.
	reqBody, _ := json.Marshal(map[string]string{
		"key":           pub,
		"install_id":    "",
		"fcm_token":     "",
		"tos":           time.Now().Format(time.RFC3339Nano),
		"model":         "PC",
		"serial_number": "",
		"os_version":    "16.0.0",
		"locale":        "en_US",
		"key_type":      "curve25519",
		"tunnel_type":   "wireguard",
	})

	req, err := http.NewRequest(http.MethodPost, baseURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", cfUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("register: POST %s: %w", baseURL, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("register: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var r regResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("register: parse response: %w", err)
	}
	if r.ID == "" || r.Token == "" {
		return nil, fmt.Errorf("register: response missing id/token")
	}

	acc := &WarpAccount{
		PrivateKey:   priv,
		PublicKey:    pub,
		AddressV4:    r.Config.Interface.Addresses.V4,
		AddressV6:    r.Config.Interface.Addresses.V6,
		AccountID:    r.ID,
		Token:        r.Token,
		TunnelType:   r.TunnelType,
		RegisteredAt: time.Now(),
	}
	if len(r.Config.Peers) > 0 {
		acc.PeerPublicKey = r.Config.Peers[0].PublicKey
	}
	if acc.PeerPublicKey == "" {
		return nil, fmt.Errorf("register: response missing peer public key")
	}

	// Reserved = first 3 bytes of config.client_id. If Cloudflare omits it, the
	// account has no client identifier (reserved stays zero) — still connectable,
	// but logged so the caller can see the two accounts differ.
	if r.Config.ClientID != "" {
		dec, err := base64.StdEncoding.DecodeString(r.Config.ClientID)
		if err != nil || len(dec) < 3 {
			return nil, fmt.Errorf("register: bad client_id %q", r.Config.ClientID)
		}
		copy(acc.Reserved[:], dec[:3])
	} else {
		logx.Warnf("[wgtun] register: no client_id in response; reserved stays zero")
	}

	// No PATCH is needed: wgcf pins the protocol in the register request body
	// (tunnel_type=wireguard), and a warp_enabled PATCH is rejected by Cloudflare
	// ("Invalid registration request") — the account is WARP-enabled on creation.
	// Just surface the protocol so the caller can confirm it is wireguard.
	if r.TunnelType != "" && r.TunnelType != "wireguard" {
		logx.Warnf("[wgtun] register: tunnel_type=%q (want wireguard); WireGuard handshake may be rejected", r.TunnelType)
	}

	logx.Infof("[wgtun] register: account %s tunnel_type=%s key_type=%s (v4=%s v6=%s)",
		AccountFingerprint(acc), acc.TunnelType, r.KeyType, acc.AddressV4, acc.AddressV6)
	return acc, nil
}

// AccountFingerprint returns a short, safe-to-log identifier: first 4 bytes of
// the SHA-256 of the public key, hex-encoded. Never log the private key.
func AccountFingerprint(acc *WarpAccount) string {
	sum := sha256.Sum256([]byte(acc.PublicKey))
	return hex.EncodeToString(sum[:4])
}

// shortKey returns the first 8 chars of a base64 key for log display.
func shortKey(b64 string) string {
	if len(b64) <= 8 {
		return b64
	}
	return b64[:8]
}

// accountsDir returns the directory where registered accounts are stored, one
// JSON file per fingerprint (so multiple accounts coexist and are never
// overwritten). Uses stateDir so tests can redirect it.
func accountsDir() string {
	return filepath.Join(stateDir, "warp-accounts")
}

// SaveAccount persists an account to warp-accounts/<fingerprint>.json. A second
// registration with a different key gets a different filename, so it never
// overwrites an existing account.
func SaveAccount(acc *WarpAccount) (string, error) {
	dir := accountsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, AccountFingerprint(acc)+".json")
	data, err := json.MarshalIndent(acc, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	logx.Infof("[wgtun] register: saved account %s to %s", AccountFingerprint(acc), path)
	return path, nil
}

// RegisterAndSave is the one-shot entry: register, then persist.
func RegisterAndSave() (*WarpAccount, string, error) {
	acc, err := RegisterAccount(nil, "")
	if err != nil {
		return nil, "", err
	}
	path, err := SaveAccount(acc)
	if err != nil {
		return nil, "", err
	}
	return acc, path, nil
}

// LoadAccount reads a saved account file back into a WarpAccount. It never logs
// or prints the private key.
func LoadAccount(path string) (*WarpAccount, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var acc WarpAccount
	if err := json.Unmarshal(data, &acc); err != nil {
		return nil, err
	}
	if acc.PrivateKey == "" || acc.PeerPublicKey == "" {
		return nil, fmt.Errorf("account file %s is incomplete", path)
	}
	return &acc, nil
}

// accountToConfig converts a registered account into a wgtun.Config, the same
// shape identity.go produces, so the stack can use it directly.
//
// Reserved is intentionally NOT set: single-layer testing proved a
// tunnel_type=wireguard account hands back handshake failures when the
// Reserved triple (from config.client_id) is applied to the initiation
// message, and works without it (wgcf's profile never ships one either).
func (a *WarpAccount) toConfig(endpoint string) Config {
	return Config{
		PrivateKey:    a.PrivateKey,
		PeerPublicKey: a.PeerPublicKey,
		IPv4:          a.AddressV4,
		IPv6:          a.AddressV6,
		MTU:           1280,
		DNS:           []string{"1.1.1.1", "1.0.0.1"},
		Endpoint:      endpoint,
	}
}
