//go:build wgtun

// Command aetherregister mints a fresh Cloudflare WARP account and saves it
// under warp-accounts/. It prints ONLY a key fingerprint and the file path —
// never the private key or any account field. The full account (including the
// private key) lives only in the 0600 account file.
package main

import (
	"fmt"
	"os"

	"github.com/aethergui/aethergui/internal/wgtun"
)

func main() {
	acc, path, err := wgtun.RegisterAndSave()
	if err != nil {
		fmt.Fprintf(os.Stderr, "aetherregister: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("fingerprint %s\n", wgtun.AccountFingerprint(acc))
	fmt.Printf("saved       %s\n", path)
}
