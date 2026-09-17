//go:build windows

package main

import (
	"embed"
	"io/fs"
)

// The web UI is compiled into the binary: the client ships as a single exe and
// every asset is served to the embedded browser straight from memory.
//
//go:embed webui/index.html webui/app.css webui/app.js
var webuiFiles embed.FS

// uiAssets returns the embedded frontend subtree.
func uiAssets() fs.FS {
	sub, err := fs.Sub(webuiFiles, "webui")
	if err != nil {
		panic(err)
	}
	return sub
}
