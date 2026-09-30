# Third-Party Notices

Xiaohe is an independent Windows client. It distributes and uses third-party
components whose licenses remain applicable to those components. This file
lists what is actually shipped in the Xiaohe release package.

## Aether Core

Xiaohe uses the Aether Core developed by CluvexStudio.

Upstream project:
https://github.com/CluvexStudio/Aether

License:
GNU Affero General Public License v3.0 (AGPL-3.0)

License text:
THIRD-PARTY-LICENSES/AETHER-AGPL-3.0.txt

Upstream license:
https://github.com/CluvexStudio/Aether/blob/main/LICENSE

How it is used:
The Aether Core runs as a separate process (`core-bin/aether.exe`) and is
started and supervised by Xiaohe over a local interface. Xiaohe does not
modify, rebuild, or relicense the Aether Core; the binary shipped in the
release package is the upstream release binary.

The Aether Core is a separate third-party component.
Copyright and licensing of the Aether Core remain with its respective
upstream copyright holders. Xiaohe does not claim ownership of the Aether
Core or of its source code.

Xiaohe is an independent project and is not an official CluvexStudio
product unless explicitly stated otherwise.

### Trademark / branding

Aether name, logo, branding, and related project identity belong to
CluvexStudio and the Aether project and are subject to the upstream
Aether trademark policy:
https://github.com/CluvexStudio/Aether/blob/main/TRADEMARK.md

Xiaohe uses the Aether Core as a third-party component and does not
claim ownership of the Aether name, logo, or branding.

Xiaohe is independently branded and is not represented as an official
Aether product.

## Go dependencies (statically linked into Xiaohe.exe)

Xiaohe.exe is built from Go sources with the following third-party Go
modules statically linked in. Each keeps its own license; the full text of
each license is kept in this repository under `vendor/`.

| Module | License | License text |
| --- | --- | --- |
| github.com/lxn/walk | BSD 3-Clause | vendor/github.com/lxn/walk/LICENSE |
| github.com/lxn/win | BSD 3-Clause | vendor/github.com/lxn/win/LICENSE |
| github.com/jchv/go-webview2 | MIT | vendor/github.com/jchv/go-webview2/LICENSE |
| github.com/jchv/go-winloader | ISC | vendor/github.com/jchv/go-winloader/LICENSE.md |
| golang.org/x/net | BSD 3-Clause | vendor/golang.org/x/net/LICENSE |
| golang.org/x/sys | BSD 3-Clause | vendor/golang.org/x/sys/LICENSE |
| gopkg.in/Knetic/govaluate.v3 | MIT | vendor/gopkg.in/Knetic/govaluate.v3/LICENSE |

The Go toolchain's standard library is covered by the Go BSD 3-Clause
license: https://go.dev/LICENSE

## Not shipped

The following are referenced by the project but are **not** distributed in
the Xiaohe release package, so their licenses do not apply to the package:

- WebView2 Runtime — provided by the operating system / Microsoft Edge, not
  bundled by Xiaohe
