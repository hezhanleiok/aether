//go:build windows

package main

import (
	"github.com/lxn/walk"

	"github.com/aethergui/aethergui/internal/logx"
	"github.com/aethergui/aethergui/internal/vpn"
)

// attachTray wires the notify icon: left click shows/hides the window, the menu
// offers connect/disconnect, the core status, and a clean exit.
func attachTray(sh *shell) error {
	ni, err := walk.NewNotifyIcon(sh.host)
	if err != nil {
		return err
	}
	if ic, err := walk.NewIconFromSysDLL("shell32", 21); err == nil {
		_ = ni.SetIcon(ic)
	}
	_ = ni.SetToolTip(appTitle)

	visible := func() bool {
		if sh.wv == nil {
			return sh.host.Visible()
		}
		return isWindowVisible(sh.hwnd)
	}
	toggle := func() {
		if visible() {
			sh.hideWindow()
			return
		}
		if sh.wv == nil {
			openBrowserShellWindow(sh.url)
			return
		}
		sh.showWindow()
	}

	ni.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			toggle()
		}
	})

	menu := ni.ContextMenu()
	add := func(text string, fn func()) {
		act := walk.NewAction()
		act.SetText(text)
		act.Triggered().Attach(fn)
		menu.Actions().Add(act)
	}
	add("显示主界面", func() {
		if sh.wv == nil {
			openBrowserShellWindow(sh.url)
			return
		}
		sh.showWindow()
	})
	add("连接", func() {
		go func() {
			if err := sh.a.Connect(); err != nil {
				logx.Errorf("[tray] connect: %v", err)
			}
		}()
	})
	add("断开", func() { go sh.a.Disconnect() })
	add("重连", func() { go sh.a.Reconnect() })
	add("退出", func() { sh.exitFromUI() })

	_ = ni.SetVisible(true)

	// Tooltip mirrors the connection state.
	sh.a.OnState(func(st vpn.State) {
		sh.host.Synchronize(func() {
			switch st.Status {
			case vpn.StatusConnected:
				_ = ni.SetToolTip(appTitle + " — 已连接 " + st.ExitIP)
			case vpn.StatusConnecting, vpn.StatusReconnecting:
				_ = ni.SetToolTip(appTitle + " — 连接中…")
			default:
				_ = ni.SetToolTip(appTitle + " — 未连接")
			}
		})
	})
	return nil
}
