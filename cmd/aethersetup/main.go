//go:build windows

// Command aethersetup is the Windows installer for the AetherVPN client.
//
// The release bundle (GUI executable plus its matching Aether core) is
// embedded into this binary, so the setup is a single self-contained file:
// it unpacks to %LOCALAPPDATA%\AetherVPN, drops a shortcut on the desktop
// and one in the start menu, and can start the client when it is done.
//
// Build it with -H=windowsgui so no console window flashes behind the wizard.
package main

import (
	"archive/zip"
	"bytes"
	"embed"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

//go:embed payload/bundle.zip
var payload embed.FS

const appName = "AetherVPN"

var (
	mw     *walk.MainWindow
	pb     *walk.ProgressBar
	status *walk.Label
	btnGo  *walk.PushButton
)

func main() {
	run()
}

func run() {
	if err := (MainWindow{
		AssignTo: &mw,
		Title:    appName + " 安装向导",
		MinSize:  Size{Width: 520, Height: 230},
		Layout:   VBox{Margins: Margins{Left: 20, Top: 20, Right: 20, Bottom: 20}, Spacing: 12},
		Children: []Widget{
			Label{Text: "即将安装 " + appName + " 客户端（含 Aether 核心）", Font: Font{PointSize: 11, Bold: true}},
			Label{Text: "安装位置：" + installDir()},
			VSpacer{Size: 8},
			ProgressBar{AssignTo: &pb, MinValue: 0, MaxValue: 100},
			Label{AssignTo: &status, Text: "准备就绪，点击「安装」开始。"},
			VSpacer{},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{AssignTo: &btnGo, Text: "安装", OnClicked: startInstall},
					PushButton{Text: "关闭", OnClicked: func() { mw.Close() }},
				},
			},
		},
	}).Create(); err != nil {
		walk.MsgBox(nil, appName, "界面创建失败："+err.Error(), walk.MsgBoxIconError)
		return
	}
	mw.Run()
}

func installDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local")
	}
	return filepath.Join(base, appName)
}

func startInstall() {
	btnGo.SetEnabled(false)
	dir := installDir()
	go func() {
		err := doInstall(dir)
		mw.Synchronize(func() {
			if err != nil {
				status.SetText("安装失败：" + err.Error())
				btnGo.SetEnabled(true)
				return
			}
			pb.SetValue(100)
			status.SetText("安装完成，桌面已创建快捷方式。")
			if walk.MsgBox(mw, appName, "安装完成，是否立即启动 "+appName+"？",
				walk.MsgBoxYesNo|walk.MsgBoxIconInformation) == walk.DlgCmdYes {
				_ = exec.Command(filepath.Join(dir, appName+".exe")).Start()
			}
			mw.Close()
		})
	}()
}

func doInstall(dir string) error {
	raw, err := payload.ReadFile("payload/bundle.zip")
	if err != nil {
		return fmt.Errorf("读取内置安装包：%w", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return fmt.Errorf("解析内置安装包：%w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	total := len(zr.File)
	for i, f := range zr.File {
		// Strip the bundle's top-level folder so the exe lands in dir root.
		name := stripTop(f.Name)
		if name == "" || strings.HasSuffix(name, "/") {
			continue
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if err := writeZipFile(f, dst); err != nil {
			return err
		}
		setProgress(int(float64(i+1)/float64(total)*90), "正在解压 "+filepath.Base(dst))
	}

	exe := filepath.Join(dir, appName+".exe")
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("安装包内缺少 %s.exe", appName)
	}
	setProgress(93, "创建快捷方式…")
	if err := makeShortcuts(exe, dir); err != nil {
		return err
	}
	setProgress(98, "正在完成…")
	return nil
}

func stripTop(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	if i := strings.Index(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

func writeZipFile(f *zip.File, dst string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, rc); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func setProgress(pct int, msg string) {
	mw.Synchronize(func() {
		pb.SetValue(pct)
		if msg != "" {
			status.SetText(msg)
		}
	})
}

// makeShortcuts creates the desktop and start-menu entries via WScript.Shell,
// which ships with Windows and needs no extra dependency.
func makeShortcuts(exe, dir string) error {
	script := "$ws = New-Object -ComObject WScript.Shell\n" +
		"$desk = $ws.SpecialFolders('Desktop')\n" +
		`$s = $ws.CreateShortcut("$desk\` + appName + `.lnk")` + "\n" +
		"$s.TargetPath = '" + exe + "'\n" +
		"$s.WorkingDirectory = '" + dir + "'\n" +
		"$s.IconLocation = '" + exe + ",0'\n" +
		"$s.Description = '" + appName + " client'\n" +
		"$s.Save()\n" +
		"$sm = Join-Path ([Environment]::GetFolderPath('StartMenu')) 'Programs\\" + appName + "'\n" +
		"New-Item -ItemType Directory -Force -Path $sm | Out-Null\n" +
		"$s2 = $ws.CreateShortcut((Join-Path $sm '" + appName + ".lnk'))\n" +
		"$s2.TargetPath = '" + exe + "'\n" +
		"$s2.WorkingDirectory = '" + dir + "'\n" +
		"$s2.IconLocation = '" + exe + ",0'\n" +
		"$s2.Save()\n"

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("创建快捷方式失败：%v %s", err, string(out))
	}
	return nil
}
