# Xiaohe — Windows 客户端（Go + 第三方 Aether Core）

> Xiaohe 是独立开发的 Windows 图形客户端，使用第三方 **Aether Core**
> （[CluvexStudio/Aether](https://github.com/CluvexStudio/Aether)）作为网络核心组件。
> 作者：**xiaohe**

**Xiaohe 不是 CluvexStudio 官方产品**，与 CluvexStudio 没有官方从属、背书或授权关系。
Xiaohe 与 Aether Core 的关系是：

```text
Xiaohe                    独立开发的 Windows 客户端（本项目）
  └── uses               调用，不修改、不重新编译
      └── Aether Core     第三方开源核心
            ├── upstream: CluvexStudio
            └── license:  AGPL-3.0
```

Go 原生 GUI 驱动 Aether Core 的 Windows 客户端。核心网络功能（WARP / WireGuard /
MASQUE / WARP-in-WARP / Gateway 发现与验证）全部由独立的 Aether Core 提供，GUI 不重复实现。

## 下载

| 文件 | 说明 |
| --- | --- |
| `Xiaohe-<版本>-win-x64.zip` | 便携版：解压后双击 `Xiaohe.exe` 即可运行 |
| `Xiaohe-Setup-<版本>.exe` | 安装版：安装完成后自动创建桌面快捷方式 |

两个版本均自带配套的 Aether Core，无需另行下载。最新版本见
[Releases](https://github.com/hezhanleiok/aether/releases)。

## 架构

```
Xiaohe.exe (Go 外壳)
   │
   ├─ 本机窗口 (WebView2 嵌入 Win32 窗口) + 托盘     ← cmd/aethergui/ui_windows.go
   │     └─ 降级：Edge/Chrome --app 无地址栏窗口（无 WebView2 运行时时）
   │
   ├─ internal/webbridge   127.0.0.1 环回 HTTP + SSE（UI 的唯一通道）
   │     ├─ GET  /api/snapshot          全量 UI 状态
   │     ├─ GET  /api/stream            每秒 SSE 快照 + 实时日志
   │     ├─ GET  /api/traffic/series    1分钟/5分钟/1小时/1天 真实采样
   │     └─ POST /api/…                 连接/协议/节点/规则/设置/核心
   │
   ├─ internal/app         装配层（Core Controller / VPN / 节点 / 代理 / 看门狗）
   │     └─ internal/coremgr            Core Controller（GUI↔Core 唯一通道）
   │            ├─ ProcessBackend       独立 aether.exe 子进程
   │            └─ LibraryBackend       libaether.dll C API
   │
   Aether Core (第三方，独立运行)  WARP · WireGuard · MASQUE H2/H3 · Gool · M-in-M
        └─ 127.0.0.1:1819 SOCKS5 + 127.0.0.1:1820 HTTP CONNECT
```

前端（`cmd/aethergui/webui/`）由 `//go:embed` 编进二进制，六个页面全部驱动真实能力：
首页 / 节点 / 分流 / 规则 / 设置 / 日志 / 关于。

**设计规则（项目要求）**
- Core 与 GUI 完全独立：Core 不硬编码进 GUI，作为独立进程/库运行
- GUI 通过明确的 Core Controller (coremgr) 调用 Core
- Core 的路径、版本、启动参数统一由 GUI 管理（设置页可见可改）
- GUI 能检测：Core 是否存在（Detect）、版本（ProbeVersion）、是否运行（Health/Running）
- 通信接口模块化（Backend 接口），升级 Core 不动上层
- **本地优先**：只实现本地 Core 的启动与连接，Core 二进制由用户放到
  exe 旁 / core-bin\ / 设置页指定路径；发现过程不访问任何网络
- **更新**：启动时自检 + 关于页手动「检查更新」，全程在软件内完成，不跳转浏览器；
  GUI 与其配套核心以**整包**形式一起替换，不会出现「核心已更新而界面未更新」的不兼容情况
- **授权**：试用制，到期提示与联系方式由仓库 `version.json` 远程控制（详见「授权与许可」）

## 功能

- **10 种模式**：全局 VPN / 全局代理 / 分流 / 直连 / WARP / Gool / WireGuard / MASQUE H2 / MASQUE H3 / 自动
- **Windows 接管**：系统代理（注册表快照/恢复）、PAC 分流（用户规则）、LAN 例外、Kill Switch（防火墙规则组）
- **IPv4/IPv6/双栈**、自定义 DNS、DoH 端点、DNS 防泄漏、DNS 分流
- **自动化**：开机启动（HKCU Run + `--connect`）、网络变化重连、断线重连、Gateway 失效切换、缓存 Gateway、重扫
- **节点列表**：Cloudflare 边缘池、IP/国家/延迟/状态、连接后出口 IP + 国旗（🇯🇵🇺🇸…）
- **Core 管理 UI**：主界面 Core 徽标（Ready/Running/Missing/版本）、设置页路径配置 + Detect/Restart/Stop

## 构建

前置：Go 1.22+。

```powershell
# 1) 放置 Core（本地二进制，来源由你自己决定，脚本不下载任何东西）
powershell -ExecutionPolicy Bypass -File scripts\setup-core.ps1 -CorePath C:\path\to\aether.exe
#    或直接复制 aether.exe 到 core-bin\ / exe 同目录

# 2) 构建
powershell -ExecutionPolicy Bypass -File scripts\build.ps1
```

### 产物结构

```
Xiaohe-<版本>\
  Xiaohe.exe             ← GUI 程序（双击即用，无需安装）
  core-bin\
    aether.exe           ← Aether Core（第三方），独立进程
  THIRD-PARTY-NOTICES.md ← 第三方组件清单与许可证
  THIRD-PARTY-LICENSES\  ← 第三方许可证正文
  LICENSE.txt            ← 本软件授权与第三方声明
  README.txt
```

核心始终是独立进程，GUI 通过 `coremgr` 调用它。但**更新时 GUI 与核心作为一个整包一起替换**，
以保证版本配套、不会出现核心先于界面更新的不兼容情况。

手动更换核心仍然可行：替换 `core-bin\aether.exe` 后进入「设置 → Aether 核心」点「检测核心」即可。

不需要 WebView2 运行时的机器会自动降级到 Edge/Chrome 的无边框窗口，界面完全一致。

## 验证

```powershell
go test ./...               # 单元测试: config/coremgr/node/sysproxy/vpn
go run ./cmd/aethersmoke    # 装配冒烟: Core 检测/节点/env 推导
go run ./cmd/aethere2e      # 真实隧道端到端: warp=on + 出口 IP
```

UI 调试（只起服务，可用浏览器打开同一套界面）：

```powershell
.\bin\Xiaohe.exe -ui=none -port=18211 -print-url
```

| `-ui` | 行为 |
| --- | --- |
| `auto`（默认） | WebView2 本机窗口，失败自动降级到浏览器 `--app` 窗口 |
| `window` | 只用 WebView2 本机窗口 |
| `browser` | 只用 Edge/Chrome `--app` 窗口 |
| `none` | 只起本地 UI 服务，不弹窗口（`-print-url` 输出地址） |

连接后: `curl -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace` → `warp=on`

## 模块

| 包 | 职责 |
| --- | --- |
| cmd/aethergui | 本机窗口（WebView2 + 托盘）与嵌入式前端资源 |
| internal/webbridge | **UI 通道**: 环回 HTTP + SSE，状态快照/流量序列/动作 API |
| internal/coremgr | **Core Controller**: Backend 接口 + 进程/库后端 + 生命周期与健康 |
| internal/vpn | 连接状态机 + AETHER_* 推导（10 模式） |
| internal/node | 节点池 / 测速 / 出口 IP 地理 |
| internal/sysproxy | 系统代理 + PAC 分流 |
| internal/killswitch | 防火墙断线保护 |
| internal/autostart | 开机启动 |
| internal/watchguard | 网络监测 / 隧道探测 / 故障切换 |
| internal/config | 设置持久化（含 CorePath/CoreKind/CoreExtraArgs） |
| internal/app | 装配层 |

## Core 升级路径

Core 版本变化只需：替换 core-bin\aether.exe（或 libaether.dll + 设置里切 library 模式）→
设置页点 Detect。Backend 接口不变；若新 Core 改了日志格式，只改 process_backend.go 的 classify()。

## 授权与许可

- **本客户端（GUI）**
  - 由 **xiaohe** 开发并发布
  - 采用**试用授权**：自首次启动起可免费试用 **7 天**
  - 授权状态与到期时间由本仓库的 `version.json` 远程控制（当前到期日 **2026-10-30**），
    到期后软件会提示续期
  - 续期请联系作者（作者主页见仓库首页）

## 第三方组件与许可证

Xiaohe 使用并随包分发第三方组件，这些组件的许可证仍然适用于它们自身，
不会因被 Xiaohe 使用而改变。

### Aether Core

- Xiaohe 使用由 **CluvexStudio** 开发的 **Aether Core**
- Aether Core 是**独立的第三方组件**，以独立进程 `core-bin\aether.exe` 运行
- Aether Core 的源代码采用 **GNU Affero General Public License v3.0（AGPL-3.0）**
- Aether Core 的版权归其原作者/维护者所有
- **Xiaohe 并不声称拥有 Aether Core 的版权**，也未修改或重新编译其源代码；
  随包分发的是上游发布的官方二进制
- **Xiaohe 不是 CluvexStudio 官方产品**
- **Xiaohe 与 CluvexStudio 没有官方从属、背书或授权关系**

官方项目：https://github.com/CluvexStudio/Aether
上游许可证：https://github.com/CluvexStudio/Aether/blob/main/LICENSE
上游商标政策：https://github.com/CluvexStudio/Aether/blob/main/TRADEMARK.md

### 商标与品牌声明

Aether name, logo, branding, and related project identity belong to
CluvexStudio and the Aether project and are subject to the upstream
Aether trademark policy.

Xiaohe uses the Aether Core as a third-party component and does not
claim ownership of the Aether name, logo, or branding.

Xiaohe is independently branded and is not represented as an official
Aether product.

### 其他第三方组件

Xiaohe.exe 静态链接了若干第三方 Go 模块（walk / win / go-webview2 /
go-winloader / x-net / x-sys / govaluate），各自的 BSD-3-Clause、MIT、ISC
许可证保持不变。完整清单见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。

## License

Xiaohe 自身的源代码**采用试用授权**（非开源许可证）：由 xiaohe 开发并发布，
自首次启动起可免费试用 7 天，授权状态与到期时间由本仓库 `version.json` 远程控制。
详见上文「授权与许可」。

Xiaohe 同时分发并使用第三方组件，这些组件的许可证仍然适用于它们自身。
其中 Aether Core 采用 **AGPL-3.0**，该许可证适用于 Aether Core 这一组件，
**不适用于 Xiaohe 自身的源代码**。

See:

- [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)
- [THIRD-PARTY-LICENSES/AETHER-AGPL-3.0.txt](THIRD-PARTY-LICENSES/AETHER-AGPL-3.0.txt)

## 致谢

- **特别感谢 [Aether](https://github.com/CluvexStudio/Aether)（CluvexStudio）** —
  Xiaohe 的全部网络能力（WARP / WireGuard / MASQUE / MASQUE-in-MASQUE / Gool /
  网关发现与验证）都来自这个第三方核心。没有 Aether Core，就没有 Xiaohe 的网络能力。
- 感谢 [Aethery](https://github.com/ZethRise/Aethery) 在移动端上的探索与参考。
