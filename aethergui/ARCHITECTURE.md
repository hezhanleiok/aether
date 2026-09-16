# 架构说明

## 分层（UI / App / Core 三层彻底解耦）

```
┌─────────────────────────────────────────────────┐
│ 嵌入式前端 cmd/aethergui/webui  (HTML/CSS/JS)        │
│   首页 · 节点 · 分流 · 规则 · 设置 · 日志 · 关于          │
├─────────────────────────────────────────────────┤
│ cmd/aethergui shell                                 │
│   WebView2 本机窗口 + 通知区图标（同一消息循环）          │
│   无 WebView2 运行时 → Edge/Chrome 无边框窗口降级        │
├─────────────────────────────────────────────────┤
│ internal/webbridge  环回 HTTP + SSE（UI 唯一入口）      │
├─────────────────────────────────────────────────┤
│ internal/app    装配层 — App 的唯一入口                 │
├──────────┬──────────┬─────────┬────────┬─────────┤
│ vpn      │ node     │sysproxy │killsw  │watchguard│
├──────────┴──────────┴─────────┴────────┴─────────┤
│ internal/coremgr   Core Controller（GUI↔Core 唯一通道） │
│   Manager: Detect/Start/Stop/Restart + Health      │
│   Backend 接口 ── ProcessBackend (aether.exe 子进程) │
│              └── LibraryBackend (libaether.dll C API)│
├─────────────────────────────────────────────────┤
│ Aether Core（独立实体，由 GUI 管理路径/版本/参数）        │
└─────────────────────────────────────────────────┘
```

## UI 通道 (internal/webbridge)

前端不再直接接触任何子系统，只走一层环回 HTTP：

- **单向写实**: `POST /api/connect|disconnect|protocol|mode|nodes/*|core/*|settings`，
  全部转发到 `app.App` 的既有方法，没有一个 UI 特权接口。
- **状态推送**: `GET /api/stream`（SSE）每秒推送一次 `snapshot`，日志行实时追加。
  快照自包含（连接状态 / 流量 / 设置 / 节点 / 系统接管状态），前端不做状态推导。
- **历史序列**: `GET /api/traffic/series?range=1m|5m|1h|1d`，数据来自
  `app.TrafficSampler` 的两级环形缓冲（1 秒精度 1 小时 + 60 秒精度 24 小时），
  下采样到固定点数后交给 canvas 绘制。
- **安全边界**: 只监听 `127.0.0.1`；首帧下发 `SameSite=Strict` 会话 Cookie，
  所有 `/api/*` 校验该 Cookie，第三方网页无法驱动本机的 VPN。

## Core Controller (internal/coremgr)

**Manager** 是 GUI 视角的 Core 唯一管理者：
- `Detect(corePath)` — Locate（纯本地搜索）→ ProbeVersion（跑 core 自身 --version / aether_version）→ Health ∈ {Missing, Incompatible, Ready, Running}
- `Start(env, workDir)` — 拒绝未 Detect / 双启动；转发事件流
- `Stop() / Restart(env)` — 生命周期全部经此
- `Path() / Version() / Health() / Running()` — GUI 显示用

**Backend** 是模块化插点（升级 Core 只换这里）：
- `Locate`：显式路径（设置/AETHER_CORE 环境变量）→ exe 旁 → core-bin\ → PATH。**从不联网**
- `ProbeVersion`：core 自己报告版本
- `Start`：进程后端 spawn + 环境变量 AETHER_*；库后端 aether_core_start + job 轮询
- 日志解析 `classify()` 集中在 process_backend.go —— Core 日志格式变化只改这一个函数

**不变式**：上层（vpn/app/UI）只依赖 coremgr.Manager 与 Session/Backend 接口，
不 import 任何具体后端；coremgr 不 import 上层。

## 连接状态机 (internal/vpn)

Disconnected → Connecting → Connected ⇄ Reconnecting → Failed(显示原因)
事件来源：coremgr 的 CoreEvent（connected/scanning/candidate/failed/stopped），
由 Manager.pump 映射到 UI 状态。envFor() 把设置翻译成 AETHER_* 变量。

## Windows 接管

- sysproxy：HKCU Internet Settings 快照/恢复 + InternetSetOptionW 广播；PAC 分流（domain/*.domain/keyword:/regexp:/full:/CIDR/private，与 core 语义一致）
- killswitch：netsh 规则组（放行 core exe/LAN/回环/WARP 网段 → 阻断出站），断开整组删除

## 本地化与无更新原则

- Core 二进制发现只查本地目录，代码中无任何仓库/Release/更新 URL
- 无自动更新逻辑、无更新服务器配置
- 升级 Core = 用户手动替换二进制 + 设置页点 Detect
