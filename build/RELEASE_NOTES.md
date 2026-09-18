## AetherVPN v1.1.0

> 基于 [Aether](https://github.com/CluvexStudio/Aether) 核心构建的 Windows 图形客户端。

### 下载

| 文件 | 说明 |
| --- | --- |
| `AetherVPN-1.1.0-win-x64.zip` | 便携版：解压后双击 `AetherVPN.exe` 即可运行 |
| `AetherVPN-Setup-1.1.0.exe` | 安装版：安装完成后自动创建桌面快捷方式 |

两个版本均自带配套的 Aether 核心，无需另行下载。

### 功能

- 支持 MASQUE（HTTP/2、HTTP/3）、MASQUE-in-MASQUE、WireGuard、Gool 等传输方式
- 实时流量图表、节点延迟测试与自动选点、按规则分流
- 系统代理接管与 Kill Switch 防泄漏
- 启动自检 + 手动「检查更新」，更新全程在软件内完成，不跳转浏览器

### 本次更新

- 更新机制改为**整合更新包**：GUI 客户端与 Aether 核心捆绑发布、一起替换，
  不会出现「核心已更新而界面未更新」的不兼容情况
- 发布方式改为 GitHub Release，不再把 exe 放在仓库根目录
- 新增 Windows 安装程序，支持桌面与开始菜单快捷方式
- 关于页：作者 xiaohe，附 GitHub / Telegram / Email 官方彩色图标

### 授权与许可

- **本客户端（GUI）**
  - 由 **xiaohe** 开发并发布
  - 采用**试用授权**：自首次启动起可免费试用 **7 天**
  - 到期后软件将提示续期，授权状态与到期时间由本仓库的 `version.json` 远程控制
  - 续期或获取授权请联系作者（见下方联系方式）
- **Aether 核心**
  - 本软件内置的是 [Aether](https://github.com/CluvexStudio/Aether) 核心二进制文件
  - 该核心的版权与许可证归原作者 **CluvexStudio** 所有，本项目仅作调用与随包分发
  - 核心更新始终与 GUI 版本配套发布，不会单独变更
- 请遵守所在地法律法规，以及所访问网络服务的使用条款

### 联系我们

| 渠道 | 地址 |
| --- | --- |
| 作者 | xiaohe |
| GitHub 主页 | https://github.com/hezhanleiok |
| 项目主页 | https://github.com/hezhanleiok/aether |
| Telegram | https://t.me/xiaoheok |
| Email | hezhanleiok@gmail.com |
