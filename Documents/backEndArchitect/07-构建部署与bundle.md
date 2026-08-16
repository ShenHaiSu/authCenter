# 07 构建部署与 Bundle

> 后端架构文档 7/8 ｜ 交叉编译、前端内嵌、Bundle 双平台产物、Windows/Linux 部署、Caddy

## 1. 目标产物形态（需求 C6）

`bundle` 是**发布目录**，承载各平台的可执行产物。由于纯 Go 跨平台 + 前端是纯静态文件：

- **后端**：分别交叉编译出 `windows/amd64` 与 `linux/amd64` 两个二进制。
- **前端**：html/css/js 无编译产物，**直接复制同一份到两个平台目录**。
- 最终 `Bundle/windows/` 与 `Bundle/linux/` 各自都是一份**完整可独立运行的发布包**（见 §4）。

```
Bundle/
├── windows/
│   ├── authcenter.exe            # Go 后端（已内嵌前端）
│   ├── web/                      # 前端静态文件副本（与二进制内嵌内容一致）
│   ├── Caddyfile.example         # 可选：Caddy 反代示例
│   └── README.txt                # 运行说明
└── linux/
    ├── authcenter                # Go 后端（已内嵌前端）
    ├── web/
    ├── authcenter.service        # systemd 单元示例
    ├── Caddyfile.example
    └── README.md
```

## 2. 前端内嵌机制（go:embed）

### 2.1 约束

`go:embed` 只能嵌入模块目录内的文件，而前端在 `FrontEnd/`（模块外）。解决方案：**构建期复制**。

### 2.2 流程

```
build 脚本
  1. 清空 BackEnd/internal/web/（保留 .gitkeep）
  2. 复制 FrontEnd/*（html/css/js）→ BackEnd/internal/web/
  3. CGO_ENABLED=0 go build ...
     // BackEnd/internal/web/embed.go:
     //   //go:embed all:web
     //   var WebFS embed.FS
  4. 产物复制到 Bundle/{windows,linux}/
```

### 2.3 开发模式

- `go run ./cmd/authcenter -web-dir ../FrontEnd`：直接从磁盘目录服务前端，改完刷新即生效，无需重新编译。

## 3. 交叉编译命令

```powershell
# Windows（在任意平台执行）
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -trimpath -ldflags "-s -w" -o Bundle/windows/authcenter.exe ./cmd/authcenter

# Linux
$env:GOOS = "linux"; $env:GOARCH = "amd64"
go build -trimpath -ldflags "-s -w" -o Bundle/linux/authcenter ./cmd/authcenter
```

> 关键：`CGO_ENABLED=0`（需求 C1 红线）+ `modernc.org/sqlite`（纯 Go 驱动）保证跨平台无编译障碍。如需 linux/arm64 追加 `GOARCH=arm64` 即可。

## 4. Bundle 脚本（build.ps1 / build.sh）

仓库根目录提供两个等价脚本，任一平台运行均可产出**两个平台**的完整 Bundle（内含两次交叉编译）：

```
build.ps1（Windows PowerShell） / build.sh（Linux bash）
步骤：
  1. $VERSION = git describe --tags --always（无 tag 则取 commit）
  2. 复制前端：robocopy/Copy-Item FrontEnd → BackEnd/internal/web/
  3. 交叉编译 windows/amd64 → Bundle/windows/authcenter.exe
  4. 交叉编译 linux/amd64   → Bundle/linux/authcenter
  5. 复制前端静态文件 → Bundle/windows/web/ 与 Bundle/linux/web/（前后端产物同时复制，C6）
  6. 复制部署辅助文件（Caddyfile.example / authcenter.service / README）
  7. 输出产物清单与 SHA256 校验和（Bundle/SHA256SUMS.txt）
```

要点：
- 步骤 5 是需求 C6 的落点：**两个平台目录都同时包含后端二进制与前端静态文件**。
- `go vet ./...` 在步骤 2 后先跑一遍，失败即中止。
- 产物命名带版本（可选）：`authcenter_0.1.0_windows_amd64.exe` 亦可，由脚本参数控制。

## 5. 部署

### 5.1 Windows

```powershell
# 前台运行
.\authcenter.exe -data-dir .\data
# 首次启动控制台会打印初始 admin 密码，同时写入 data\auth.log

# 注册为服务（可选，需 nssm）
nssm install AuthCenter "C:\path\authcenter.exe" -data-dir "C:\path\data"
nssm start AuthCenter
```

- 开机自启/崩溃重启：任务计划程序 或 NSSM。
- 防火墙：**无需开放入站端口**（仅监听 127.0.0.1）。

### 5.2 Linux（systemd）

```ini
# /etc/systemd/system/authcenter.service
[Unit]
Description=AuthCenter Authentication Service
After=network.target

[Service]
Type=simple
User=authcenter
WorkingDirectory=/opt/authcenter
ExecStart=/opt/authcenter/authcenter -data-dir /opt/authcenter/data
Restart=on-failure
RestartSec=3
# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now authcenter
journalctl -u authcenter -f   # 查看日志（含首次 admin 密码，见 auth.log）
```

### 5.3 Caddy（HTTPS 出口）

```caddyfile
# 公网域名
auth.example.com {
    reverse_proxy 127.0.0.1:53779
}

# 或局域网内网（自签证书）
# auth.lan { tls internal; reverse_proxy 127.0.0.1:53779 }
```

## 6. 数据目录与运维

| 项 | 说明 |
|----|------|
| 目录 | 默认 `data/`（可用 `-data-dir` 覆盖）；含 `authcenter.db`、`auth.log` |
| 备份 | 停服或使用 `sqlite3 .backup`；备份须与 `AUTHCENTER_JWT_SECRET`（若手动设置）一并保存 |
| 升级 | 停服 → 替换二进制（数据目录不动）→ 启动（自动迁移建表）→ 验证 `/api/v1/admin/me` |
| 健康检查 | `GET /healthz`（返回 200 "ok"，不写审计，供 Caddy/systemd 探测） |

> `GET /healthz` 在《05》未列出，此处补充为运维专用公开接口。

## 7. 发布检查清单

- [ ] `CGO_ENABLED=0` 双平台编译通过，`go vet` 无告警
- [ ] `Bundle/windows` 与 `Bundle/linux` 均含：后端二进制 + `web/` 前端副本 + 部署辅助文件
- [ ] 在干净目录解包运行：首次启动打印 admin 密码、`data/` 自动创建
- [ ] 浏览器访问 `http://127.0.0.1:53779` 能打开登录页并完成登录
- [ ] 外部项目用 curl 调用 `/api/v1/authenticate` 认证成功/失败符合预期
- [ ] 生成 `SHA256SUMS.txt` 并随发布附上
