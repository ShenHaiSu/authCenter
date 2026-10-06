# AuthCenter — 中心认证服务

> 内部中心认证服务：纯 Go 后端，仅监听 `127.0.0.1:53779`（HTTP，HTTPS 由外置 Caddy 反代）；其他项目程序携带「项目名 + 版本号 + 指纹 + 分配密钥」调用认证接口，管理员通过轻量 Web 界面管理项目与密钥。**M1-M6 全部完成**，发布产物见 `Bundle/`。

## 目录结构

```
authCenter/
├── BackEnd/                 # Go 后端模块（独立 go module）
│   ├── cmd/authcenter/      # 入口：装配 config → db → service → http server
│   └── internal/            # config / database / model / store / service / httpapi / web（go:embed）
├── FrontEnd/                # 前端静态资源（html/css/js，唯一源）
├── deploy/                  # 部署辅助文件模板（构建期复制进 Bundle）
├── Bundle/                  # 双平台发布目录（windows/ 与 linux/，由 build 脚本产出）
├── Documents/               # 设计文档集 + M1-M6 验收报告（见下）
├── build.ps1                # 一键构建双平台 Bundle（Windows PowerShell，PS5.1 兼容）
└── build.sh                 # 等价构建脚本（Linux bash）
```

## 快速开始（发布包方式）

```powershell
# 一键构建双平台完整 Bundle（CGO_ENABLED=0 交叉编译 + 前端副本 + 部署文件 + SHA256SUMS）
.\build.ps1                  # 或 ./build.sh（Linux）

# 运行 Windows 产物
cd Bundle\windows
.\authcenter.exe -data-dir .\data
```

- 首次启动会在**控制台打印初始 admin 密码**（30 位随机），同时写入 `data/auth.log`（仅一次，请立即保存）。
- 重启幂等：admin 已存在则跳过，密码不变；`settings.jwt_secret` 自动生成并复用（可用环境变量 `AUTHCENTER_JWT_SECRET` 覆盖）。
- 浏览器访问 `http://127.0.0.1:53779`，用 admin + 初始密码登录后即可管理项目、密钥、审计。
- 健康检查：`GET http://127.0.0.1:53779/healthz` → `ok`。
- 对外 HTTPS：由外置 Caddy 反代（示例见 `Bundle/{windows,linux}/Caddyfile.example`）；Linux systemd 单元示例见 `Bundle/linux/authcenter.service`。

## 开发模式

```powershell
cd BackEnd
go build -o authcenter.exe ./cmd/authcenter
.\authcenter.exe -data-dir .\data -web-dir ..\FrontEnd   # 前端从磁盘读，改完刷新即生效
```

## 常用命令

```powershell
cd BackEnd
go test ./...              # 全部测试
go vet ./...               # 静态检查
$env:CGO_ENABLED="0"; go build ./...   # cgo 红线验证
go test -bench . -benchtime 1s ./internal/...   # 性能冒烟（08 §6）
```

## 配置项（flag）

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-listen` | `127.0.0.1:53779` | 监听地址（需求固定本机） |
| `-data-dir` | `data` | 数据目录（db + auth.log） |
| `-log-level` | `info` | debug/info/warn/error |
| `-log-format` | `text` | text/json |
| `-web-dir` | 空（内嵌） | 开发模式：从磁盘目录服务前端 |

环境变量：

| 变量 | 说明 |
|------|------|
| `AUTHCENTER_JWT_SECRET` | 覆盖 JWT secret（备份恢复场景必需） |
| `AUTHCENTER_KEY_ENC_KEY` | **F-021 密钥存储加密主密钥**，`base64(32B)`；不设置则密钥以明文存储 |

主密钥生成（只保存在密码管理器 / `EnvironmentFile`，不入库、不落盘、不进日志）：

```bash
# Linux / macOS
export AUTHCENTER_KEY_ENC_KEY=$(head -c 32 /dev/urandom | base64)
# Windows PowerShell
$env:AUTHCENTER_KEY_ENC_KEY = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }))
```

> ⚠️ 启用密钥加密后，**主密钥丢失 = 全部项目密钥不可恢复**；回滚只能用「启用前的数据库备份」，
> 换回旧二进制无法读取密文库。详见 `Documents/need01/03-F021-密钥存储加密.md`。

## 密钥存储加密（F-021）

- 配置 `AUTHCENTER_KEY_ENC_KEY` 后：新生成的密钥以 **AES-256-GCM** 密文落盘
  （`api_key.key_value` 存 `base64(nonce‖ct‖tag)`，`key_value_enc=1`），客户端无感知（仍用原 40 位明文调用认证）。
- 认证主路径改为按 `hex(SHA-256(明文密钥))` 走 `key_hash` 唯一索引等值查询；存量行由后台任务分批回填。
- 启动自检（fail-fast）：`key_encryption_enabled=1` 而无主密钥、或主密钥与库中密文不匹配 → **拒绝启动**并写
  `system.key_encryption_verify_failed` 审计。
- 管理界面「系统设置 → 密钥存储加密」提供**启用**（破坏性操作，需二次确认）；**不提供关闭**（单向棘轮）。

## 设计文档

- `Documents/README.md` — 项目总览、决策记录（R1-R5、D1-D4）、里程碑计划（M1-M6）
- `Documents/backEndArchitect/01~08` — 需求/架构/数据库/模块/API/安全/构建/测试验收
- `Documents/frontEndArchitect/01~02` — 前端总体设计与页面交互
- `Documents/backEndArchitect/09~13` — M1/M3/M4/M5/M6 开发验收与基准测试报告

## 里程碑进度

| 里程碑 | 内容 | 状态 |
|--------|------|------|
| M1 | 后端骨架：config/database/启动流程/admin 初始化/日志 | ✅ 完成 |
| M2 | 管理后端：会话、项目、密钥、审计 | ✅ 完成 |
| M3 | 对外认证 API + 可选令牌 + 限流 + 全审计 | ✅ 完成 |
| M4 | 前端管理界面 | ✅ 完成 |
| M5 | 构建脚本、Bundle 双平台产物、部署文档 | ✅ 完成 |
| M6 | 安全清单核验、性能冒烟、交付文档收尾、验收矩阵 | ✅ 完成 |
