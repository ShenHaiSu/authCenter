# AuthCenter — 中心认证服务

> 内部中心认证服务：纯 Go 后端，仅监听 `127.0.0.1:53779`（HTTP，HTTPS 由外置 Caddy 反代）；其他项目程序携带「项目名 + 版本号 + 指纹 + 分配密钥」调用认证接口，管理员通过轻量 Web 界面管理项目与密钥。当前处于 **M1 骨架阶段**。

## 目录结构

```
authCenter/
├── BackEnd/                 # Go 后端模块（独立 go module）
│   ├── cmd/authcenter/      # 入口：装配 config → db → service → http server
│   └── internal/            # config / database / model / store / service / httpapi / web
├── FrontEnd/                # 前端静态资源（html/css/js，M4 提供）
├── Bundle/                  # 双平台发布目录（windows/ 与 linux/，M5 产出）
├── Documents/               # 设计文档集（见下）
└── build.ps1 / build.sh     # 构建与 bundle 脚本（M5 提供）
```

## 快速开始（M1）

```powershell
cd BackEnd
go build -o authcenter.exe ./cmd/authcenter
.\authcenter.exe -data-dir .\data
```

- 首次启动会在**控制台打印初始 admin 密码**（30 位随机），同时写入 `data/auth.log`（仅一次，请立即保存）。
- 重启幂等：admin 已存在则跳过，密码不变；`settings.jwt_secret` 自动生成并复用（可用环境变量 `AUTHCENTER_JWT_SECRET` 覆盖）。
- 健康检查：`GET http://127.0.0.1:53779/healthz` → `ok`。

## 常用命令

```powershell
cd BackEnd
go test ./...              # 全部测试
go vet ./...               # 静态检查
$env:CGO_ENABLED="0"; go build ./...   # cgo 红线验证
```

## 配置项（flag）

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-listen` | `127.0.0.1:53779` | 监听地址（需求固定本机） |
| `-data-dir` | `data` | 数据目录（db + auth.log） |
| `-log-level` | `info` | debug/info/warn/error |
| `-log-format` | `text` | text/json |
| `-web-dir` | 空（内嵌） | 开发模式：从磁盘目录服务前端（M4 起生效） |

环境变量：`AUTHCENTER_JWT_SECRET`（覆盖 JWT secret，备份恢复场景必需）。

## 设计文档

- `Documents/README.md` — 项目总览、决策记录（R1-R5、D1-D4）、里程碑计划（M1-M6）
- `Documents/backEndArchitect/01~08` — 需求/架构/数据库/模块/API/安全/构建/测试验收
- `Documents/frontEndArchitect/01~02` — 前端总体设计与页面交互
- `Documents/backEndArchitect/09-M1开发验收与基准测试报告.md` — M1 阶段验收与性能基准

## 里程碑进度

| 里程碑 | 内容 | 状态 |
|--------|------|------|
| M1 | 后端骨架：config/database/启动流程/admin 初始化/日志 | ✅ 完成 |
| M2 | 管理后端：会话、项目、密钥、审计 | ✅ 完成 |
| M3 | 对外认证 API + 可选令牌 + 限流 + 全审计 | ⬜ 待开发 |
| M4 | 前端管理界面 | ⬜ 待开发 |
| M5 | 构建脚本、Bundle 双平台产物、部署文档 | ⬜ 待开发 |
| M6 | 测试补全与验收 | ⬜ 待开发 |
