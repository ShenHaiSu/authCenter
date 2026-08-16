# AuthCenter — 中心认证服务（Linux 发布包）

后端架构文档：`Documents/backEndArchitect/07-构建部署与bundle.md`

## 内容清单

| 文件 | 说明 |
|------|------|
| `authcenter` | 后端主程序（已内嵌前端静态资源，单文件运行） |
| `web/` | 前端静态文件副本（与二进制内嵌内容一致，仅供核对） |
| `authcenter.service` | systemd 单元示例 |
| `Caddyfile.example` | Caddy 反代示例（对外 HTTPS 出口，可选） |

## 快速开始

```bash
# 1. 放到专用目录并创建运行用户
sudo mkdir -p /opt/authcenter
sudo useradd -r -s /usr/sbin/nologin authcenter
sudo cp authcenter /opt/authcenter/

# 2. 首次前台启动观察初始 admin 密码（打印到控制台，并写入 data/auth.log）
cd /opt/authcenter
sudo -u authcenter ./authcenter -data-dir ./data
#    请立即保存密码——之后不再展示（重启幂等，不会重复生成）

# 3. 注册 systemd 服务
sudo cp authcenter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now authcenter
journalctl -u authcenter -f   # 首次启动日志含 admin 密码
```

浏览器访问 `http://127.0.0.1:53779`，用 admin + 初始密码登录。

## 运维

- 健康检查：`curl http://127.0.0.1:53779/healthz` → `ok`
- 备份：停服后备份 `data/`，或 `sqlite3 data/authcenter.db ".backup backup.db"`；
  若通过环境变量 `AUTHCENTER_JWT_SECRET` 手动设置过密钥，备份必须与它一并保存。
- 升级：停服 → 替换 `authcenter`（data 目录不动）→ 启动（自动迁移建表）→
  验证 `GET /api/v1/admin/me`。

## 安全提示

- 仅监听 `127.0.0.1:53779`（HTTP）；对外 HTTPS 一律用 Caddy 反代
  （`Caddyfile.example`），不要在 AuthCenter 内开启 TLS。
- systemd 单元已做加固：`NoNewPrivileges` / `ProtectSystem=strict` /
  `ProtectHome` / `PrivateTmp`（数据目录 0700、db 文件 0600）。
- 密钥泄露时可在管理界面立即吊销并轮换，审计页可追溯该密钥全部认证记录。
