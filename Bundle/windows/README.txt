AuthCenter — 中心认证服务（Windows 发布包）
==========================================

内容清单
--------
  authcenter.exe      后端主程序（已内嵌前端静态资源，单文件运行）
  web/                前端静态文件副本（与二进制内嵌内容一致，仅供核对）
  Caddyfile.example   Caddy 反代示例（对外 HTTPS 出口，可选）

快速开始
--------
1. 将本目录复制到专用位置（如 C:\AuthCenter），打开 PowerShell 运行：
       .\authcenter.exe -data-dir .\data
2. 首次启动控制台会打印初始 admin 密码（30 位随机），同时写入 data\auth.log；
   请立即保存——之后不再展示（重启幂等，不会重复生成）。
3. 浏览器访问 http://127.0.0.1:53779 ，用 admin + 初始密码登录。

注册为系统服务（可选，需 NSSM）
------------------------------
  nssm install AuthCenter "C:\AuthCenter\authcenter.exe" -data-dir "C:\AuthCenter\data"
  nssm start AuthCenter

注意
----
- 服务仅监听 127.0.0.1:53779（HTTP），无需开放入站防火墙端口。
- 对外 HTTPS 请使用 Caddy 反代（见 Caddyfile.example）。
- 健康检查：GET http://127.0.0.1:53779/healthz → ok。
- 备份 = data\authcenter.db + data\auth.log；若通过环境变量
  AUTHCENTER_JWT_SECRET 手动设置过密钥，备份必须与它一并保存。
- 升级：停服 → 替换 authcenter.exe（data 目录不动）→ 启动（自动迁移建表）。
