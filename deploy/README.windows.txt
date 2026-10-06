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

密钥存储加密（F-021，可选）
----------------------------
  1. 生成 32 字节主密钥（base64），另存到密码管理器：
       $env:AUTHCENTER_KEY_ENC_KEY = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }))
       $env:AUTHCENTER_KEY_ENC_KEY          # 记下这个值
  2. 以系统环境变量方式持久化（需管理员 PowerShell）：
       [Environment]::SetEnvironmentVariable('AUTHCENTER_KEY_ENC_KEY', $env:AUTHCENTER_KEY_ENC_KEY, 'Machine')
  3. 重启服务后，控制台日志应出现「主密钥已加载，当前库中暂无密文密钥」。
  - 配置主密钥后新生成的密钥即以 AES-256-GCM 密文落盘；存量明文密钥的转换在
    管理界面「系统设置 → 密钥存储加密 → 启用密钥加密」（破坏性操作，需二次确认）。
  - 主密钥丢失 = 全部项目密钥不可恢复；主密钥不匹配会导致启动失败（fail-fast）。
  - 回滚只能用「启用加密前的 data\ 备份」，换回旧程序无法读取密文库。

注意
----
- 服务仅监听 127.0.0.1:53779（HTTP），无需开放入站防火墙端口。
- 对外 HTTPS 请使用 Caddy 反代（见 Caddyfile.example）。
- 健康检查：GET http://127.0.0.1:53779/healthz → ok。
- 备份 = data\authcenter.db + data\auth.log；若通过环境变量
  AUTHCENTER_JWT_SECRET 手动设置过密钥，备份必须与它一并保存。
- 升级：停服 → 替换 authcenter.exe（data 目录不动）→ 启动（自动迁移建表）。
