# 05 API 接口设计

> 后端架构文档 5/8 ｜ 全部接口定义、错误码、审计事件映射

## 1. 通用约定

| 项 | 约定 |
|----|------|
| Base URL | 本机：`http://127.0.0.1:53779`；对外：Caddy 反代域名（如 `https://auth.example.com`） |
| 编码 | 请求/响应均为 `application/json; charset=utf-8` |
| 时间 | ISO8601 UTC，如 `2026-01-01T00:00:00Z`；过期时间可为 `null`（永不过期） |
| 鉴权 | 管理 API：会话 cookie `auth_session`（httpOnly）；认证 API：无 |
| 请求体上限 | 1MB |
| 响应结构 | 成功 `{code:0, message:"ok", data:{...}}`；失败 `{code, message, request_id}` |
| 幂等 | 创建类接口不幂等（每次生成新资源）；`rotate` 不幂等（每次生成新密钥） |
| 版本 | 路径前缀 `/api/v1`，破坏性变更升 v2 |

## 2. 错误码总表

| HTTP | 业务码 | 说明 |
|------|--------|------|
| 200 | 0 | 成功 |
| 400 | 20001 | 参数缺失/非法（invalid_parameter） |
| 400 | 20002 | JSON 解析失败（invalid_json） |
| 400 | 20003 | 校验失败（validation_failed，附字段明细） |
| 401 | 20101 | 用户名或密码错误（bad_credentials） |
| 401 | 20102 | 账号已停用（account_disabled） |
| 401 | 20103 | 会话缺失或过期（session_expired / unauthorized） |
| 403 | 20104 | 无权限 |
| 404 | 20200 | 资源不存在（project_not_found / key_not_found） |
| 409 | 20201 | 名称冲突（name_conflict） |
| 409 | 20202 | 资源状态不允许（如删除已启用密钥需先禁用） |
| 429 | 10009 | 触发限流（rate_limited） |
| 500 | 50000 | 服务器内部错误 |

**认证接口专用**（HTTP 一律 200，业务结果放 body，便于客户端统一解析）：

| 业务码 | 说明 |
|--------|------|
| 0 | authenticated=true |
| 10001 | 项目不存在（project_not_found） |
| 10002 | 项目已停用（project_disabled） |
| 10003 | 版本过低（version_too_old） |
| 10004 | 密钥不存在（key_not_found） |
| 10005 | 密钥已停用（key_disabled） |
| 10006 | 密钥已过期（key_expired） |
| 10007 | 指纹不匹配（fingerprint_mismatch） |
| 10008 | 未绑定指纹但系统要求绑定（fingerprint_required） |
| 10009 | 限流（rate_limited） |

## 3. 对外认证 API（公开）

### 3.1 认证

```
POST /api/v1/authenticate
```

请求：

```jsonc
{
  "project_name": "my-service",      // 必填，项目名
  "version": "1.2.3",                // 必填，项目版本号（语义化建议）
  "fingerprint": "a1b2c3d4...",      // 必填，客户端指纹（见《06》§4）
  "key": "Kx8...40位密钥...",          // 必填，分配的密钥
  "issue_token": false               // 可选，true 时签发 JWT（决策 D1）
}
```

响应（成功，`code:0`）：

```jsonc
{
  "code": 0,
  "message": "ok",
  "data": {
    "authenticated": true,
    "project": { "name": "my-service", "current_version": "1.2.3" },
    "server_time": "2026-01-01T00:00:00Z",
    "token": null                        // issue_token=true 时为：
    // { "token": "eyJ...", "algorithm": "HS256", "expires_at": "2026-01-02T00:00:00Z" }
  }
}
```

响应（失败，`code` 取表 2，HTTP 仍为 200）：

```jsonc
{
  "code": 10006,
  "message": "密钥已过期",
  "data": { "authenticated": false, "reason": "key_expired" },
  "request_id": "..."
}
```

> 设计说明：认证结果放业务码 + `data.authenticated`，客户端只看 `code==0` 即通过，无需依赖 HTTP 状态码。

限流：默认每 IP 100 次/分钟（可配置）。审计：成功 `auth.authenticate`，失败 `auth.authenticate_failed`（detail 含 reason、fingerprint、version）。

## 4. 管理 API（需会话）

> 除 4.1 登录外，均需 `auth_session` cookie。

### 4.1 登录 / 登出 / 当前用户 / 改密

```
POST /api/v1/admin/login
req:  { "username": "admin", "password": "..." }
resp: { "code": 0, "data": { "user": { "username":"admin", "last_login_at":"..." } } }
      // Set-Cookie: auth_session=<token>; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800
失败: 401/20101 或 401/20102
审计: admin.login / admin.login_failed
```

```
POST /api/v1/admin/logout          → 删除会话 + 清 cookie；审计 admin.logout
GET  /api/v1/admin/me              → { "user": { "username", "created_at", "last_login_at" } }
PUT  /api/v1/admin/password
req:  { "old_password": "...", "new_password": "..." }   // 新密码 ≥ 12 位
resp: 200；并使该用户全部会话失效（需重新登录）；审计 admin.password_change
```

### 4.2 项目

```
GET  /api/v1/projects?page=1&size=20&q=&active=    → { items:[{id,name,description,current_version,min_version,is_active,key_count,created_at}], total, page, size }
POST /api/v1/projects
req:  { "name":"my-service", "description":"", "current_version":"1.0.0", "min_version":null }
resp: 201 { project }；409/20201 名称冲突；审计 project.create
GET  /api/v1/projects/{id}                          → { project, keys:[...] }
PUT  /api/v1/projects/{id}
req:  { "description":"", "current_version":"1.2.0", "min_version":null, "is_active":true }
resp: 200；审计 project.update / project.enable / project.disable
DELETE /api/v1/projects/{id}                        → 204；审计 project.delete（级联删密钥，先二次确认）
```

### 4.3 密钥

```
GET  /api/v1/projects/{id}/keys?page=&size=&active=  → { items:[{id,project_id,name,has_fingerprint,fingerprint,expires_at,is_active,last_used_at,last_used_ip,created_at}], total }
     // 注意：列表永不返回 key_value 明文（只返回 has_fingerprint 布尔）
POST /api/v1/projects/{id}/keys
req:  { "name":"生产环境", "expires_at":"2027-01-01T00:00:00Z"|null, "fingerprint":"a1b2..."|null }
resp: 201 { key:{...}, "key_value":"Kx8...40位..." }   // key_value 仅此一次返回
审计: key.create
PUT  /api/v1/keys/{id}
req:  { "name":"", "expires_at":"", "fingerprint":"", "is_active":true }  // 传 null 字段=不改动
resp: 200 { key }；审计 key.update / key.enable / key.disable
POST /api/v1/keys/{id}/rotate
resp: 200 { "new_key": {id, key_value(仅一次), expires_at}, "old_key_grace_until":"2026-01-08T00:00:00Z" }
审计: key.rotate
DELETE /api/v1/keys/{id}    → 204（吊销，立即失效）；审计 key.delete
```

### 4.4 审计日志

```
GET /api/v1/audit-logs?page=1&size=20&event_type=&result=&actor=&from=&to=&q=
resp: { items:[{id,event_time,event_type,actor_type,actor_name,target_type,target_name,result,detail,ip,request_id}], total, page, size }
```

### 4.5 仪表盘统计（P2，先占位）

```
GET /api/v1/stats
resp: { "projects": n, "active_keys": n, "expiring_keys_7d": n, "auth_today": {total, success, failure} }
```

## 5. 审计事件映射表

| API | 成功事件 | 失败事件 |
|-----|----------|----------|
| POST /authenticate | auth.authenticate | auth.authenticate_failed |
| POST /admin/login | admin.login | admin.login_failed |
| POST /admin/logout | admin.logout | — |
| PUT /admin/password | admin.password_change | — |
| POST /projects | project.create | — |
| PUT /projects/{id} | project.update / .enable / .disable | — |
| DELETE /projects/{id} | project.delete | — |
| POST /projects/{id}/keys | key.create | — |
| PUT /keys/{id} | key.update / .enable / .disable | — |
| POST /keys/{id}/rotate | key.rotate | — |
| DELETE /keys/{id} | key.delete | — |
| 启动/关闭 | system.startup / system.shutdown | — |
| admin 初始化 | system.admin_initialized | — |
| 密钥加密迁移（hash 回填 / 启用加密） | system.key_encryption_migrated | — |
| 密钥加密启动自检失败 | — | system.key_encryption_verify_failed |
| 审计清理 | system.audit_cleanup | — |
| 修改设置 | settings.update | — |

## 6. 系统设置 API（F-019 审计保留策略 / F-021 密钥存储加密）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/settings` | 白名单设置项 + 审计用量 + 密钥加密状态（**永不返回 jwt_secret 与主密钥**） |
| PUT | `/api/v1/settings` | 更新保留策略（`audit_retention_days` / `audit_cleanup_interval_hours` / `audit_min_keep_rows`） |
| POST | `/api/v1/settings/audit/cleanup-now` | 手动立即执行一轮审计清理 |
| POST | `/api/v1/settings/audit/checkpoint` | 回收 WAL 空间 |
| POST | `/api/v1/settings/key-encryption/enable` | **F-021 启用密钥存储加密**（破坏性，需二次确认；无 disable） |

`GET /api/v1/settings` 中与 F-021 相关的响应片段：

```jsonc
"settings": {
  "key_encryption_enabled": true,
  "key_encryption_version": "aes-256-gcm-v1",
  "key_encrypted_count": 12,
  "key_hash_backfill_state": "done"
},
"key_encryption": {
  "master_key_configured": true,   // 仅布尔，绝不返回密钥或其哈希
  "mode": "encrypted",             // encrypted | plaintext
  "encrypted_count": 12,
  "total_keys": 15,
  "pending_hash_rows": 0
}
```

`POST /api/v1/settings/key-encryption/enable`：

| 情况 | 响应 |
|------|------|
| env 未提供主密钥 | 409 / 20202「未配置 AUTHCENTER_KEY_ENC_KEY，无法启用加密」 |
| 已是加密模式 | 409 / 20202「密钥存储已处于加密模式」 |
| `key_hash` 回填未完成 | 409 / 20202「存在 N 行尚未回填 key_hash…」 |
| 成功 | 200 `{ "encrypted_rows": N, "duration_ms": M, "mode": "encrypted" }` + 审计 `system.key_encryption_migrated` |

## 7. 前端页面 → API 映射（速查）

| 页面 | 调用 API |
|------|----------|
| 登录页 | POST /admin/login；GET /admin/me（校验会话） |
| 仪表盘 | GET /stats；GET /audit-logs（最近事件） |
| 项目管理 | GET/POST /projects；GET/PUT/DELETE /projects/{id} |
| 密钥管理 | GET /projects/{id}/keys；POST /projects/{id}/keys；PUT /keys/{id}；POST /keys/{id}/rotate；DELETE /keys/{id} |
| 审计日志 | GET /audit-logs |
| 修改密码 | PUT /admin/password |
| 系统设置 | GET/PUT /settings；POST /settings/audit/cleanup-now；POST /settings/key-encryption/enable |
