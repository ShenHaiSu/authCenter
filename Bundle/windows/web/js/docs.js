/* ============================================================
 * js/docs.js — 接入方对接文档（静态内容，无 API 调用）
 * 新界面设计 02（Documents/newInterfaceDesign/02-接入方对接文档界面设计.md）
 * 前端架构文档 02 §11
 * 单源模型：DOC_SECTIONS 为唯一事实源，页面渲染（renderDocsHtml）
 * 与 Markdown 构建（buildMarkdown）遍历同一份数据；
 * 下载成品与 attachments/AuthCenter-接入对接文档.md 逐字一致。
 * 块类型：p / steps / ul / table / code / note / h3 / h4
 * ============================================================ */

/** 行内 Markdown 渲染：先 escapeHtml，再受限还原 **粗体** 与 `行内代码`。 */
function docInline(text) {
  return escapeHtml(text)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
}

/** 从 GFM 表格文本解析表头与数据行（md 为唯一来源，页面渲染不再重复维护 rows）。 */
function parseMdTable(md) {
  const lines = md.split('\n').filter((l) => l.trim() !== '');
  const cells = (line) => line.replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
  return { headers: cells(lines[0]), rows: lines.slice(2).map(cells) };
}

/** 对接文档内容数据（唯一事实源，11 节；与后端实现逐条核对）。 */
const DOC_SECTIONS = [
  {
    id: 'overview',
    title: '一、概述与接入流程',
    blocks: [
      { type: 'p', md: 'AuthCenter 是内部中心认证服务：其他项目程序携带「项目名 + 版本号 + 指纹 + 分配密钥」调用认证接口，后端校验通过后返回认证结果（可选签发短期访问令牌）。' },
      { type: 'p', md: '接入共四步：' },
      {
        type: 'steps',
        md: [
          '1. **开户**：联系 AuthCenter 管理员创建项目（拿到唯一 `project_name`）并生成密钥（拿到 40 位 `key`，注意密钥明文仅展示一次，请立即保存）；',
          '2. **约定指纹**：与管理员确认是否绑定指纹；若绑定，客户端必须计算并携带相同的指纹；',
          '3. **调用认证接口**：程序启动时（或定时/按需）携带四要素调用 `POST /api/v1/authenticate`；',
          '4. **处理结果**：`code == 0` 即认证通过；否则按业务码排错（见「错误码速查表」）。',
        ],
      },
    ],
  },
  {
    id: 'base-url',
    title: '二、服务地址与 Base URL',
    blocks: [
      {
        type: 'table',
        md: [
          '| 环境 | Base URL |',
          '|------|----------|',
          '| 本机（开发/内网直连） | `http://127.0.0.1:53779` |',
          '| 对外（Caddy 反代 HTTPS） | `https://auth.example.com`（以管理员实际分配为准） |',
        ].join('\n'),
      },
      {
        type: 'ul',
        md: [
          '- 接口路径前缀：`/api/v1`；请求/响应均为 `application/json; charset=utf-8`；',
          '- 健康检查（连通性验证）：`GET /healthz` → HTTP 200，body 为 `ok`。',
        ],
      },
    ],
  },
  {
    id: 'authenticate',
    title: '三、认证接口 POST /api/v1/authenticate',
    blocks: [
      { type: 'h3', md: '### 3.1 请求参数（请求体 JSON）' },
      {
        type: 'table',
        md: [
          '| 字段 | 类型 | 必填 | 长度/取值 | 作用与意义 |',
          '|------|------|------|-----------|------------|',
          '| `project_name` | string | ✅ | 与管理员创建的项目名完全一致（区分大小写） | 标识调用方项目；后端按此查找项目配置（状态、版本限制） |',
          '| `version` | string | ✅ | 语义化版本建议 `主.次.修订`，如 `1.2.3` | 项目当前版本；后端与项目 `min_version` 比较，低于最低版本拒绝 |',
          '| `fingerprint` | string | ✅ | 1-128 字符，如 `sha256(机器ID)[:32]` | 客户端指纹；密钥绑定指纹时须精确匹配；系统开启强制策略时未绑定指纹的密钥一律拒绝 |',
          '| `key` | string | ✅ | 40 位 `A-Za-z0-9` | 管理员分配的密钥；后端按此查密钥状态（启用/过期/归属） |',
          '| `issue_token` | bool | ❌ 默认 `false` | `true` / `false` | 是否签发 JWT 访问令牌；仅当认证通过且为 `true` 时签发 |',
        ].join('\n'),
      },
      { type: 'h3', md: '### 3.2 请求示例' },
      {
        type: 'code',
        lang: 'jsonc',
        md: `// 仅认证
{
  "project_name": "my-service",
  "version": "1.2.3",
  "fingerprint": "a1b2c3d4e5f6a7b8c9d0",
  "key": "Kx8AbC...（40位）",
  "issue_token": false
}

// 认证并签发令牌
{
  "project_name": "my-service",
  "version": "1.2.3",
  "fingerprint": "a1b2c3d4e5f6a7b8c9d0",
  "key": "Kx8AbC...（40位）",
  "issue_token": true
}`,
      },
      { type: 'h3', md: '### 3.3 响应结构通用约定' },
      {
        type: 'ul',
        md: [
          '- 成功：`{ "code": 0, "message": "ok", "data": { ... } }`',
          '- 失败：`{ "code": <业务码>, "message": "...", "request_id": "..." }`',
          '- **注意：认证接口 HTTP 状态码一律 200**（仅服务器内部错误为 500），业务结果放在 `code` 字段，客户端应只看 `code` 判断结果，不要依赖 HTTP 状态码。',
        ],
      },
      { type: 'h3', md: '### 3.4 成功响应（code:0）data 字段' },
      {
        type: 'table',
        md: [
          '| 字段 | 类型 | 作用与意义 |',
          '|------|------|------------|',
          '| `authenticated` | bool | 恒为 `true`（认证成功时） |',
          '| `project.name` | string | 认证通过的项目名（回显，供核对） |',
          '| `project.current_version` | string | 项目当前维护版本（客户端可据此提示升级） |',
          '| `server_time` | string（ISO8601 UTC） | 服务端当前时间，用于客户端时间校准 |',
          '| `token` | object / null | `issue_token=true` 时签发令牌对象；否则为 `null` |',
        ].join('\n'),
      },
      { type: 'p', md: '成功响应示例：' },
      {
        type: 'code',
        lang: 'jsonc',
        md: `{
  "code": 0,
  "message": "ok",
  "data": {
    "authenticated": true,
    "project": { "name": "my-service", "current_version": "1.2.3" },
    "server_time": "2026-01-01T00:00:00Z",
    "token": null
    // issue_token=true 时为：
    // { "token": "eyJ...", "algorithm": "HS256", "expires_at": "2026-01-02T00:00:00Z" }
  }
}`,
      },
      { type: 'h3', md: '### 3.5 失败响应（HTTP 仍为 200）data 字段' },
      {
        type: 'table',
        md: [
          '| 字段 | 类型 | 作用与意义 |',
          '|------|------|------------|',
          '| `authenticated` | bool | 恒为 `false` |',
          '| `reason` | string | 机器可读失败原因码，与业务码一一对应（见错误码表） |',
        ].join('\n'),
      },
      { type: 'p', md: '失败响应示例：' },
      {
        type: 'code',
        lang: 'jsonc',
        md: `{
  "code": 10006,
  "message": "密钥已过期",
  "data": { "authenticated": false, "reason": "key_expired" },
  "request_id": "3f9a..."
}`,
      },
    ],
  },
  {
    id: 'error-codes',
    title: '四、错误码速查表',
    blocks: [
      { type: 'h3', md: '### 4.1 认证接口专用业务码（HTTP 一律 200）' },
      {
        type: 'table',
        md: [
          '| 业务码 | reason | 含义 | 客户端处置建议 |',
          '|--------|--------|------|----------------|',
          '| 0 | — | 认证通过 | 放行 |',
          '| 10001 | `project_not_found` | 项目不存在 | 核对 `project_name` 与管理员创建是否一致 |',
          '| 10002 | `project_disabled` | 项目已停用 | 联系管理员启用 |',
          '| 10003 | `version_too_old` | 版本低于项目最低版本 | 升级程序版本 |',
          '| 10004 | `key_not_found` | 密钥不存在或不属于该项目 | 核对 `key` 是否正确、是否属于该项目 |',
          '| 10005 | `key_disabled` | 密钥已停用 | 联系管理员启用密钥 |',
          '| 10006 | `key_expired` | 密钥已过期 | 联系管理员轮换/生成新密钥 |',
          '| 10007 | `fingerprint_mismatch` | 指纹与绑定不一致 | 核对指纹算法与取值 |',
          '| 10008 | `fingerprint_required` | 未绑定指纹但系统要求绑定 | 联系管理员绑定指纹 |',
          '| 10009 | `rate_limited` | 触发限流 | 退避重试（见「限流与审计」） |',
        ].join('\n'),
      },
      { type: 'h3', md: '### 4.2 通用错误码（带 HTTP 状态）' },
      {
        type: 'table',
        md: [
          '| HTTP | 业务码 | 含义 |',
          '|------|--------|------|',
          '| 400 | 20001 | 参数缺失/非法 |',
          '| 400 | 20002 | JSON 解析失败 |',
          '| 400 | 20003 | 校验失败 |',
          '| 500 | 50000 | 服务器内部错误 |',
        ].join('\n'),
      },
      { type: 'note', md: '> 管理 API（`20101-20104`、`20200-20202` 等）与接入方无关，此处不展开。' },
    ],
  },
  {
    id: 'check-order',
    title: '五、认证校验顺序（排错参考）',
    blocks: [
      { type: 'p', md: '后端按以下顺序校验，**失败即返回并写审计**（对外不暴露密钥归属细节）：' },
      {
        type: 'code',
        lang: '',
        md: `1  IP 限流（默认 100 次/分钟）        → 10009 rate_limited
2  项目存在（project_name 精确匹配）   → 10001 project_not_found
3  项目启用                           → 10002 project_disabled
4  版本 ≥ min_version（语义化比较）    → 10003 version_too_old
5  密钥存在（key 精确匹配）            → 10004 key_not_found
6  密钥属于该项目                      → 10004（对外不区分，审计记 key_mismatch）
7  密钥启用                           → 10005 key_disabled
8  密钥未过期                         → 10006 key_expired
9  指纹校验（绑定精确匹配/强制策略）     → 10007 / 10008
10 更新密钥最后使用时间/IP（60s 窗口）
11 写审计 success
12 可选：签发 JWT（issue_token=true）`,
      },
    ],
  },
  {
    id: 'fields',
    title: '六、字段详解',
    blocks: [
      {
        type: 'ul',
        md: [
          '- **版本比较规则**（宽松语义化）：按 `.` 分段比较数字主三段（缺省段补 0），`-beta`/`+build` 后缀忽略。例：客户端 `1.10.0` 与 `min_version=1.9` → 通过；`1.8.9` 与 `min_version=1.9` → 拒绝（`version_too_old`）。',
          '- **指纹约定**：建议 `sha256(机器唯一ID)` 取前 32 位 hex；指纹**大小写敏感**，需与管理员绑定值完全一致；绑定指纹的密钥在其他机器上使用会被拒绝（`fingerprint_mismatch`）。',
          '- **密钥生命周期**：密钥可能永不过期（`expires_at` 为 null）或带过期时间；轮换后旧密钥进入 7 天宽限期（宽限期内仍可认证），期满自动过期失效。',
        ],
      },
    ],
  },
  {
    id: 'jwt',
    title: '七、可选 JWT 令牌（issue_token=true 时）',
    blocks: [
      {
        type: 'ul',
        md: [
          '- 算法：`HS256`；issuer：`authcenter`；有效期默认 24 小时（服务端 `settings.token_ttl_seconds` 可配置）。',
          '- Claims（payload）说明：',
        ],
      },
      {
        type: 'table',
        md: [
          '| 字段 | 含义 |',
          '|------|------|',
          '| `sub` | `project:{project_name}`，如 `project:my-service` |',
          '| `pid` | 项目 ID（int） |',
          '| `kid` | 密钥 ID（int，用于追踪该令牌由哪个密钥签发） |',
          '| `ver` | 认证时的项目版本 |',
          '| `iat` / `exp` | 签发时间 / 过期时间（Unix 秒） |',
          '| `jti` | 唯一令牌 ID（随机） |',
          '| `iss` | `authcenter` |',
        ].join('\n'),
      },
      {
        type: 'ul',
        md: [
          '- **校验方式**：调用方可自持 `jwt_secret`（由管理员通过环境变量 `AUTHCENTER_JWT_SECRET` 共享）本地校验签名 + `exp` + `iss`；或每次调用认证接口换取新令牌。',
          '- **安全提示**：令牌是短期凭证，不要在日志中打印；用于后续受保护接口时放入请求头 `Authorization: Bearer <token>`。',
        ],
      },
    ],
  },
  {
    id: 'rate-audit',
    title: '八、限流与审计',
    blocks: [
      {
        type: 'ul',
        md: [
          '- **认证限流**：每 IP 每分钟 100 次（服务端可配 `rate_limit_auth_per_min`）；超限返回 `10009 rate_limited`，客户端应退避重试（建议指数退避，至少等待 1 分钟窗口）。',
          '- **审计**：每次认证（成功/失败）都会写入审计日志：成功 `auth.authenticate`、失败 `auth.authenticate_failed`（detail 含失败原因、版本、指纹、IP；**不含密钥明文**），管理员可在管理界面审计页追溯。',
        ],
      },
    ],
  },
  {
    id: 'examples',
    title: '九、调用示例',
    blocks: [
      { type: 'h3', md: '### curl' },
      {
        type: 'code',
        lang: 'bash',
        md: `# 仅认证
curl -s -X POST http://127.0.0.1:53779/api/v1/authenticate \\
  -H 'Content-Type: application/json' \\
  -d '{"project_name":"my-service","version":"1.2.3","fingerprint":"a1b2c3d4...","key":"Kx8AbC..."}'
# 返回示例：{"code":0,"message":"ok","data":{"authenticated":true,...}}`,
      },
      { type: 'h3', md: '### Python 3（标准库 urllib）' },
      {
        type: 'code',
        lang: 'python',
        md: `import json, urllib.request

payload = {
    "project_name": "my-service",
    "version": "1.2.3",
    "fingerprint": "a1b2c3d4",
    "key": "Kx8AbC...",
    "issue_token": False,
}
req = urllib.request.Request(
    "http://127.0.0.1:53779/api/v1/authenticate",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(req) as r:
    data = json.load(r)
if data["code"] == 0:
    print("认证通过，当前版本:", data["data"]["project"]["current_version"])
else:
    print("认证失败:", data["code"], data["data"]["reason"])`,
      },
      { type: 'h3', md: '### Go（标准库）' },
      {
        type: 'code',
        lang: 'go',
        md: `package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
)

func main() {
    body, _ := json.Marshal(map[string]any{
        "project_name": "my-service",
        "version":      "1.2.3",
        "fingerprint":  "a1b2c3d4",
        "key":          "Kx8AbC...",
        "issue_token":  false,
    })
    resp, err := http.Post("http://127.0.0.1:53779/api/v1/authenticate",
        "application/json", bytes.NewReader(body))
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    var out struct {
        Code int \`json:"code"\`
        Data struct {
            Authenticated bool \`json:"authenticated"\`
        } \`json:"data"\`
    }
    _ = json.NewDecoder(resp.Body).Decode(&out)
    // 一律以 code==0 判断，不要依赖 HTTP 状态码（认证失败时 HTTP 仍为 200）
    if out.Code == 0 && out.Data.Authenticated {
        fmt.Println("认证通过")
    }
}`,
      },
      { type: 'note', md: '> 通用要点：**一律解析 JSON body 的 `code` 判断结果**；网络错误 / HTTP 5xx 视为服务不可用，做重试。' },
    ],
  },
  {
    id: 'troubleshoot',
    title: '十、常见失败排查表',
    blocks: [
      {
        type: 'table',
        md: [
          '| 现象 | 原因 | 处理 |',
          '|------|------|------|',
          '| `10001 project_not_found` | 项目名拼写不一致 / 项目被删除 | 与管理员核对项目名 |',
          '| `10003 version_too_old` | 版本号低于项目 `min_version` | 升级客户端版本号（保持与发布版本一致） |',
          '| `10006 key_expired` | 密钥过期 / 轮换后旧密钥超出宽限期 | 联系管理员申请新密钥 |',
          '| `10007 fingerprint_mismatch` | 指纹不一致（换机器 / 大小写 / 算法差异） | 统一指纹算法与取值，或让管理员解绑指纹 |',
          '| `10009 rate_limited` | 频繁调用（>100 次/分钟/IP） | 退避重试、合并请求 |',
          '| 连不上 / 超时 | 服务未启动 / 端口不通 / Caddy 配置错误 | `curl http://127.0.0.1:53779/healthz` 应返回 `ok` |',
        ].join('\n'),
      },
    ],
  },
  {
    id: 'security',
    title: '十一、安全建议',
    blocks: [
      {
        type: 'steps',
        md: [
          '1. 密钥是敏感凭证：写入程序配置 / 环境变量，**勿硬编码进源码、勿提交版本库**；',
          '2. 定期轮换密钥（管理员侧操作），轮换宽限期 7 天，两端做好新旧切换；',
          '3. 高价值项目绑定指纹，防止密钥被拷贝到其他机器使用；',
          '4. 认证请求走 HTTPS（对外经 Caddy 反代），避免密钥明文在公网传输；',
          '5. 令牌（JWT）短期有效，按需申请（`issue_token` 默认关闭），不要在日志中打印；',
          '6. 关注审计页中自己项目的认证失败记录，异常尝试及时上报管理员。',
        ],
      },
    ],
  },
];

/** 渲染单个内容块 → HTML 字符串（页面侧，md 原样过转义）。 */
function docsBlockHtml(b) {
  switch (b.type) {
    case 'p':
      return `<p>${docInline(b.md)}</p>`;
    case 'steps':
      return `<ol class="guide-steps">${b.md.map((l) => `<li>${docInline(l.replace(/^\d+\.\s*/, ''))}</li>`).join('')}</ol>`;
    case 'ul':
      return `<ul class="guide-list">${b.md.map((l) => `<li>${docInline(l.replace(/^-\s*/, ''))}</li>`).join('')}</ul>`;
    case 'table': {
      const { headers, rows } = parseMdTable(b.md);
      return `<div class="table-wrap"><table class="table">
        <thead><tr>${headers.map((h) => `<th>${docInline(h)}</th>`).join('')}</tr></thead>
        <tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${docInline(c)}</td>`).join('')}</tr>`).join('')}</tbody>
      </table></div>`;
    }
    case 'code':
      return `<pre class="code-block"><code>${escapeHtml(b.md)}</code></pre>`;
    case 'note':
      return `<div class="callout callout-tip">${docInline(b.md.replace(/^>\s*/, ''))}</div>`;
    case 'h3':
      return `<h3>${docInline(b.md.replace(/^###\s*/, ''))}</h3>`;
    case 'h4':
      return `<h4>${docInline(b.md.replace(/^####\s*/, ''))}</h4>`;
    default:
      return '';
  }
}

/** 按块类型拼接 MD 原文（下载用；与页面渲染同一数据源）。 */
function pushMdBlock(lines, b) {
  switch (b.type) {
    case 'p':
    case 'note':
    case 'h3':
    case 'h4':
      lines.push(b.md, '');
      break;
    case 'steps':
    case 'ul':
      b.md.forEach((l) => lines.push(l));
      lines.push('');
      break;
    case 'table':
      lines.push(b.md, '');
      break;
    case 'code':
      lines.push('```' + (b.lang || ''), b.md, '```', '');
      break;
    default:
      break;
  }
}

/**
 * 构建完整 Markdown：标题 + 版本行 + 各节（与页面渲染同源）。
 * 成品与 attachments/AuthCenter-接入对接文档.md 逐字一致。
 */
function buildMarkdown() {
  const lines = [];
  lines.push('# AuthCenter 接入对接文档', '');
  lines.push('> 版本：v1.0（与当前部署的 AuthCenter 一致）｜ 适用于项目接入方开发人员');
  lines.push('> 内容与 AuthCenter 管理界面「对接文档」页一致，可离线使用。');
  lines.push('', '---', '');
  DOC_SECTIONS.forEach((sec, i) => {
    lines.push(`## ${sec.title}`, '');
    sec.blocks.forEach((b) => pushMdBlock(lines, b));
    if (i < DOC_SECTIONS.length - 1) lines.push('---', '');
  });
  return lines.join('\n');
}

/** 下载：Blob + ObjectURL + 隐藏 <a> 触发；加 BOM 防 Windows 记事本中文乱码。 */
function downloadDoc() {
  try {
    const md = buildMarkdown();
    const blob = new Blob(['\ufeff' + md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'AuthCenter-接入对接文档.md';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast('对接文档已下载', 'success');
  } catch (err) {
    toastError(err);
  }
}

/** 渲染对接文档视图（顶部卡片 + 左 TOC + 右内容 + 底部下载区）。 */
function loadDocs() {
  const root = document.getElementById('docs-root');
  try {
    root.innerHTML = `
      <div class="card">
        <div class="card-title">🔌 接入方对接文档
          <button class="btn btn-primary" id="docs-download-btn">⬇ 下载 Markdown 文档</button>
        </div>
        <div class="form-hint">本文档用于其他项目对接 AuthCenter 认证后端；页面内容与下载的 Markdown 完全一致（同一数据源，可离线使用）。</div>
        <div class="toolbar" style="margin-top:12px;margin-bottom:0;">
          <span class="badge badge-info">文件：AuthCenter-接入对接文档.md</span>
          <span class="form-hint">UTF-8 · GitHub 风格 Markdown；建议下载后随项目代码入库，方便离线查阅。</span>
        </div>
      </div>

      <div class="guide-layout">
        <nav class="guide-toc">
          ${DOC_SECTIONS.map((s) => `<a href="#docs-${s.id}" data-anchor="${s.id}">${escapeHtml(s.title)}</a>`).join('')}
        </nav>
        <div class="guide-content">
          ${DOC_SECTIONS.map((s) => `
            <section class="guide-section" id="docs-${s.id}">
              <h3>${escapeHtml(s.title)}</h3>
              ${s.blocks.map(docsBlockHtml).join('')}
            </section>`).join('')}
        </div>
      </div>

      <div class="card" style="margin-top:16px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
        <span class="form-hint">内容较长，需要离线交付时下载一份 Markdown 存档，随项目代码一同入库。</span>
        <button class="btn btn-primary" id="docs-download-bottom">⬇ 下载 Markdown 文档</button>
      </div>`;

    $('#docs-download-btn').addEventListener('click', downloadDoc);
    $('#docs-download-bottom').addEventListener('click', downloadDoc);
    bindDocsToc();
  } catch (err) {
    toastError(err);
    root.innerHTML = '<div class="empty">对接文档加载失败，请刷新重试</div>';
  }
}

/** TOC 锚点点击平滑滚动（02 §11，同教程页）。 */
function bindDocsToc() {
  $$('.guide-toc a[data-anchor]').forEach((a) => {
    a.addEventListener('click', (e) => {
      e.preventDefault();
      const el = document.getElementById('docs-' + a.dataset.anchor);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });
}
