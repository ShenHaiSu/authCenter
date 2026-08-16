/* ============================================================
 * js/api.js — fetch 封装、统一错误处理、会话判断、时间格式化
 * 前端架构文档 01 §3 / 02 §8
 * ============================================================ */

// 会话过期业务码（05 §2）。
const CODE_SESSION_EXPIRED = 20103;

/**
 * 统一 API 请求封装。
 * 成功返回 data 字段；失败抛 Error（附 code）；401/20103 跳转登录页。
 * @param {string} path 接口路径（不含 /api/v1 前缀）
 * @param {object} [options]
 * @param {boolean} [options.redirectOn401=true] 401/20103 时是否跳转登录页。
 *   登录页自身的会话探测（如 login.js 的 GET /admin/me）应传 false，
 *   避免「401 → 跳 /login.html → 重载 → 再探测 → 401」的自跳转死循环。
 */
async function api(path, { method = 'GET', body, redirectOn401 = true } = {}) {
  const res = await fetch('/api/v1' + path, {
    method,
    credentials: 'same-origin',
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  // 204 No Content：无响应体。
  if (res.status === 204) return null;

  const json = await res.json().catch(() => ({ code: 50000, message: '响应解析失败' }));

  if (res.status === 401 || json.code === CODE_SESSION_EXPIRED) {
    // 已在登录页时不重复导航（兜底，防止其它路径在登录页误触发全局跳转）。
    if (redirectOn401 && !/\/login\.html$/.test(location.pathname)) {
      location.href = '/login.html';
    }
    throw new Error('会话过期，请重新登录');
  }
  if (json.code !== 0) {
    const err = new Error(json.message || '请求失败');
    err.code = json.code;
    throw err;
  }
  return json.data;
}

/* ---------------- 时间格式化 ---------------- */

/**
 * 后端 UTC ISO8601 → 浏览器本地时区字符串。
 * 空值返回 '—'。
 */
function formatTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

/** ISO 时间 → datetime-local 输入框值（本地时区，yyyy-MM-ddTHH:mm）。 */
function toLocalInputValue(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** datetime-local 输入值 → 后端 ISO8601 UTC；空串返回 null（永不过期）。 */
function parseLocalInput(v) {
  if (!v) return null;
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString();
}

/* ---------------- 展示映射 ---------------- */

/** 审计事件类型 → 中文标签（05 §5 审计事件映射表）。 */
const EVENT_TYPE_LABELS = {
  'system.startup': '服务启动',
  'system.shutdown': '服务关闭',
  'system.admin_initialized': '初始管理员生成',
  'admin.login': '管理员登录',
  'admin.login_failed': '登录失败',
  'admin.logout': '管理员登出',
  'admin.password_change': '修改密码',
  'project.create': '创建项目',
  'project.update': '更新项目',
  'project.enable': '启用项目',
  'project.disable': '停用项目',
  'project.delete': '删除项目',
  'key.create': '生成密钥',
  'key.update': '更新密钥',
  'key.enable': '启用密钥',
  'key.disable': '停用密钥',
  'key.rotate': '轮换密钥',
  'key.delete': '吊销密钥',
  'auth.authenticate': '外部认证成功',
  'auth.authenticate_failed': '外部认证失败',
};

function eventTypeLabel(t) {
  return EVENT_TYPE_LABELS[t] || t;
}

/** 结果 → 徽章 HTML。 */
function resultBadge(result) {
  if (result === 'success') return '<span class="badge badge-success">成功</span>';
  if (result === 'failure') return '<span class="badge badge-danger">失败</span>';
  return `<span class="badge badge-muted">${escapeHtml(result || '—')}</span>`;
}

/**
 * 过期时间相对提示：永不过期 / 已过期 / N 天后 / 具体日期。
 * 返回 { text, cls }，cls 为 badge 样式（warning=即将到期、danger=已过期）。
 */
function expiryInfo(expiresAt) {
  if (!expiresAt) return { text: '永不过期', cls: 'badge-muted' };
  const d = new Date(expiresAt);
  if (Number.isNaN(d.getTime())) return { text: escapeHtml(expiresAt), cls: 'badge-muted' };
  const now = Date.now();
  const diffDays = Math.ceil((d.getTime() - now) / 86400000);
  if (diffDays < 0) return { text: '已过期', cls: 'badge-danger' };
  if (diffDays <= 7) return { text: `${diffDays} 天后`, cls: 'badge-warning' };
  const p = (n) => String(n).padStart(2, '0');
  return { text: `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`, cls: 'badge-muted' };
}
