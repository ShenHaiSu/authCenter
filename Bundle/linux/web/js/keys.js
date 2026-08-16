/* ============================================================
 * js/keys.js — 密钥视图：列表/筛选/生成/编辑/轮换/吊销（02 §5）
 * API：GET/POST /projects/{id}/keys、PUT /keys/{id}、
 *      POST /keys/{id}/rotate、DELETE /keys/{id}
 * 安全约束：明文密钥只存在于展示模态框 DOM，关闭即清空，
 *           不写入 localStorage / 内存变量（02 §5 / 02 §9）。
 * ============================================================ */

let keysFilter = 'all';   // all | active | inactive | expired
let keyModal = null;      // 生成/编辑模态框（单例）
let _revealedKey = null;  // 当前展示的明文（仅模态框存活期间）

async function loadKeys() {
  const root = document.getElementById('keys-root');
  if (!state.currentProject) {
    root.innerHTML = '<div class="empty">未选择项目，请先进入项目管理</div>';
    return;
  }
  const pid = state.currentProject.id;
  root.innerHTML = '<div class="loading"><span class="spinner"></span>加载中…</div>';

  try {
    const data = await api(`/projects/${pid}/keys?page=1&size=100`);
    const items = data.items || [];
    const now = Date.now();
    const isExpired = (k) => k.expires_at && new Date(k.expires_at).getTime() < now;

    const filtered = items.filter((k) => {
      switch (keysFilter) {
        case 'active': return k.is_active && !isExpired(k);
        case 'inactive': return !k.is_active;
        case 'expired': return isExpired(k);
        default: return true;
      }
    });

    root.innerHTML = `
      <div class="breadcrumb">
        <a onclick="showView('projects')">项目</a>
        <span class="sep">/</span>
        <span class="current">${escapeHtml(state.currentProject.name)}</span>
      </div>

      <div class="card">
        <div class="toolbar">
          <select id="key-filter" class="form-control" style="max-width:160px;">
            <option value="all" ${keysFilter === 'all' ? 'selected' : ''}>全部</option>
            <option value="active" ${keysFilter === 'active' ? 'selected' : ''}>启用</option>
            <option value="inactive" ${keysFilter === 'inactive' ? 'selected' : ''}>停用</option>
            <option value="expired" ${keysFilter === 'expired' ? 'selected' : ''}>已过期</option>
          </select>
          <span class="spacer"></span>
          <button id="key-create-btn" class="btn btn-primary">＋ 生成密钥</button>
        </div>

        ${filtered.length === 0
          ? '<div class="empty">暂无密钥，点击「生成密钥」创建</div>'
          : `<div class="table-wrap"><table class="table">
              <thead><tr>
                <th>备注</th><th>指纹</th><th>过期时间</th><th>状态</th>
                <th>最后使用</th><th>创建时间</th><th>操作</th>
              </tr></thead>
              <tbody>
                ${filtered.map((k) => {
                  const exp = expiryInfo(k.expires_at);
                  return `<tr>
                    <td><b>${escapeHtml(k.name)}</b></td>
                    <td>${fpBadge(k.fingerprint)}</td>
                    <td><span class="badge ${exp.cls}">${exp.text}</span></td>
                    <td>${activeBadge(k.is_active)}</td>
                    <td>${k.last_used_at
                      ? escapeHtml(formatTime(k.last_used_at)) + '<br><small style="color:var(--text-secondary)">' + escapeHtml(k.last_used_ip || '') + '</small>'
                      : '<span style="color:var(--text-secondary)">从未使用</span>'}</td>
                    <td>${escapeHtml(formatTime(k.created_at))}</td>
                    <td class="actions">
                      <button class="btn btn-link" onclick="openKeyModal(${k.id})">编辑</button>
                      <button class="btn btn-link" onclick="rotateKey(${k.id}, '${escapeHtml(k.name)}')">轮换</button>
                      <button class="btn btn-link" onclick="toggleKey(${k.id}, ${k.is_active})">${k.is_active ? '禁用' : '启用'}</button>
                      <button class="btn btn-link-danger" onclick="deleteKey(${k.id}, '${escapeHtml(k.name)}')">吊销</button>
                    </td>
                  </tr>`;
                }).join('')}
              </tbody>
            </table></div>`}
      </div>`;

    $('#key-filter').addEventListener('change', (e) => {
      keysFilter = e.target.value;
      loadKeys();
    });
    $('#key-create-btn').addEventListener('click', () => openKeyModal(null));
  } catch (err) {
    toastError(err);
    root.innerHTML = '<div class="empty">加载失败，请刷新重试</div>';
  }
}

/* ---------------- 明文展示模态框（02 §5） ---------------- */

function revealKey(plain, extraHint) {
  _revealedKey = plain;
  const valueEl = document.getElementById('key-reveal-value');
  valueEl.textContent = plain;
  // 警示文案（含轮换宽限期提示时追加）。
  const warn = document.querySelector('#key-reveal-modal .key-warning');
  if (extraHint) warn.textContent = '⚠ ' + extraHint;
  else warn.textContent = '⚠ 明文仅显示一次，关闭后不可再次查看，请立即复制保存！';
  openModal('key-reveal-modal');
}

function clearRevealedKey() {
  _revealedKey = null;
  const el = document.getElementById('key-reveal-value');
  if (el) el.textContent = '';
}

// 关闭明文模态框时清空 DOM 中的明文（含遮罩点击、Esc）。
document.addEventListener('click', (e) => {
  if (e.target.id === 'key-reveal-copy') {
    copyRevealedKey();
  }
  if ((e.target.classList && e.target.classList.contains('modal-mask') && e.target.id === 'key-reveal-modal')
      || (e.target.closest && e.target.closest('#key-reveal-modal [data-close]'))) {
    clearRevealedKey();
  }
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && document.getElementById('key-reveal-modal').classList.contains('show')) {
    clearRevealedKey();
  }
});

async function copyRevealedKey() {
  if (!_revealedKey) return;
  try {
    await navigator.clipboard.writeText(_revealedKey);
    toast('密钥已复制', 'success');
  } catch (err) {
    // 降级：选中文本复制。
    const el = document.getElementById('key-reveal-value');
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    document.execCommand('copy');
    sel.removeAllRanges();
    toast('密钥已复制', 'success');
  }
}

/* ---------------- 行操作 ---------------- */

/** 生成（create）时展示明文；编辑（update）时只返回 key 视图。 */
async function toggleKey(id, isActive) {
  try {
    await api('/keys/' + id, { method: 'PUT', body: { is_active: !isActive } });
    toast(isActive ? '密钥已禁用' : '密钥已启用', 'success');
    loadKeys();
  } catch (err) {
    toastError(err);
  }
}

/** 轮换：确认框提示宽限期（02 §5），成功后展示新密钥明文一次。 */
function rotateKey(id, name) {
  confirmAction(`确定轮换密钥「${name}」吗？将生成新密钥，旧密钥保留 7 天宽限期后失效（宽限期内仍可认证）。`, '轮换密钥', async () => {
    try {
      const data = await api(`/keys/${id}/rotate`, { method: 'POST' });
      const plain = data.new_key && data.new_key.key_value;
      if (!plain) throw new Error('轮换响应缺少新密钥明文');
      revealKey(plain, `明文仅显示一次！新密钥已生成，旧密钥保留至 ${formatTime(data.old_key_grace_until)} 后失效。`);
      toast('密钥已轮换', 'success');
      loadKeys();
    } catch (err) {
      toastError(err);
    }
  });
}

/** 吊销：二次确认（02 §7），立即失效。 */
function deleteKey(id, name) {
  confirmAction(`确定吊销密钥「${name}」吗？吊销后<b>立即失效</b>，使用该密钥的客户端将无法认证！`, '吊销密钥', async () => {
    await api('/keys/' + id, { method: 'DELETE' });
    toast('密钥已吊销', 'success');
    loadKeys();
  });
}

/* ---------------- 生成 / 编辑模态框（02 §5） ---------------- */

function ensureKeyModal() {
  if (keyModal) return;
  const mask = document.createElement('div');
  mask.id = 'key-modal';
  mask.className = 'modal-mask';
  mask.innerHTML = `
    <div class="modal">
      <div class="modal-header">
        <h3 id="key-modal-title">生成密钥</h3>
        <button type="button" class="modal-close" data-close>×</button>
      </div>
      <form id="key-form" autocomplete="off">
        <div class="form-group">
          <label class="required" for="k-name">备注</label>
          <input id="k-name" class="form-control" type="text" placeholder="如 生产环境 / 测试环境" required maxlength="128">
        </div>
        <div class="form-group">
          <label for="k-expires">过期时间（留空 = 永不过期）</label>
          <input id="k-expires" class="form-control" type="datetime-local">
        </div>
        <div class="form-group">
          <label for="k-fp">绑定指纹（可选）</label>
          <input id="k-fp" class="form-control" type="text" placeholder="1-128 字符，如 sha256(机器ID)[:32]">
          <div class="form-hint">绑定后仅携带该指纹的客户端可认证；编辑时留空 = 解绑</div>
        </div>
        <div class="form-group" id="k-active-group" style="display:none;">
          <label for="k-active">状态</label>
          <select id="k-active" class="form-control">
            <option value="1">启用</option>
            <option value="0">禁用</option>
          </select>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn" data-close>取消</button>
          <button type="submit" id="key-save-btn" class="btn btn-primary">保存</button>
        </div>
      </form>
    </div>`;
  document.body.appendChild(mask);
  keyModal = mask;

  $('#key-form', mask).addEventListener('submit', async (e) => {
    e.preventDefault();
    const pid = state.currentProject.id;
    const keyId = mask.dataset.keyId || null;
    const name = $('#k-name', mask).value.trim();
    const expiresAt = parseLocalInput($('#k-expires', mask).value); // null=永不过期
    const fingerprint = $('#k-fp', mask).value.trim();

    if (!name) { toast('密钥备注不能为空', 'warning'); return; }

    try {
      if (keyId) {
        // 编辑：PUT；空指纹 = 解绑（传空串），过期时间空 = 永不过期。
        const body = {
          name,
          expires_at: expiresAt,
          fingerprint: fingerprint || '',
          is_active: $('#k-active', mask).value === '1',
        };
        await api('/keys/' + keyId, { method: 'PUT', body });
        toast('密钥已更新', 'success');
      } else {
        // 生成：响应含唯一一次明文 → 展示（02 §5）。
        const data = await api(`/projects/${pid}/keys`, {
          method: 'POST',
          body: { name, expires_at: expiresAt, fingerprint: fingerprint || null },
        });
        if (!data.key_value) throw new Error('响应缺少密钥明文');
        closeModal('key-modal');
        revealKey(data.key_value);
        toast('密钥已生成，请立即复制保存', 'success');
        return;
      }
      closeModal('key-modal');
      loadKeys();
    } catch (err) {
      toastError(err);
    }
  });
}

/** 打开生成（null）或编辑（key）模态框。 */
async function openKeyModal(keyId) {
  ensureKeyModal();
  $('#key-modal-title').textContent = keyId ? '编辑密钥' : '生成密钥';
  $('#k-active-group').style.display = keyId ? '' : 'none';

  if (keyId) {
    try {
      // 编辑预填：先列当前项目密钥找到目标（避免新增详情 API）。
      const pid = state.currentProject.id;
      const data = await api(`/projects/${pid}/keys?page=1&size=100`);
      const key = (data.items || []).find((k) => k.id === keyId);
      if (!key) throw new Error('密钥不存在');
      $('#k-name', keyModal).value = key.name;
      $('#k-expires', keyModal).value = toLocalInputValue(key.expires_at);
      $('#k-fp', keyModal).value = key.fingerprint || '';
      $('#k-active', keyModal).value = key.is_active ? '1' : '0';
      keyModal.dataset.keyId = String(keyId);
    } catch (err) {
      toastError(err);
      return;
    }
  } else {
    $('#k-name', keyModal).value = '';
    $('#k-expires', keyModal).value = '';
    $('#k-fp', keyModal).value = '';
    $('#k-active', keyModal).value = '1';
    delete keyModal.dataset.keyId;
  }

  openModal('key-modal');
  setTimeout(() => $('#k-name', keyModal).focus(), 50);
}
