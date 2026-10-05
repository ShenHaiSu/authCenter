/* ============================================================
 * js/admins.js — 管理员账号管理视图（need01 02-F020 §6）
 * API：GET/POST /admins、PUT /admins/{id}、PUT /admins/{id}/password
 * 仅 owner 可见（app.js 按 /admin/me 的 role 隐藏导航；后端 requireOwner 兜底）
 * ============================================================ */

let adminsPage = 1;
const ADMINS_PAGE_SIZE = 20;

/** 角色 → 徽章 HTML（owner=超级管理员 info，admin=管理员 muted）。 */
function roleBadge(role) {
  return role === 'owner'
    ? '<span class="badge badge-info role-badge">超级管理员</span>'
    : '<span class="badge badge-muted role-badge">管理员</span>';
}

/** 加载并渲染管理员列表。 */
async function loadAdmins() {
  const root = document.getElementById('admins-root');
  root.innerHTML = '<div class="loading"><span class="spinner"></span>加载中…</div>';
  try {
    const data = await api('/admins?page=' + adminsPage + '&size=' + ADMINS_PAGE_SIZE);
    renderAdmins(root, data.items || [], data.total || 0);
  } catch (err) {
    // 非 owner 直接访问（改 hash 等）：以服务端 403 为准（need01 02 §6.3）。
    toastError(err);
    root.innerHTML = '<div class="empty">加载失败：' + escapeHtml(err.message || '请刷新重试') + '</div>';
  }
}

/** 渲染列表 + 分页 + 行内操作。 */
function renderAdmins(root, items, total) {
  const me = state.user || {};
  const pages = Math.max(1, Math.ceil(total / ADMINS_PAGE_SIZE));

  root.innerHTML = `
    <div class="card">
      <div class="card-title">管理员</div>
      <div class="callout callout-tip">系统须始终保留至少一个启用的超级管理员；停用账号会立即吊销其全部会话。</div>
      <div class="toolbar">
        <span class="form-hint">共 ${escapeHtml(total)} 个管理员账号</span>
        <span class="spacer"></span>
        <button id="adm-create-btn" class="btn btn-primary">＋ 新增管理员</button>
      </div>

      ${items.length === 0
        ? '<div class="empty">暂无其他管理员</div>'
        : `<div class="table-wrap"><table class="table">
            <thead><tr>
              <th>用户名</th><th>角色</th><th>状态</th><th>强制改密</th><th>最后登录</th><th>操作</th>
            </tr></thead>
            <tbody>
              ${items.map((u) => {
                const isSelf = me.id === u.id;
                const tip = isSelf ? ' title="不能对自己执行此操作"' : '';
                const dis = isSelf ? ' disabled' : '';
                return `<tr>
                  <td><b>${escapeHtml(u.username)}</b>${isSelf ? ' <span class="badge badge-muted">本人</span>' : ''}</td>
                  <td>${roleBadge(u.role)}</td>
                  <td>${activeBadge(u.is_active)}</td>
                  <td>${u.force_password_change ? '<span class="badge badge-warning">待改密</span>' : '—'}</td>
                  <td>${escapeHtml(u.last_login_at ? formatTime(u.last_login_at) : '—')}${u.last_login_ip ? '<div class="form-hint">' + escapeHtml(u.last_login_ip) + '</div>' : ''}</td>
                  <td class="actions">
                    <button class="btn btn-link"${tip}${dis} onclick="openAdminEditModal(${u.id})">编辑角色</button>
                    <button class="btn btn-link"${tip}${dis} onclick="toggleAdminActive(${u.id}, ${u.is_active ? 'true' : 'false'})">${u.is_active ? '停用' : '启用'}</button>
                    <button class="btn btn-link-danger"${tip}${dis} onclick="openAdminResetPasswordModal(${u.id})">重置密码</button>
                  </td>
                </tr>`;
              }).join('')}
            </tbody>
          </table></div>`}

      <div class="pagination">
        <span>共 ${escapeHtml(total)} 条 · 第 ${adminsPage}/${pages} 页</span>
        <button id="adm-prev" class="btn btn-sm" ${adminsPage <= 1 ? 'disabled' : ''}>上一页</button>
        <button id="adm-next" class="btn btn-sm" ${adminsPage >= pages ? 'disabled' : ''}>下一页</button>
      </div>
    </div>`;

  $('#adm-create-btn').addEventListener('click', () => openAdminCreateModal());
  $('#adm-prev').addEventListener('click', () => { if (adminsPage > 1) { adminsPage--; loadAdmins(); } });
  $('#adm-next').addEventListener('click', () => { if (adminsPage < pages) { adminsPage++; loadAdmins(); } });
}

/** 启停管理员（破坏性操作走二次确认）。 */
function toggleAdminActive(id, isActive) {
  const verb = isActive ? '停用' : '启用';
  const msg = isActive
    ? '停用后该账号将<b>立即退出登录且无法再登录</b>，其全部会话会被吊销。确认停用？'
    : '确认启用该管理员账号？';
  confirmAction(msg, '确认' + verb, async () => {
    await api('/admins/' + id, { method: 'PUT', body: { is_active: !isActive } });
    toast('已' + verb, 'success');
    loadAdmins();
  });
}

/* ---------------- 模态框（新增 / 编辑角色 / 重置密码） ---------------- */

let adminsModalsReady = false;

/** 一次性创建三个模态框（与 projects.js 的单例模态框风格一致）。 */
function ensureAdminModals() {
  if (adminsModalsReady) return;
  adminsModalsReady = true;

  const create = document.createElement('div');
  create.id = 'admin-create-modal';
  create.className = 'modal-mask';
  create.innerHTML = `
    <div class="modal">
      <div class="modal-header">
        <h3>新增管理员</h3>
        <button type="button" class="modal-close" data-close>×</button>
      </div>
      <form id="admin-create-form" autocomplete="off">
        <div class="form-group">
          <label class="required" for="ac-username">用户名</label>
          <input id="ac-username" class="form-control" type="text" required maxlength="32" placeholder="3-32 位字母、数字、_ . -">
          <div class="form-hint">创建后不可修改；须与既有用户名不同</div>
        </div>
        <div class="form-group">
          <label class="required" for="ac-password">初始密码</label>
          <input id="ac-password" class="form-control" type="password" required autocomplete="new-password" placeholder="至少 12 位，含字母与数字">
        </div>
        <div class="form-group">
          <label for="ac-role">角色</label>
          <select id="ac-role" class="form-control">
            <option value="admin">管理员（项目/密钥/审计）</option>
            <option value="owner">超级管理员（可管理管理员账号）</option>
          </select>
        </div>
        <div class="form-group">
          <label class="check-line"><input id="ac-force" type="checkbox" checked> 要求下次登录时修改密码</label>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn" data-close>取消</button>
          <button type="submit" id="admin-create-submit" class="btn btn-primary">创建</button>
        </div>
      </form>
    </div>`;
  document.body.appendChild(create);

  const edit = document.createElement('div');
  edit.id = 'admin-edit-modal';
  edit.className = 'modal-mask';
  edit.innerHTML = `
    <div class="modal">
      <div class="modal-header">
        <h3>编辑管理员</h3>
        <button type="button" class="modal-close" data-close>×</button>
      </div>
      <form id="admin-edit-form" autocomplete="off">
        <div class="form-group">
          <label>用户名</label>
          <input id="ae-username" class="form-control" type="text" disabled>
        </div>
        <div class="form-group">
          <label for="ae-role">角色</label>
          <select id="ae-role" class="form-control">
            <option value="admin">管理员</option>
            <option value="owner">超级管理员</option>
          </select>
          <div class="form-hint">降级为管理员后，对方将无法再管理其它管理员</div>
        </div>
        <div class="form-group">
          <label class="check-line"><input id="ae-force" type="checkbox"> 要求下次登录时修改密码</label>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn" data-close>取消</button>
          <button type="submit" id="admin-edit-submit" class="btn btn-primary">保存</button>
        </div>
      </form>
    </div>`;
  document.body.appendChild(edit);

  const reset = document.createElement('div');
  reset.id = 'admin-reset-modal';
  reset.className = 'modal-mask';
  reset.innerHTML = `
    <div class="modal">
      <div class="modal-header">
        <h3>重置密码</h3>
        <button type="button" class="modal-close" data-close>×</button>
      </div>
      <form id="admin-reset-form" autocomplete="off">
        <div class="form-group">
          <label>目标账号</label>
          <input id="ar-username" class="form-control" type="text" disabled>
        </div>
        <div class="form-group">
          <label class="required" for="ar-password">新密码</label>
          <input id="ar-password" class="form-control" type="password" required autocomplete="new-password" placeholder="至少 12 位，含字母与数字">
          <div class="form-hint">重置后该账号的全部会话会立即失效</div>
        </div>
        <div class="form-group">
          <label class="check-line"><input id="ar-force" type="checkbox" checked> 要求下次登录时修改密码</label>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn" data-close>取消</button>
          <button type="submit" id="admin-reset-submit" class="btn btn-danger">重置</button>
        </div>
      </form>
    </div>`;
  document.body.appendChild(reset);

  /* ---- 提交处理 ---- */

  $('#admin-create-form', create).addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = $('#ac-username', create).value.trim();
    const password = $('#ac-password', create).value;
    const role = $('#ac-role', create).value;
    const force = $('#ac-force', create).checked;
    if (!username) { toast('请输入用户名', 'warning'); return; }
    if (password.length < 12 || !/[A-Za-z]/.test(password) || !/\d/.test(password)) {
      toast('密码至少 12 位且同时包含字母与数字', 'warning');
      return;
    }
    try {
      await withSubmitting($('#admin-create-submit', create), () =>
        api('/admins', {
          method: 'POST',
          body: { username, password, role, force_password_change: force },
        }));
      closeModal('admin-create-modal');
      toast('管理员已创建', 'success');
      adminsPage = 1;
      loadAdmins();
    } catch (err) {
      if (err && err.code === 20201) toast('用户名已存在，请更换', 'warning');
      else toastError(err);
    }
  });

  $('#admin-edit-form', edit).addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = edit.dataset.adminId;
    const role = $('#ae-role', edit).value;
    const force = $('#ae-force', edit).checked;
    const body = { role, force_password_change: force };
    try {
      await withSubmitting($('#admin-edit-submit', edit), () =>
        api('/admins/' + id, { method: 'PUT', body }));
      closeModal('admin-edit-modal');
      toast('已保存', 'success');
      loadAdmins();
    } catch (err) {
      toastError(err);
    }
  });

  $('#admin-reset-form', reset).addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = reset.dataset.adminId;
    const newPassword = $('#ar-password', reset).value;
    const force = $('#ar-force', reset).checked;
    if (newPassword.length < 12 || !/[A-Za-z]/.test(newPassword) || !/\d/.test(newPassword)) {
      toast('新密码至少 12 位且同时包含字母与数字', 'warning');
      return;
    }
    try {
      await withSubmitting($('#admin-reset-submit', reset), () =>
        api('/admins/' + id + '/password', {
          method: 'PUT',
          body: { new_password: newPassword, force_change: force },
        }));
      closeModal('admin-reset-modal');
      toast('密码已重置', 'success');
      loadAdmins();
    } catch (err) {
      toastError(err);
    }
  });
}

/** 打开新增管理员模态框。 */
function openAdminCreateModal() {
  ensureAdminModals();
  $('#ac-username').value = '';
  $('#ac-password').value = '';
  $('#ac-role').value = 'admin';
  $('#ac-force').checked = true;
  openModal('admin-create-modal');
  setTimeout(() => $('#ac-username').focus(), 50);
}

/** 打开编辑角色模态框（预填当前值）。 */
async function openAdminEditModal(id) {
  ensureAdminModals();
  try {
    const data = await api('/admins?page=1&size=100');
    const u = (data.items || []).find((x) => x.id === id);
    if (!u) { toast('未找到该管理员', 'warning'); return; }
    $('#ae-username').value = u.username;
    $('#ae-role').value = u.role;
    $('#ae-force').checked = !!u.force_password_change;
    $('#admin-edit-modal').dataset.adminId = String(id);
    openModal('admin-edit-modal');
  } catch (err) {
    toastError(err);
  }
}

/** 打开重置密码模态框（预填用户名）。 */
async function openAdminResetPasswordModal(id) {
  ensureAdminModals();
  try {
    const data = await api('/admins?page=1&size=100');
    const u = (data.items || []).find((x) => x.id === id);
    if (!u) { toast('未找到该管理员', 'warning'); return; }
    $('#ar-username').value = u.username;
    $('#ar-password').value = '';
    $('#ar-force').checked = true;
    $('#admin-reset-modal').dataset.adminId = String(id);
    openModal('admin-reset-modal');
    setTimeout(() => $('#ar-password').focus(), 50);
  } catch (err) {
    toastError(err);
  }
}
