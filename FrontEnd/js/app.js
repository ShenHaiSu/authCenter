/* ============================================================
 * js/app.js — 主界面框架：导航切换、当前用户、登出、修改密码
 * 前端架构文档 01 §4/§5 / 02 §2/§7
 * ============================================================ */

 const VIEW_TITLES = {
   dashboard: '仪表盘',
   projects: '项目',
   keys: '密钥管理',
   audit: '审计日志',
   settings: '系统设置',
   password: '修改密码',
   guide: '使用教程',
   docs: '对接文档',
 };

/** 视图加载函数映射（keys 由 projects.js 进入时设置 currentProject）。 */
 const VIEW_LOADERS = {
   dashboard: loadDashboard,
   projects: loadProjects,
   keys: loadKeys,
   audit: loadAudit,
   settings: loadSettings,
   password: renderPasswordView,
   guide: loadGuide,
   docs: loadDocs,
 };

/** 全局轻量状态（01 §5：不引入框架状态库）。 */
const state = { user: null, currentProject: null };

/** 切换视图：隐藏/显示 div + 高亮导航 + 更新标题 + 惰性加载。 */
function showView(id) {
  $$('.view').forEach((v) => v.classList.remove('active'));
  const view = document.getElementById('view-' + id);
  if (view) view.classList.add('active');

  $$('.sidebar-nav a').forEach((a) =>
    a.classList.toggle('active', a.dataset.view === id)
  );
  $('#topbar-title').textContent = VIEW_TITLES[id] || id;

  const loader = VIEW_LOADERS[id];
  if (loader && typeof loader === 'function') loader();
}

/* ---------------- 初始化 ---------------- */

(async function init() {
  // 未登录 → 跳登录页（01 §4）。
  let me;
  try {
    me = await api('/admin/me');
  } catch (err) {
    location.href = '/login.html';
    return;
  }
  state.user = me.user;
  $('#current-user').textContent = me.user.username;
  $('#sidebar-user').textContent = '当前用户：' + me.user.username;

  // 导航切换。
  $$('.sidebar-nav a').forEach((a) => {
    a.addEventListener('click', () => showView(a.dataset.view));
  });

  // 登出（01 §4：POST /admin/logout → 跳登录页）。
  $('#logout-btn').addEventListener('click', async () => {
    try {
      await api('/admin/logout', { method: 'POST' });
    } catch (err) { /* 忽略登出错误，仍跳登录页 */ }
    location.href = '/login.html';
  });

  // 默认视图：仪表盘。
  showView('dashboard');
})();

/* ---------------- 修改密码视图（02 §7） ---------------- */

function renderPasswordView() {
  const root = document.getElementById('password-root');
  root.innerHTML = `
    <div class="card" style="max-width:520px;">
      <div class="card-title">修改密码</div>
      <div class="form-hint" style="margin-bottom:16px;">新密码须 ≥ 12 位，且同时包含字母与数字。提交成功后将被退出登录，需用新密码重新登录。</div>
      <form id="password-form" autocomplete="off">
        <div class="form-group">
          <label class="required" for="pw-old">旧密码</label>
          <input id="pw-old" class="form-control" type="password" required autocomplete="current-password">
        </div>
        <div class="form-group">
          <label class="required" for="pw-new">新密码</label>
          <input id="pw-new" class="form-control" type="password" required autocomplete="new-password">
          <div class="form-hint" id="pw-strength">密码强度：—</div>
        </div>
        <div class="form-group">
          <label class="required" for="pw-confirm">确认新密码</label>
          <input id="pw-confirm" class="form-control" type="password" required autocomplete="new-password">
        </div>
        <button id="pw-submit" type="submit" class="btn btn-primary">修改密码</button>
      </form>
    </div>`;

  // 实时强度提示（02 §7）。
  const pwNew = $('#pw-new');
  const strength = $('#pw-strength');
  pwNew.addEventListener('input', () => {
    const v = pwNew.value;
    let label = '密码强度：弱';
    if (v.length >= 12 && /[A-Za-z]/.test(v) && /\d/.test(v)) {
      label = '密码强度：强 ✓';
      strength.style.color = 'var(--success)';
    } else {
      label = v.length >= 12
        ? '密码强度：中（需同时包含字母与数字）'
        : `密码强度：弱（至少 12 位，当前 ${v.length} 位）`;
      strength.style.color = 'var(--warning)';
    }
    strength.textContent = label;
  });

  $('#password-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const oldPw = $('#pw-old').value;
    const newPw = pwNew.value;
    const confirmPw = $('#pw-confirm').value;

    if (!oldPw || !newPw) { toast('请输入旧密码与新密码', 'warning'); return; }
    if (newPw.length < 12) { toast('新密码至少 12 位', 'warning'); return; }
    if (!/[A-Za-z]/.test(newPw) || !/\d/.test(newPw)) {
      toast('新密码必须同时包含字母与数字', 'warning');
      return;
    }
    if (newPw !== confirmPw) { toast('两次输入的新密码不一致', 'warning'); return; }

    try {
      await withSubmitting($('#pw-submit'), () =>
        api('/admin/password', { method: 'PUT', body: { old_password: oldPw, new_password: newPw } })
      );
      toast('密码已修改，请重新登录', 'success');
      setTimeout(() => { location.href = '/login.html'; }, 800);
    } catch (err) {
      toastError(err);
    }
  });
}
