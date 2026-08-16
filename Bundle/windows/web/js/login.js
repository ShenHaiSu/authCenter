/* ============================================================
 * js/login.js — 登录逻辑（前端架构文档 02 §1）
 * 加载：GET /admin/me 已登录 → 跳 index.html
 * 提交：POST /admin/login 成功 → 跳 index.html
 *       失败（20101/20102）→ 表单下方红色提示；429 → 限流提示
 * ============================================================ */

(function () {
  const form = document.getElementById('login-form');
  const errorBox = document.getElementById('login-error');
  const btn = document.getElementById('login-btn');

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.classList.add('show');
  }

  // 已登录则直接进入主界面。
  // redirectOn401: false —— 本页即登录页，未登录（401）应停留本页而非再次跳转，
  // 否则会形成「401 → 跳 /login.html → 重载 → 再探测 → 401」的死循环。
  api('/admin/me', { redirectOn401: false })
    .then(() => { location.href = '/index.html'; })
    .catch(() => { /* 未登录：停留登录页 */ });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorBox.classList.remove('show');

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    if (!username || !password) {
      showError('请输入用户名与密码');
      return;
    }

    try {
      await withSubmitting(btn, async () => {
        await api('/admin/login', {
          method: 'POST',
          body: { username, password },
        });
      });
      location.href = '/index.html';
    } catch (err) {
      // 429 限流：按文档 02 §1 明确提示。
      if (err && err.code === 10009) {
        showError('尝试过于频繁，请 15 分钟后再试');
      } else if (err && (err.code === 20101 || err.code === 20102)) {
        showError('用户名或密码错误');
      } else if (err && err.message) {
        showError(err.message);
      } else {
        showError('登录失败，请稍后重试');
      }
    }
  });
})();
