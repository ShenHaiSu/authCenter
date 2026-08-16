/* ============================================================
 * js/common.js — DOM 工具、模态框、toast、二次确认、XSS 转义
 * 前端架构文档 01 §2（common.js）/ 02 §8 通用错误处理
 * ============================================================ */

/** 选择器快捷函数。 */
function $(sel, root) { return (root || document).querySelector(sel); }
function $$(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }

/** HTML 转义，防止用户数据 XSS（所有动态渲染必须过此函数）。 */
function escapeHtml(v) {
  if (v === null || v === undefined) return '';
  return String(v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** 布尔 → 启用/停用徽章。 */
function activeBadge(isActive) {
  return isActive
    ? '<span class="badge badge-success">启用</span>'
    : '<span class="badge badge-muted">停用</span>';
}

/** 有/无指纹徽章。 */
function fpBadge(fingerprint) {
  if (fingerprint) return '<span class="badge badge-info">已绑定指纹</span>';
  return '<span class="badge badge-muted">未绑定</span>';
}

/* ---------------- Toast 轻提示 ---------------- */

/** 显示 toast（success / error / warning / 默认）。 */
function toast(message, type) {
  let container = $('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }
  const el = document.createElement('div');
  el.className = 'toast' + (type ? ' ' + type : '');
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => {
    el.style.transition = 'opacity 0.3s';
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 320);
  }, 3200);
}

/**
 * 统一错误提示：
 * 429 → 「操作过于频繁，请稍后再试」；其余 → 展示 message。
 */
function toastError(err) {
  if (err && err.code === 10009) {
    toast('操作过于频繁，请稍后再试', 'warning');
  } else if (err && err.code === 10008) {
    toast('未绑定指纹但系统要求绑定', 'warning');
  } else if (err && err.message) {
    toast(err.message, 'error');
  } else {
    toast('服务暂不可用，请稍后重试', 'error');
  }
}

/* ---------------- 模态框 ---------------- */

function openModal(id) {
  const mask = document.getElementById(id);
  if (mask) mask.classList.add('show');
}

function closeModal(id) {
  const mask = document.getElementById(id);
  if (mask) mask.classList.remove('show');
}

/** 关闭全部模态框（含二次确认）。 */
function closeAllModals() {
  $$('.modal-mask.show').forEach((m) => m.classList.remove('show'));
}

// 全局事件：点击遮罩关闭、Esc 关闭；模态框内按钮 data-close 关闭。
document.addEventListener('click', (e) => {
  if (e.target.classList && e.target.classList.contains('modal-mask')) {
    e.target.classList.remove('show');
  }
  const closer = e.target.closest && e.target.closest('[data-close]');
  if (closer) closeModal(closer.closest('.modal-mask').id);
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeAllModals();
});

/**
 * 危险操作二次确认（02 §7：删除项目/吊销密钥需确认）。
 * @param {string} message 确认框正文
 * @param {string} [confirmText] 确认按钮文字
 * @param {Function} onConfirm 确认回调（async）
 */
function confirmAction(message, confirmText, onConfirm) {
  const mask = document.getElementById('confirm-modal');
  if (!mask) return;
  $('#confirm-message').textContent = message;
  const btn = $('#confirm-ok');
  btn.textContent = confirmText || '确认';
  btn.className = 'btn btn-danger';
  mask.classList.add('show');
  // 先解绑旧监听，避免重复点击叠加。
  const next = btn.cloneNode(true);
  btn.parentNode.replaceChild(next, btn);
  next.addEventListener('click', async () => {
    mask.classList.remove('show');
    try {
      await onConfirm();
    } catch (err) {
      toastError(err);
    }
  });
}

/* ---------------- 表单工具 ---------------- */

/** 表单提交时禁用提交按钮防重复提交。 */
function withSubmitting(btn, fn) {
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = '提交中…';
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      btn.disabled = false;
      btn.textContent = original;
    });
}
