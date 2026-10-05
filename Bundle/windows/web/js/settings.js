/* ============================================================
 * js/settings.js — 系统设置视图：审计保留策略（need01 01-F019 §6）
 * API：GET/PUT /settings、POST /settings/audit/cleanup-now、POST /settings/audit/checkpoint
 * ============================================================ */

async function loadSettings() {
  const root = document.getElementById('settings-root');
  root.innerHTML = '<div class="loading"><span class="spinner"></span>加载中…</div>';
  try {
    const data = await api('/settings');
    renderSettings(root, data.settings || {}, data.usage || {});
  } catch (err) {
    toastError(err);
    root.innerHTML = '<div class="empty">加载失败，请刷新重试</div>';
  }
}

function renderSettings(root, s, usage) {
  const retDays = s.audit_retention_days ?? 90;
  const intervalH = s.audit_cleanup_interval_hours ?? 24;
  const minKeep = s.audit_min_keep_rows ?? 1000;
  const lastAt = s.audit_last_cleanup_at || '';
  const lastRows = s.audit_last_cleanup_rows ?? 0;
  const totalRows = usage.total_rows ?? 0;
  const oldest = usage.oldest_event_time || '';

  root.innerHTML = `
    <div class="card">
      <div class="card-title">系统设置</div>
      <div class="callout callout-tip">审计保留策略生效后，超期记录将被自动删除且不可恢复。</div>
      <div class="settings-row">
        <label for="set-ret-days">保留天数</label>
        <input id="set-ret-days" class="form-control" type="number" min="0" max="3650" value="${escapeHtml(retDays)}">
        <span class="form-hint">天（0 = 永久保留，1-3650）</span>
      </div>
      <div class="settings-row">
        <label for="set-interval">清理间隔</label>
        <input id="set-interval" class="form-control" type="number" min="1" max="720" value="${escapeHtml(intervalH)}">
        <span class="form-hint">小时（1-720）</span>
      </div>
      <div class="settings-row">
        <label for="set-minkeep">最少保留行数</label>
        <input id="set-minkeep" class="form-control" type="number" min="0" value="${escapeHtml(minKeep)}">
        <span class="form-hint">行（0 = 不保底）</span>
      </div>
      <div style="margin-top:12px;"><button id="set-save" class="btn btn-primary">保存</button></div>
    </div>
    <div class="card">
      <div class="card-title">审计用量</div>
      <div class="stats-grid">
        <div class="stat-card"><div class="stat-label">总记录数</div><div class="stat-value">${escapeHtml(totalRows)}</div></div>
        <div class="stat-card"><div class="stat-label">最早记录</div><div class="stat-value" style="font-size:16px;">${escapeHtml(oldest ? formatTime(oldest) : '—')}</div></div>
        <div class="stat-card"><div class="stat-label">上次清理</div><div class="stat-value" style="font-size:16px;">${escapeHtml(lastAt ? formatTime(lastAt) : '从未')}</div><div class="stat-hint">删除 ${escapeHtml(lastRows)} 行</div></div>
        <div class="stat-card"><div class="stat-label">当前占用</div><div class="stat-value" style="font-size:16px;">—</div><div class="stat-hint">WAL 回收后文件系统可见</div></div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">维护操作</div>
      <div class="toolbar">
        <button id="set-cleanup" class="btn">立即清理超期记录</button>
        <button id="set-checkpoint" class="btn">回收 WAL 空间</button>
      </div>
      <div class="form-hint">如需真正缩小 db 文件，请在停机后执行 <code>sqlite3 data/authcenter.db 'VACUUM;'</code>。</div>
    </div>`;

  $('#set-save').addEventListener('click', async (e) => {
    const days = Number($('#set-ret-days').value);
    const hours = Number($('#set-interval').value);
    const keep = Number($('#set-minkeep').value);
    if (!Number.isInteger(days) || days < 0 || days > 3650) { toast('保留天数必须在 0..3650', 'warning'); return; }
    if (!Number.isInteger(hours) || hours < 1 || hours > 720) { toast('清理间隔必须在 1..720', 'warning'); return; }
    if (!Number.isInteger(keep) || keep < 0) { toast('最少保留行数必须 >= 0', 'warning'); return; }
    try {
      await withSubmitting(e.target, () => api('/settings', {
        method: 'PUT',
        body: { audit_retention_days: days, audit_cleanup_interval_hours: hours, audit_min_keep_rows: keep },
      }));
      toast('已保存', 'success');
      loadSettings();
    } catch (err) { toastError(err); }
  });

  $('#set-cleanup').addEventListener('click', () => {
    confirmAction(`将立即删除 ${retDays} 天前的审计记录，不可恢复。确认继续？`, '确认清理', async () => {
      const btn = $('#set-cleanup');
      try {
        const data = await withSubmitting(btn, () => api('/settings/audit/cleanup-now', { method: 'POST' }));
        toast(`已删除 ${data.deleted_rows ?? 0} 行`, 'success');
        loadSettings();
      } catch (err) { toastError(err); }
    });
  });

  $('#set-checkpoint').addEventListener('click', async (e) => {
    try {
      await withSubmitting(e.target, () => api('/settings/audit/checkpoint', { method: 'POST' }));
      toast('WAL 已回收', 'success');
    } catch (err) { toastError(err); }
  });
}
