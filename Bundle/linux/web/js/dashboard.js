/* ============================================================
 * js/dashboard.js — 仪表盘视图（前端架构文档 02 §3）
 * 统计卡片：GET /stats
 * 最近认证事件：GET /audit-logs?event_type=auth.authenticate&size=10
 * ============================================================ */

async function loadDashboard() {
  const root = document.getElementById('dashboard-root');
  root.innerHTML = '<div class="loading"><span class="spinner"></span>加载中…</div>';

  try {
    const [stats, recent] = await Promise.all([
      api('/stats'),
      api('/audit-logs?event_type=auth.authenticate&size=10'),
    ]);

    const expiring = (stats.expiring_keys_7d || 0);
    const auth = stats.auth_today || { total: 0, success: 0, failure: 0 };
    const recentItems = recent.items || [];

    // 即将过期提示条（02 §3：7 天内黄色徽章提示）。
    const warnBar = expiring > 0
      ? `<div class="card" style="border-left:4px solid var(--warning);">
           <div>⚠ 有 <b>${expiring}</b> 个密钥将在 7 天内到期，请及时轮换。
             <button class="btn btn-sm" style="margin-left:8px;" onclick="showView('projects')">前往处理</button>
           </div>
         </div>`
      : '';

    root.innerHTML = `
      ${warnBar}
      <div class="stats-grid">
        <div class="stat-card" onclick="showView('projects')">
          <div class="stat-label">项目数</div>
          <div class="stat-value">${stats.projects || 0}</div>
          <div class="stat-hint">点击进入项目管理</div>
        </div>
        <div class="stat-card" onclick="showView('projects')">
          <div class="stat-label">有效密钥数</div>
          <div class="stat-value">${stats.active_keys || 0}</div>
          <div class="stat-hint">启用状态的密钥总数</div>
        </div>
        <div class="stat-card" onclick="showView('projects')">
          <div class="stat-label">7 天内到期密钥</div>
          <div class="stat-value ${expiring > 0 ? 'warn' : 'ok'}">${expiring}</div>
          <div class="stat-hint">${expiring > 0 ? '需尽快轮换' : '暂无到期风险'}</div>
        </div>
        <div class="stat-card" onclick="showView('audit')">
          <div class="stat-label">今日认证</div>
          <div class="stat-value">${auth.total || 0}</div>
          <div class="stat-hint">成功 <span class="badge badge-success">${auth.success || 0}</span>
                失败 <span class="badge badge-danger">${auth.failure || 0}</span></div>
        </div>
      </div>

      <div class="card">
        <div class="card-title">最近认证事件
          <button class="btn btn-sm" onclick="showView('audit')">查看全部</button>
        </div>
        ${recentItems.length === 0
          ? '<div class="empty">暂无外部认证记录</div>'
          : `<div class="table-wrap"><table class="table">
              <thead><tr><th>时间</th><th>项目</th><th>结果</th><th>指纹</th><th>IP</th></tr></thead>
              <tbody>
                ${recentItems.map((e) => {
                  let detail = {};
                  try { detail = e.detail ? JSON.parse(e.detail) : {}; } catch (err) { /* 忽略 */ }
                  return `<tr>
                    <td>${escapeHtml(formatTime(e.event_time))}</td>
                    <td>${escapeHtml(e.target_name || e.actor_name || '—')}</td>
                    <td>${resultBadge(e.result)}</td>
                    <td class="mono">${escapeHtml(detail.fingerprint || '—')}</td>
                    <td>${escapeHtml(e.ip || '—')}</td>
                  </tr>`;
                }).join('')}
              </tbody>
            </table></div>`}
      </div>`;
  } catch (err) {
    toastError(err);
    root.innerHTML = '<div class="empty">加载失败，请刷新重试</div>';
  }
}
