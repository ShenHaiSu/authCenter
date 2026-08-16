/* ============================================================
 * js/audit.js — 审计日志视图：筛选/分页/detail 展开（02 §6）
 * API：GET /audit-logs?event_type=&result=&from=&to=&q=&page=&size=
 * ============================================================ */

let auditPage = 1;
const AUDIT_PAGE_SIZE = 20;

async function loadAudit() {
  const root = document.getElementById('audit-root');
  root.innerHTML = '<div class="loading"><span class="spinner"></span>加载中…</div>';

  const q = new URLSearchParams();
  q.set('page', String(auditPage));
  q.set('size', String(AUDIT_PAGE_SIZE));

  const ev = document.getElementById('af-event');
  const rs = document.getElementById('af-result');
  const from = document.getElementById('af-from');
  const to = document.getElementById('af-to');
  const kw = document.getElementById('af-q');
  if (ev && ev.value) q.set('event_type', ev.value);
  if (rs && rs.value) q.set('result', rs.value);
  if (from && from.value) q.set('from', parseLocalInput(from.value) || '');
  if (to && to.value) q.set('to', parseLocalInput(to.value) || '');
  if (kw && kw.value.trim()) q.set('q', kw.value.trim());

  try {
    const data = await api('/audit-logs?' + q.toString());
    const items = data.items || [];
    const total = data.total || 0;
    const pages = Math.max(1, Math.ceil(total / AUDIT_PAGE_SIZE));

    root.innerHTML = `
      <div class="card">
        <div class="card-title">审计日志</div>
        <div class="toolbar">
          <select id="af-event" class="form-control" style="max-width:170px;">
            <option value="">全部事件</option>
            ${Object.keys(EVENT_TYPE_LABELS).map((t) =>
              `<option value="${t}" ${ev && ev.value === t ? 'selected' : ''}>${EVENT_TYPE_LABELS[t]}</option>`
            ).join('')}
          </select>
          <select id="af-result" class="form-control" style="max-width:120px;">
            <option value="">全部结果</option>
            <option value="success" ${rs && rs.value === 'success' ? 'selected' : ''}>成功</option>
            <option value="failure" ${rs && rs.value === 'failure' ? 'selected' : ''}>失败</option>
          </select>
          <input id="af-from" class="form-control" type="datetime-local" style="max-width:200px;" value="${from ? from.value : ''}">
          <span style="color:var(--text-secondary);">至</span>
          <input id="af-to" class="form-control" type="datetime-local" style="max-width:200px;" value="${to ? to.value : ''}">
          <input id="af-q" class="form-control" style="max-width:160px;" placeholder="关键词…" value="${kw ? escapeHtml(kw.value) : ''}">
          <button id="af-search-btn" class="btn btn-primary">筛选</button>
          <button id="af-reset-btn" class="btn">重置</button>
        </div>

        ${items.length === 0
          ? '<div class="empty">没有匹配的审计记录</div>'
          : `<div class="table-wrap"><table class="table">
              <thead><tr>
                <th>时间</th><th>事件</th><th>操作者</th><th>目标</th><th>结果</th><th>IP</th><th>请求 ID</th>
              </tr></thead>
              <tbody>
                ${items.map((e) => `<tr>
                  <td style="white-space:nowrap;">${escapeHtml(formatTime(e.event_time))}</td>
                  <td>${escapeHtml(eventTypeLabel(e.event_type))}</td>
                  <td>${escapeHtml(e.actor_name || '—')}</td>
                  <td>${escapeHtml(e.target_name || '—')}</td>
                  <td>${resultBadge(e.result)}</td>
                  <td>${escapeHtml(e.ip || '—')}</td>
                  <td><a class="detail-toggle" data-id="${e.id}" style="cursor:pointer;font-family:var(--font-mono);font-size:12px;">${escapeHtml((e.request_id || '').slice(0, 12))}…</a></td>
                </tr>
                <tr class="detail-row" id="detail-row-${e.id}">
                  <td colspan="7"><div class="detail-json">${escapeHtml(e.detail || '{}')}</div></td>
                </tr>`).join('')}
              </tbody>
            </table></div>`}

        <div class="pagination">
          <span>共 ${total} 条 · 第 ${auditPage}/${pages} 页</span>
          <button id="af-prev" class="btn btn-sm" ${auditPage <= 1 ? 'disabled' : ''}>上一页</button>
          <button id="af-next" class="btn btn-sm" ${auditPage >= pages ? 'disabled' : ''}>下一页</button>
        </div>
      </div>`;

    // 筛选 / 重置 / 分页。
    $('#af-search-btn').addEventListener('click', () => { auditPage = 1; loadAudit(); });
    $('#af-reset-btn').addEventListener('click', () => {
      $('#af-event').value = '';
      $('#af-result').value = '';
      $('#af-from').value = '';
      $('#af-to').value = '';
      $('#af-q').value = '';
      auditPage = 1;
      loadAudit();
    });
    $('#af-prev').addEventListener('click', () => { if (auditPage > 1) { auditPage--; loadAudit(); } });
    $('#af-next').addEventListener('click', () => { if (auditPage < pages) { auditPage++; loadAudit(); } });

    // detail 行展开（02 §6：可展开查看 detail JSON）。
    $$('.detail-toggle').forEach((a) => {
      a.addEventListener('click', () => {
        const row = document.getElementById('detail-row-' + a.dataset.id);
        if (row) row.classList.toggle('open');
      });
    });
  } catch (err) {
    toastError(err);
    root.innerHTML = '<div class="empty">加载失败，请刷新重试</div>';
  }
}
