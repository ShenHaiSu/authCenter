/* ============================================================
 * js/projects.js — 项目视图：列表/搜索/新建/编辑/启停/删除（02 §4）
 * API：GET/POST /projects、GET/PUT/DELETE /projects/{id}
 * ============================================================ */

let projectsQuery = '';
let projectsModal = null; // 新建/编辑模态框 DOM（单例）

async function loadProjects() {
  const root = document.getElementById('projects-root');
  root.innerHTML = '<div class="loading"><span class="spinner"></span>加载中…</div>';

  try {
    const data = await api('/projects?page=1&size=100&q=' + encodeURIComponent(projectsQuery));
    const items = data.items || [];

    root.innerHTML = `
      <div class="card">
        <div class="toolbar">
          <input id="project-search" class="form-control" style="max-width:280px;"
                 placeholder="按名称搜索…" value="${escapeHtml(projectsQuery)}">
          <button id="project-search-btn" class="btn">搜索</button>
          <span class="spacer"></span>
          <button id="project-create-btn" class="btn btn-primary">＋ 新建项目</button>
        </div>

        ${items.length === 0
          ? '<div class="empty">暂无项目，点击「新建项目」创建</div>'
          : `<div class="table-wrap"><table class="table">
              <thead><tr>
                <th>名称</th><th>当前版本</th><th>密钥数</th><th>状态</th><th>创建时间</th><th>操作</th>
              </tr></thead>
              <tbody>
                ${items.map((p) => `<tr>
                  <td><b>${escapeHtml(p.name)}</b></td>
                  <td class="mono">${escapeHtml(p.current_version || '—')}</td>
                  <td>${p.key_count || 0}</td>
                  <td>${activeBadge(p.is_active)}</td>
                  <td>${escapeHtml(formatTime(p.created_at))}</td>
                  <td class="actions">
                    <button class="btn btn-link" onclick="viewProjectKeys(${p.id}, '${escapeHtml(p.name)}')">查看密钥</button>
                    <button class="btn btn-link" onclick="openProjectModal(${p.id})">编辑</button>
                    <button class="btn btn-link" onclick="toggleProject(${p.id}, ${p.is_active})">${p.is_active ? '停用' : '启用'}</button>
                    <button class="btn btn-link-danger" onclick="deleteProject(${p.id}, '${escapeHtml(p.name)}')">删除</button>
                  </td>
                </tr>`).join('')}
              </tbody>
            </table></div>`}

        <div class="form-hint" style="margin-top:10px;">共 ${data.total || 0} 个项目</div>
      </div>`;

    $('#project-search').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        projectsQuery = e.target.value.trim();
        loadProjects();
      }
    });
    $('#project-search-btn').addEventListener('click', () => {
      projectsQuery = $('#project-search').value.trim();
      loadProjects();
    });
    $('#project-create-btn').addEventListener('click', () => openProjectModal(null));
  } catch (err) {
    toastError(err);
    root.innerHTML = '<div class="empty">加载失败，请刷新重试</div>';
  }
}

/** 进入密钥管理视图（02 §4：记录 state.currentProject）。 */
function viewProjectKeys(id, name) {
  state.currentProject = { id, name };
  showView('keys');
}

/** 启停项目（PUT is_active 取反）。 */
async function toggleProject(id, isActive) {
  try {
    await api('/projects/' + id, {
      method: 'PUT',
      body: { is_active: !isActive },
    });
    toast(isActive ? '项目已停用' : '项目已启用', 'success');
    loadProjects();
  } catch (err) {
    toastError(err);
  }
}

/** 删除项目：二次确认 + 级联删密钥提示（02 §4）。 */
function deleteProject(id, name) {
  confirmAction(`确定删除项目「${name}」吗？此操作将<b>级联删除其全部密钥</b>，且不可恢复！`, '删除项目', async () => {
    await api('/projects/' + id, { method: 'DELETE' });
    toast('项目已删除', 'success');
    loadProjects();
  });
}

/* ---------------- 新建 / 编辑模态框（02 §4） ---------------- */

function ensureProjectsModal() {
  if (projectsModal) return;
  const mask = document.createElement('div');
  mask.id = 'project-modal';
  mask.className = 'modal-mask';
  mask.innerHTML = `
    <div class="modal">
      <div class="modal-header">
        <h3 id="project-modal-title">新建项目</h3>
        <button type="button" class="modal-close" data-close>×</button>
      </div>
      <form id="project-form" autocomplete="off">
        <div class="form-group">
          <label class="required" for="pj-name">名称</label>
          <input id="pj-name" class="form-control" type="text" placeholder="如 my-service" required maxlength="128">
          <div class="form-hint">项目名唯一，外部认证时以此标识项目</div>
        </div>
        <div class="form-group">
          <label for="pj-desc">描述</label>
          <input id="pj-desc" class="form-control" type="text" placeholder="可选">
        </div>
        <div class="form-group">
          <label class="required" for="pj-ver">当前版本</label>
          <input id="pj-ver" class="form-control" type="text" placeholder="1.0.0">
        </div>
        <div class="form-group">
          <label for="pj-minver">最低版本（可选）</label>
          <input id="pj-minver" class="form-control" type="text" placeholder="留空 = 不限制版本">
        </div>
        <div class="modal-footer">
          <button type="button" class="btn" data-close>取消</button>
          <button type="submit" id="project-save-btn" class="btn btn-primary">保存</button>
        </div>
      </form>
    </div>`;
  document.body.appendChild(mask);
  projectsModal = mask;

  $('#project-form', mask).addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = mask.dataset.projectId || null;
    const name = $('#pj-name', mask).value.trim();
    const description = $('#pj-desc', mask).value.trim();
    const currentVersion = $('#pj-ver', mask).value.trim();
    const minVersionRaw = $('#pj-minver', mask).value.trim();
    const minVersion = minVersionRaw === '' ? null : minVersionRaw;

    if (!name) { toast('项目名称不能为空', 'warning'); return; }

    try {
      await withSubmitting($('#project-save-btn', mask), () => {
        if (id) {
          // 编辑：PUT 为全量语义（05 §4.2），需传完整字段。
          return api('/projects/' + id, {
            method: 'PUT',
            body: { description, current_version: currentVersion, min_version: minVersion, is_active: true },
          });
        }
        return api('/projects', {
          method: 'POST',
          body: { name, description, current_version: currentVersion, min_version: minVersion },
        });
      });
      closeModal('project-modal');
      toast(id ? '项目已更新' : '项目已创建', 'success');
      loadProjects();
    } catch (err) {
      // 409/20201 名称冲突（02 §4：提示改名字）。
      if (err && err.code === 20201) {
        toast('名称已被占用，请更换项目名', 'warning');
      } else {
        toastError(err);
      }
    }
  });
}

/** 打开新建（null）或编辑（id）模态框。 */
async function openProjectModal(id) {
  ensureProjectsModal();
  $('#project-modal-title').textContent = id ? '编辑项目' : '新建项目';

  if (id) {
    // 预填当前值（GET 详情）。
    try {
      const data = await api('/projects/' + id);
      const p = data.project;
      $('#pj-name', projectsModal).value = p.name;
      $('#pj-desc', projectsModal).value = p.description || '';
      $('#pj-ver', projectsModal).value = p.current_version || '';
      $('#pj-minver', projectsModal).value = p.min_version || '';
      // 编辑时名称不可改（唯一标识，保持简单）。
      $('#pj-name', projectsModal).disabled = true;
      projectsModal.dataset.projectId = String(id);
    } catch (err) {
      toastError(err);
      return;
    }
  } else {
    $('#pj-name', projectsModal).disabled = false;
    $('#pj-name', projectsModal).value = '';
    $('#pj-desc', projectsModal).value = '';
    $('#pj-ver', projectsModal).value = '';
    $('#pj-minver', projectsModal).value = '';
    delete projectsModal.dataset.projectId;
  }

  openModal('project-modal');
  setTimeout(() => $('#pj-name', projectsModal).focus(), 50);
}
