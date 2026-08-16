/* ============================================================
 * js/guide.js — 管理员使用教程（静态内容，无 API 调用）
 * 新界面设计 01（Documents/newInterfaceDesign/01-管理员使用教程界面设计.md）
 * 前端架构文档 02 §10
 * 块类型：p / steps / tip / warn / table / img
 * ============================================================ */

/** 行内 Markdown 渲染：先 escapeHtml，再受限还原 **粗体** 与 `行内代码`。 */
function guideInline(text) {
  return escapeHtml(text)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
}

/** 渲染单个内容块 → HTML 字符串。 */
function guideBlockHtml(b) {
  switch (b.type) {
    case 'p':
      return `<p>${guideInline(b.md)}</p>`;
    case 'steps':
      return `<ol class="guide-steps">${b.items.map((it) => `<li>${guideInline(it)}</li>`).join('')}</ol>`;
    case 'tip':
      return `<div class="callout callout-tip">${guideInline(b.md)}</div>`;
    case 'warn':
      return `<div class="callout callout-warn">${guideInline(b.md)}</div>`;
    case 'table':
      return `<div class="table-wrap"><table class="table">
        <thead><tr>${b.headers.map((h) => `<th>${guideInline(h)}</th>`).join('')}</tr></thead>
        <tbody>${b.rows.map((r) => `<tr>${r.map((c) => `<td>${guideInline(c)}</td>`).join('')}</tr>`).join('')}</tbody>
      </table></div>`;
    case 'img':
      return `<div class="guide-shot">📷 截图占位：${escapeHtml(b.desc)}</div>`;
    default:
      return '';
  }
}

/** 教程内容数据（唯一事实源，§1-§7；与当前界面实际交互逐项核对）。 */
const GUIDE_SECTIONS = [
  {
    id: 'setup',
    title: '1. 首次部署与登录',
    blocks: [
      { type: 'p', md: 'AuthCenter 支持两种部署形态：发布包直跑与系统服务托管。' },
      {
        type: 'steps',
        items: [
          '发布包：进入 `Bundle/{windows,linux}` 对应目录，运行 `authcenter(.exe) -data-dir ./data` 启动服务',
          '系统服务：Windows 用 NSSM、Linux 用 systemd 托管（示例见 `deploy/` 目录）',
        ],
      },
      { type: 'p', md: '首次启动时，服务会在**控制台**打印初始密码，并写入 `data/auth.log`（30 位随机串，仅此一次，重启不会重复生成）。' },
      { type: 'warn', md: '初始密码丢失无法找回：只能删除 `data/authcenter.db` 后重新初始化（会清空全部数据）。' },
      { type: 'p', md: '登录步骤：' },
      {
        type: 'steps',
        items: [
          '浏览器访问 `http://127.0.0.1:53779`',
          '输入用户名 `admin` 与初始密码，点击「登录」',
          '点击右上角「登出」退出到登录页；会话 7 天有效，修改密码后会注销全部会话',
        ],
      },
      { type: 'tip', md: '登录失败会触发锁定：每 IP 每分钟 5 次、同用户名连续失败 5 次锁 15 分钟，界面提示「尝试过于频繁，请 15 分钟后再试」。' },
      { type: 'img', desc: '登录页（用户名 + 密码 + 登录按钮）' },
    ],
  },
  {
    id: 'dashboard',
    title: '2. 仪表盘',
    blocks: [
      { type: 'p', md: '仪表盘是登录后的默认视图，展示系统运行概览。' },
      {
        type: 'table',
        headers: ['统计卡', '内容', '点击行为'],
        rows: [
          ['项目数', '全部项目数量', '跳转项目视图'],
          ['有效密钥数', '启用状态的密钥总数', '跳转项目视图'],
          ['7 天内到期密钥', '即将到期数量（黄色 = 有风险）', '跳转项目视图'],
          ['今日认证', '成功 / 失败次数', '跳转审计日志'],
        ],
      },
      { type: 'p', md: '下方「最近认证事件」表展示最近 10 条外部认证记录（时间 / 项目 / 结果 / 指纹 / IP），点击「查看全部」进入审计日志。' },
      { type: 'warn', md: '当有密钥将在 7 天内到期时，仪表盘顶部会显示黄色提示条，请及时轮换处理。' },
      { type: 'img', desc: '仪表盘（四张统计卡 + 最近认证事件表）' },
    ],
  },
  {
    id: 'projects',
    title: '3. 项目管理',
    blocks: [
      {
        type: 'table',
        headers: ['操作', '步骤', '注意'],
        rows: [
          ['新建项目', '项目 → ＋新建项目 → 填写名称 / 描述 / 当前版本 / 最低版本 → 保存', '名称唯一，外部认证以 `project_name` 精确匹配'],
          ['搜索', '输入名称关键词 → 回车或点「搜索」', '—'],
          ['编辑', '点「编辑」→ 修改描述 / 当前版本 / 最低版本 → 保存', '名称不可修改（唯一标识）'],
          ['停用 / 启用', '点「停用」/「启用」按钮', '停用后外部认证返回 `project_disabled`'],
          ['删除', '点「删除」→ 二次确认', '⚠ 级联删除该项目全部密钥，**不可恢复**'],
        ],
      },
      { type: 'tip', md: '`min_version` 留空 = 不限制版本；填写后，低于该版本的客户端认证将返回 `version_too_old`。' },
      { type: 'p', md: '项目列表展示名称、当前版本、密钥数、状态与创建时间；「查看密钥」进入该项目的密钥管理。' },
      { type: 'img', desc: '项目列表（工具栏 + 表格 + 行操作）' },
    ],
  },
  {
    id: 'keys',
    title: '4. 密钥管理',
    blocks: [
      {
        type: 'steps',
        items: [
          '进入：项目列表 → 点「查看密钥」进入该项目密钥管理',
          '生成密钥：点「＋生成密钥」→ 填写备注（必填）/ 过期时间（留空 = 永不过期）/ 绑定指纹（可选）→ 保存',
          '编辑：修改备注 / 过期时间 / 指纹 / 状态；编辑时指纹留空 = 解绑',
          '启停：禁用后外部认证返回 `key_disabled`',
          '轮换：二次确认 → 生成新密钥，旧密钥保留 7 天宽限期（宽限期内仍可认证，期满自动失效）',
          '吊销：二次确认 → **立即失效**，使用该密钥的客户端即刻无法认证',
        ],
      },
      { type: 'warn', md: '密钥明文**仅显示一次**：生成 / 轮换后立即复制保存，关闭模态框后不可再次查看；列表永不显示明文。' },
      { type: 'p', md: '状态筛选支持 全部 / 启用 / 停用 / 已过期；过期时间以徽章显示：`永不过期` / `N 天后`（黄）/ `已过期`（红）。' },
      { type: 'tip', md: '轮换适用于密钥疑似泄露、例行换密或到期前预防性轮换；宽限期内新旧密钥并行，便于灰度切换。' },
      { type: 'img', desc: '密钥列表（筛选 + 表格 + 生成密钥按钮）' },
    ],
  },
  {
    id: 'audit',
    title: '5. 审计日志',
    blocks: [
      { type: 'p', md: '审计日志记录全部管理操作与外部认证事件，可按条件检索。' },
      {
        type: 'steps',
        items: [
          '筛选：事件类型（登录 / 项目 / 密钥 / 认证…）/ 结果（成功/失败）/ 时间范围 / 关键词',
          '表格：时间 / 事件类型 / 操作者 / 目标 / 结果 / IP / 请求 ID',
          '点击请求 ID 可展开 detail JSON（失败原因、指纹、版本等）',
          '分页：上一页 / 下一页 + 总数',
        ],
      },
      { type: 'tip', md: '常用排查：外部认证失败 → 筛选事件类型 `auth.authenticate_failed` → 展开 detail 查看 `reason`（如 `key_expired`、`fingerprint_mismatch`）。' },
      { type: 'img', desc: '审计日志（筛选区 + 表格 + 分页）' },
    ],
  },
  {
    id: 'password',
    title: '6. 修改密码',
    blocks: [
      {
        type: 'steps',
        items: [
          '进入「修改密码」视图',
          '填写旧密码与新密码（≥ 12 位，且同时包含字母与数字；有实时强度提示）',
          '再次确认新密码 → 提交',
        ],
      },
      { type: 'warn', md: '提交成功后将被退出登录，需用新密码重新登录。' },
      { type: 'tip', md: '建议拿到初始密码后第一件事就是修改密码。' },
      { type: 'img', desc: '修改密码表单（旧密码 / 新密码 / 确认新密码）' },
    ],
  },
  {
    id: 'safety',
    title: '7. 安全红线（必读）',
    blocks: [
      { type: 'p', md: '以下红线与纪律为管理员必须遵守的操作底线：' },
      {
        type: 'table',
        headers: ['红线', '说明'],
        rows: [
          ['🔴 密钥明文只展示一次', '生成 / 轮换后立即复制；关闭模态框即无法找回'],
          ['🔴 初始密码立即修改', '首次登录后立刻改密，勿长期使用打印在控制台的密码'],
          ['🔴 删除项目 / 吊销密钥不可逆', '操作前确认级联影响（项目删除 = 全部密钥失效；吊销 = 立即失效）'],
          ['🟡 密钥轮换纪律', '到期前、疑似泄露时及时轮换；宽限期内新旧密钥并行，便于灰度'],
          ['🟡 指纹绑定', '高价值项目建议绑定指纹，防密钥被拷走异地使用'],
          ['🟡 会话安全', '会话 7 天有效；改密会注销全部会话；不要在公用机器长期保持登录'],
          ['🟡 端口不对外', '服务仅监听 `127.0.0.1:53779`，勿开放入站防火墙端口；对外一律走 Caddy HTTPS 反代'],
        ],
      },
      { type: 'warn', md: '遇到不确定的操作，先查阅本教程对应小节；危险操作均有二次确认，请勿盲目跳过。' },
    ],
  },
];

/** 渲染教程视图（顶部卡片 + 左 TOC + 右内容）。 */
function loadGuide() {
  const root = document.getElementById('guide-root');
  try {
    root.innerHTML = `
      <div class="card">
        <div class="card-title">📖 AuthCenter 管理界面使用教程</div>
        <div class="form-hint">本文档覆盖本界面全部功能，按左侧小节阅读；涉及危险操作处均有红色警示。静态内容，无需联网。</div>
      </div>
      <div class="guide-layout">
        <nav class="guide-toc">
          ${GUIDE_SECTIONS.map((s) => `<a href="#guide-${s.id}" data-anchor="${s.id}">${escapeHtml(s.title)}</a>`).join('')}
        </nav>
        <div class="guide-content">
          ${GUIDE_SECTIONS.map((s) => `
            <section class="guide-section" id="guide-${s.id}">
              <h3>${escapeHtml(s.title)}</h3>
              ${s.blocks.map(guideBlockHtml).join('')}
            </section>`).join('')}
        </div>
      </div>`;
    bindGuideToc();
  } catch (err) {
    toastError(err);
    root.innerHTML = '<div class="empty">教程加载失败，请刷新重试</div>';
  }
}

/** TOC 锚点点击平滑滚动（02 §10）。 */
function bindGuideToc() {
  $$('.guide-toc a[data-anchor]').forEach((a) => {
    a.addEventListener('click', (e) => {
      e.preventDefault();
      const el = document.getElementById('guide-' + a.dataset.anchor);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });
}
