package httpapi

import (
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/authcenter/authcenter/internal/service"
	"github.com/authcenter/authcenter/internal/store"
	"github.com/authcenter/authcenter/internal/web"
)

type RouterDeps struct {
	Logger    *slog.Logger
	Store     *store.Store
	Sessions  *service.SessionService
	Projects  *service.ProjectService
	Apikeys   *service.ApiKeyService
	Audits    *service.AuditService
	Auths     *service.AuthService
	Stats     *service.StatsService
	Settings  *service.SettingsService
	Retention *service.AuditRetentionService
	Admins    *service.AdminUserService
	Runner    *service.MaintenanceRunner
	// WebFS 前端静态资源树（已剥离目录前缀）。nil = 使用 go:embed 内嵌
	// （发布二进制；开发模式由 main 注入 os.DirFS，文档 07 §2.3）。
	WebFS fs.FS
}

// New 装配路由与中间件（M2：管理 API 全量；M3：对外认证 API；M4：前端静态资源 + 统计）。
func New(deps RouterDeps) http.Handler {
	mux := http.NewServeMux()

	// 运维接口（文档 07 §5.3，公开）。
	mux.HandleFunc("GET /healthz", healthz)

	// 对外认证 API（05 §3，公开，无会话）：POST /api/v1/authenticate。
	hAuth := &authHandlers{auths: deps.Auths}
	mux.HandleFunc("POST /api/v1/authenticate", hAuth.handleAuthenticate)

	// 管理员会话（05 §4.1）：登录公开，其余需会话。
	hAdmin := &adminHandlers{sessions: deps.Sessions}
	mux.HandleFunc("POST /api/v1/admin/login", hAdmin.handleLogin)

	requireAdmin := RequireAdmin(deps.Store)
	mux.HandleFunc("POST /api/v1/admin/logout", requireAdmin(hAdmin.handleLogout))
	mux.HandleFunc("GET /api/v1/admin/me", requireAdmin(hAdmin.handleMe))

	// 管理员账号管理（F-020 need01 02 §5）：全部需 **owner**。
	// requireOwner 挂在 RequireAdmin 之后：RequireAdmin 先解析会话归属与角色，再判 owner。
	if deps.Admins != nil {
		hAdmins := &adminUserHandlers{admins: deps.Admins}
		requireOwner := func(h func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
			return requireAdmin(requireOwner(h))
		}
		mux.HandleFunc("GET /api/v1/admins", requireOwner(hAdmins.handleListAdmins))
		mux.HandleFunc("POST /api/v1/admins", requireOwner(hAdmins.handleCreateAdmin))
		mux.HandleFunc("PUT /api/v1/admins/{id}", requireOwner(hAdmins.handleUpdateAdmin))
		mux.HandleFunc("PUT /api/v1/admins/{id}/password", requireOwner(hAdmins.handleResetAdminPassword))
	}
	mux.HandleFunc("PUT /api/v1/admin/password", requireAdmin(hAdmin.handleChangePassword))

	// 项目（05 §4.2）。
	hProj := &projectHandlers{projects: deps.Projects, apikeys: deps.Apikeys}
	mux.HandleFunc("GET /api/v1/projects", requireAdmin(hProj.handleListProjects))
	mux.HandleFunc("POST /api/v1/projects", requireAdmin(hProj.handleCreateProject))
	mux.HandleFunc("GET /api/v1/projects/{id}", requireAdmin(hProj.handleGetProject))
	mux.HandleFunc("PUT /api/v1/projects/{id}", requireAdmin(hProj.handleUpdateProject))
	mux.HandleFunc("DELETE /api/v1/projects/{id}", requireAdmin(hProj.handleDeleteProject))

	// 密钥（05 §4.3）。
	hKey := &keyHandlers{apikeys: deps.Apikeys}
	mux.HandleFunc("GET /api/v1/projects/{id}/keys", requireAdmin(hKey.handleListKeys))
	mux.HandleFunc("POST /api/v1/projects/{id}/keys", requireAdmin(hKey.handleCreateKey))
	mux.HandleFunc("PUT /api/v1/keys/{id}", requireAdmin(hKey.handleUpdateKey))
	mux.HandleFunc("POST /api/v1/keys/{id}/rotate", requireAdmin(hKey.handleRotateKey))
	mux.HandleFunc("DELETE /api/v1/keys/{id}", requireAdmin(hKey.handleDeleteKey))

	// 审计日志（05 §4.4）。
	hAudit := &auditHandlers{audits: deps.Audits}
	mux.HandleFunc("GET /api/v1/audit-logs", requireAdmin(hAudit.handleListAuditLogs))

	// 仪表盘统计（05 §4.5，M4 落地：前端仪表盘数据源）。
	if deps.Stats != nil {
		hStats := &statsHandlers{stats: deps.Stats}
		mux.HandleFunc("GET /api/v1/stats", requireAdmin(hStats.handleStats))
	}
	// 系统设置（need01 01 §5：保留策略 + 用量 + 手动维护，全部需会话）。
	if deps.Settings != nil && deps.Retention != nil {
		hSettings := &settingsHandlers{settings: deps.Settings, retention: deps.Retention, runner: deps.Runner}
		mux.HandleFunc("GET /api/v1/settings", requireAdmin(hSettings.handleGetSettings))
		mux.HandleFunc("PUT /api/v1/settings", requireAdmin(hSettings.handleUpdateSettings))
		mux.HandleFunc("POST /api/v1/settings/audit/cleanup-now", requireAdmin(hSettings.handleCleanupNow))
		mux.HandleFunc("POST /api/v1/settings/audit/checkpoint", requireAdmin(hSettings.handleCheckpoint))
		// F-021：启用密钥存储加密（破坏性，只提供启用；前端走 confirmAction 二次确认）。
		mux.HandleFunc("POST /api/v1/settings/key-encryption/enable", requireAdmin(hSettings.handleEnableKeyEncryption))
	}

	// 前端静态资源（M4：内嵌 web 或 -web-dir 磁盘目录，文档 07 §2）。
	mux.Handle("/", webHandler(assetsFS(deps.WebFS)))

	// 中间件链（由外到内：Recover → RequestID → AccessLog → LimitBody）。
	return Recover(RequestID(AccessLog(deps.Logger)(LimitBody(mux))))
}

// assetsFS 解析前端资源树：优先注入的 WebFS（main 按 -web-dir 决定），否则用内嵌。
func assetsFS(injected fs.FS) fs.FS {
	if injected != nil {
		return injected
	}
	// 内嵌 FS 路径带 "web/" 前缀，剥离后供 FileServer 使用（07 §2.2）。
	if assets, err := web.Assets(); err == nil {
		return assets
	}
	return nil
}

// webHandler 服务前端静态资源；拦截目录请求避免目录列表（安全约束，06 §11）。
func webHandler(assets fs.FS) http.Handler {
	if assets == nil {
		// 内嵌资源不可用（极端情况）：返回 404 JSON。
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fail(w, http.StatusNotFound, CodeNotFound, "资源不存在")
		})
	}
	fileServer := http.FileServer(http.FS(assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// "/css/" 这类目录请求不提供目录列表，统一 404。
		if r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/") {
			fail(w, http.StatusNotFound, CodeNotFound, "资源不存在")
			return
		}
		// /api/ 未注册路径保持 JSON 404（05 §1 响应约定），不落 FileServer。
		if strings.HasPrefix(r.URL.Path, "/api/") {
			fail(w, http.StatusNotFound, CodeNotFound, "资源不存在")
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
