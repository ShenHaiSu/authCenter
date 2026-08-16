package httpapi

import (
	"log/slog"
	"net/http"

	"github.com/authcenter/authcenter/internal/service"
	"github.com/authcenter/authcenter/internal/store"
)

// RouterDeps 路由装配依赖（httpapi → service → store，文档 04 §1 依赖规则）。
type RouterDeps struct {
	Logger   *slog.Logger
	Store    *store.Store
	Sessions *service.SessionService
	Projects *service.ProjectService
	Apikeys  *service.ApiKeyService
	Audits   *service.AuditService
	Auths    *service.AuthService
}

// New 装配路由与中间件（M2：管理 API 全量；M3：对外认证 API）。
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

	// 根路径占位：M4 内嵌 web 后替换为 http.FileServer（07 §2）。
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			fail(w, http.StatusNotFound, CodeNotFound, "资源不存在")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>AuthCenter</title></head><body>
<h1>AuthCenter 中心认证服务</h1>
<p>服务运行中（M2 骨架）。管理界面将在后续里程碑提供。</p>
<p>健康检查：<a href="/healthz">/healthz</a></p>
</body></html>`))
	})

	// 中间件链（由外到内：Recover → RequestID → AccessLog → LimitBody）。
	return Recover(RequestID(AccessLog(deps.Logger)(LimitBody(mux))))
}
