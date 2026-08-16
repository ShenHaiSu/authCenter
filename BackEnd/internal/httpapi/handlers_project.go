package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/authcenter/authcenter/internal/service"
)

// projectHandlers 项目管理 handlers（文档 05 §4.2）。
type projectHandlers struct {
	projects *service.ProjectService
	apikeys  *service.ApiKeyService
}

// createProjectRequest 创建项目请求。
type createProjectRequest struct {
	Name           string  `json:"name"`
	Description    string  `json:"description"`
	CurrentVersion string  `json:"current_version"`
	MinVersion     *string `json:"min_version"`
}

// handleListProjects GET /api/v1/projects?page=&size=&q=&active=
func (h *projectHandlers) handleListProjects(w http.ResponseWriter, r *http.Request) {
	page, size := parsePagination(r)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	active := parseBoolParam(r, "active")
	items, total, err := h.projects.List(r.Context(), q, active, page, size)
	if err != nil {
		failService(w, err)
		return
	}
	ok(w, map[string]any{"items": items, "total": total, "page": page, "size": size})
}

// handleCreateProject POST /api/v1/projects
func (h *projectHandlers) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	var req createProjectRequest
	if err := DecodeJSON(w, r, &req); err != nil {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		fail(w, http.StatusBadRequest, CodeInvalidParam, "项目名称不能为空")
		return
	}
	p, err := h.projects.Create(r.Context(), currentUser(r), req.Name, req.Description, req.CurrentVersion, req.MinVersion, clientIP(r))
	if err != nil {
		failService(w, err)
		return
	}
	okStatus(w, http.StatusCreated, map[string]any{"project": p})
}

// handleGetProject GET /api/v1/projects/{id}：返回项目 + 全部密钥（05 §4.2）。
func (h *projectHandlers) handleGetProject(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	p, err := h.projects.Get(r.Context(), id)
	if err != nil {
		failService(w, err)
		return
	}
	keys, _, err := h.apikeys.List(r.Context(), id, nil, 1, 100)
	if err != nil {
		failService(w, err)
		return
	}
	ok(w, map[string]any{"project": p, "keys": keys})
}

// updateProjectRequest 更新项目请求（PUT 为全量语义，文档 05 §4.2）。
type updateProjectRequest struct {
	Description    string  `json:"description"`
	CurrentVersion string  `json:"current_version"`
	MinVersion     *string `json:"min_version"`
	IsActive       bool    `json:"is_active"`
}

// handleUpdateProject PUT /api/v1/projects/{id}
func (h *projectHandlers) handleUpdateProject(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	var req updateProjectRequest
	if err := DecodeJSON(w, r, &req); err != nil {
		return
	}
	p, err := h.projects.Update(r.Context(), currentUser(r), id, req.Description, req.CurrentVersion, req.MinVersion, req.IsActive, clientIP(r))
	if err != nil {
		failService(w, err)
		return
	}
	ok(w, map[string]any{"project": p})
}

// handleDeleteProject DELETE /api/v1/projects/{id}：204，级联删密钥。
func (h *projectHandlers) handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if err := h.projects.Delete(r.Context(), currentUser(r), id, clientIP(r)); err != nil {
		failService(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// pathID 从请求路径取 {id} 并解析为 int64；非法返回 0（路由已限定格式）。
func pathID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}
