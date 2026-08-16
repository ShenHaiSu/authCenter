package httpapi

import (
	"net/http"
	"time"

	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/service"
)

// keyHandlers 密钥管理 handlers（文档 05 §4.3）。
type keyHandlers struct {
	apikeys *service.ApiKeyService
}

// createKeyRequest 生成密钥请求（05 §4.3）。
type createKeyRequest struct {
	Name        string     `json:"name"`
	ExpiresAt   *time.Time `json:"expires_at"`  // null=永不过期
	Fingerprint *string    `json:"fingerprint"` // null=不绑定
}

// keyView 密钥列表项：附 has_fingerprint 布尔（05 §4.3），永不含 key_value。
type keyView struct {
	ID             int64      `json:"id"`
	ProjectID      int64      `json:"project_id"`
	Name           string     `json:"name"`
	HasFingerprint bool       `json:"has_fingerprint"`
	Fingerprint    *string    `json:"fingerprint"`
	ExpiresAt      *time.Time `json:"expires_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP     string     `json:"last_used_ip,omitempty"`
	IsActive       bool       `json:"is_active"`
	CreatedBy      string     `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
}

func toKeyView(k *model.APIKey) keyView {
	return keyView{
		ID:             k.ID,
		ProjectID:      k.ProjectID,
		Name:           k.Name,
		HasFingerprint: k.Fingerprint != nil && *k.Fingerprint != "",
		Fingerprint:    k.Fingerprint,
		ExpiresAt:      k.ExpiresAt,
		LastUsedAt:     k.LastUsedAt,
		LastUsedIP:     k.LastUsedIP,
		IsActive:       k.IsActive,
		CreatedBy:      k.CreatedBy,
		CreatedAt:      k.CreatedAt,
	}
}

// handleListKeys GET /api/v1/projects/{id}/keys?page=&size=&active=
func (h *keyHandlers) handleListKeys(w http.ResponseWriter, r *http.Request) {
	projectID := pathID(r)
	page, size := parsePagination(r)
	active := parseBoolParam(r, "active")
	keys, total, err := h.apikeys.List(r.Context(), projectID, active, page, size)
	if err != nil {
		failService(w, err)
		return
	}
	items := make([]keyView, 0, len(keys))
	for i := range keys {
		items = append(items, toKeyView(&keys[i]))
	}
	ok(w, map[string]any{"items": items, "total": total, "page": page, "size": size})
}

// handleCreateKey POST /api/v1/projects/{id}/keys：
// 明文 key_value 仅此一次返回（05 §4.3）。
func (h *keyHandlers) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	projectID := pathID(r)
	var req createKeyRequest
	if err := DecodeJSON(w, r, &req); err != nil {
		return
	}
	if req.Name == "" {
		fail(w, http.StatusBadRequest, CodeInvalidParam, "密钥备注不能为空")
		return
	}
	k, plain, err := h.apikeys.Create(r.Context(), currentUser(r), projectID, req.Name, req.ExpiresAt, req.Fingerprint, clientIP(r))
	if err != nil {
		failService(w, err)
		return
	}
	okStatus(w, http.StatusCreated, map[string]any{
		"key":       toKeyView(k),
		"key_value": plain, // 唯一一次明文
	})
}

// updateKeyRequest 更新密钥请求：null 字段=不改动（05 §4.3）。
type updateKeyRequest struct {
	Name        *string    `json:"name"`
	ExpiresAt   *time.Time `json:"expires_at"`  // null=不改动
	Fingerprint *string    `json:"fingerprint"` // null=不改动
	IsActive    *bool      `json:"is_active"`
}

// handleUpdateKey PUT /api/v1/keys/{id}
func (h *keyHandlers) handleUpdateKey(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	old, err := h.apikeys.Get(r.Context(), id)
	if err != nil {
		failService(w, err)
		return
	}
	var req updateKeyRequest
	if err := DecodeJSON(w, r, &req); err != nil {
		return
	}
	// null=不改动：nil 时保留原值。
	name := old.Name
	if req.Name != nil {
		name = *req.Name
	}
	expiresAt := old.ExpiresAt
	if req.ExpiresAt != nil {
		expiresAt = req.ExpiresAt
	}
	fp := old.Fingerprint
	if req.Fingerprint != nil {
		fp = req.Fingerprint
	}
	isActive := old.IsActive
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	k, err := h.apikeys.Update(r.Context(), currentUser(r), id, name, expiresAt, fp, isActive, clientIP(r))
	if err != nil {
		failService(w, err)
		return
	}
	ok(w, map[string]any{"key": toKeyView(k)})
}

// handleRotateKey POST /api/v1/keys/{id}/rotate：
// 新密钥明文仅一次返回；旧密钥进入宽限期（05 §4.3 / 04 §3.5）。
func (h *keyHandlers) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	newKey, plain, graceUntil, err := h.apikeys.Rotate(r.Context(), currentUser(r), id, clientIP(r))
	if err != nil {
		failService(w, err)
		return
	}
	ok(w, map[string]any{
		"new_key": map[string]any{
			"id":         newKey.ID,
			"key_value":  plain, // 唯一一次明文
			"expires_at": newKey.ExpiresAt,
		},
		"old_key_grace_until": graceUntil,
	})
}

// handleDeleteKey DELETE /api/v1/keys/{id}：204，立即失效（软删）。
func (h *keyHandlers) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if err := h.apikeys.Delete(r.Context(), currentUser(r), id, clientIP(r)); err != nil {
		failService(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
