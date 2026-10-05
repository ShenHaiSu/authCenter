// handlers_admin_user.go — F-020 管理员账号管理端点（need01 02 §5）。
// 全部需 owner（requireOwner 包装，见 router.go）；两角色除本组端点外权限相同。
package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/service"
)

// adminUserHandlers /api/v1/admins* handlers。
type adminUserHandlers struct {
	admins *service.AdminUserService
}

// adminUserView 管理员响应视图（手工投影，密码哈希绝不出现在任何响应）。
type adminUserView struct {
	ID                  int64   `json:"id"`
	Username            string  `json:"username"`
	Role                string  `json:"role"`
	IsActive            bool    `json:"is_active"`
	ForcePasswordChange bool    `json:"force_password_change"`
	CreatedAt           string  `json:"created_at"`
	UpdatedAt           *string `json:"updated_at"`
	LastLoginAt         *string `json:"last_login_at"`
	LastLoginIP         string  `json:"last_login_ip,omitempty"`
}

// adminJSONUser 把 model.AdminUser 投影为响应视图（剥离密码哈希）。
func adminJSONUser(u *model.AdminUser) adminUserView {
	return adminUserView{
		ID:                  u.ID,
		Username:            u.Username,
		Role:                u.Role,
		IsActive:            u.IsActive,
		ForcePasswordChange: u.ForcePasswordChange,
		CreatedAt:           formatISOTime(u.CreatedAt),
		UpdatedAt:           formatISOTimePtr(u.UpdatedAt),
		LastLoginAt:         formatISOTimePtr(u.LastLoginAt),
		LastLoginIP:         u.LastLoginIP,
	}
}

// formatISOTime 时间 → ISO8601 UTC 字符串；零值返回 ""（界面显示为 —）。
func formatISOTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// formatISOTimePtr 时间指针 → ISO8601 字符串指针（nil 透传，响应中为 null）。
func formatISOTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := formatISOTime(*t)
	return &s
}

// adminPathID 解析路径参数 {id}（非法或非正整数返回 false）。
func adminPathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// failAdminUser 管理员管理端点的失败响应：在 failService 基础上保留 service 层的具体提示。
//
// 必要性：R1/R2 的护栏文案（「系统必须至少保留一个启用的超级管理员」「不能对自己执行此操作」）
// 是 owner 判断下一步操作的关键信息（need01 02 §5.3 要求 409 响应带该文案），
// 而 failService 对 ErrStateConflict 只回固定文案「资源状态不允许」。
func failAdminUser(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrStateConflict):
		fail(w, http.StatusConflict, CodeStateConflict, adminUserErrMsg(err))
	case errors.Is(err, service.ErrInvalidParameter):
		fail(w, http.StatusBadRequest, CodeInvalidParam, adminUserErrMsg(err))
	case errors.Is(err, service.ErrPasswordTooWeak):
		fail(w, http.StatusBadRequest, CodeValidationFailed, err.Error())
	default:
		failService(w, err)
	}
}

// adminUserErrMsg 提取哨兵错误包装出的具体提示（去掉 "state conflict: " 等前缀）。
func adminUserErrMsg(err error) string {
	msg := err.Error()
	for _, prefix := range []string{
		service.ErrStateConflict.Error() + ": ",
		service.ErrInvalidParameter.Error() + ": ",
	} {
		msg = strings.TrimPrefix(msg, prefix)
	}
	if msg == "" {
		return "资源状态不允许"
	}
	return msg
}

// handleListAdmins GET /api/v1/admins（需 owner）：分页列表，?page=&size=。
func (h *adminUserHandlers) handleListAdmins(w http.ResponseWriter, r *http.Request) {
	page, size := parsePagination(r)
	items, total, err := h.admins.List(r.Context(), page, size)
	if err != nil {
		failAdminUser(w, err)
		return
	}
	views := make([]adminUserView, 0, len(items))
	for i := range items {
		views = append(views, adminJSONUser(&items[i]))
	}
	ok(w, map[string]any{"total": total, "page": page, "size": size, "items": views})
}

// createAdminRequest POST /api/v1/admins 请求体。
type createAdminRequest struct {
	Username            string `json:"username"`
	Password            string `json:"password"`
	Role                string `json:"role"`
	ForcePasswordChange *bool  `json:"force_password_change"`
}

// handleCreateAdmin POST /api/v1/admins（需 owner）：201 + 新用户；同名 409/20201。
func (h *adminUserHandlers) handleCreateAdmin(w http.ResponseWriter, r *http.Request) {
	var req createAdminRequest
	if err := DecodeJSON(w, r, &req); err != nil {
		return
	}
	// 默认要求下次登录改密：owner 只是代设初始密码。
	forceChange := true
	if req.ForcePasswordChange != nil {
		forceChange = *req.ForcePasswordChange
	}
	role := req.Role
	if role == "" {
		role = model.RoleAdmin
	}
	u, err := h.admins.Create(r.Context(), currentUser(r), req.Username, req.Password, role, forceChange, clientIP(r))
	if err != nil {
		failAdminUser(w, err)
		return
	}
	okStatus(w, http.StatusCreated, map[string]any{"user": adminJSONUser(u)})
}

// updateAdminRequest PUT /api/v1/admins/{id} 请求体（部分更新，三字段均可选）。
type updateAdminRequest struct {
	Role                *string `json:"role"`
	IsActive            *bool   `json:"is_active"`
	ForcePasswordChange *bool   `json:"force_password_change"`
}

// handleUpdateAdmin PUT /api/v1/admins/{id}（需 owner）：改角色 / 启停 / 强制改密。
// 部分更新语义：每个字段走各自的 service 方法，从而各自携带 R1/R2 护栏与审计事件。
func (h *adminUserHandlers) handleUpdateAdmin(w http.ResponseWriter, r *http.Request) {
	id, idOK := adminPathID(r)
	if !idOK {
		fail(w, http.StatusBadRequest, CodeInvalidParam, "参数缺失或非法")
		return
	}
	var req updateAdminRequest
	if err := DecodeJSON(w, r, &req); err != nil {
		return
	}
	ctx, actor, ip := r.Context(), currentUser(r), clientIP(r)
	if req.Role != nil {
		if err := h.admins.SetRole(ctx, actor, id, *req.Role, ip); err != nil {
			failAdminUser(w, err)
			return
		}
	}
	if req.IsActive != nil {
		if err := h.admins.SetActive(ctx, actor, id, *req.IsActive, ip); err != nil {
			failAdminUser(w, err)
			return
		}
	}
	if req.ForcePasswordChange != nil {
		if err := h.admins.SetForcePasswordChange(ctx, actor, id, *req.ForcePasswordChange, ip); err != nil {
			failAdminUser(w, err)
			return
		}
	}
	u, err := h.admins.Get(ctx, id)
	if err != nil {
		failAdminUser(w, err)
		return
	}
	ok(w, map[string]any{"user": adminJSONUser(u)})
}

// resetAdminPasswordRequest PUT /api/v1/admins/{id}/password 请求体。
type resetAdminPasswordRequest struct {
	NewPassword string `json:"new_password"`
	ForceChange *bool  `json:"force_change"`
}

// handleResetAdminPassword PUT /api/v1/admins/{id}/password（需 owner）：
// 重置他人密码并吊销其全部会话；默认要求其下次登录强制改密。
func (h *adminUserHandlers) handleResetAdminPassword(w http.ResponseWriter, r *http.Request) {
	id, idOK := adminPathID(r)
	if !idOK {
		fail(w, http.StatusBadRequest, CodeInvalidParam, "参数缺失或非法")
		return
	}
	var req resetAdminPasswordRequest
	if err := DecodeJSON(w, r, &req); err != nil {
		return
	}
	forceChange := true
	if req.ForceChange != nil {
		forceChange = *req.ForceChange
	}
	if err := h.admins.ResetPassword(r.Context(), currentUser(r), id, req.NewPassword, forceChange, clientIP(r)); err != nil {
		failAdminUser(w, err)
		return
	}
	ok(w, map[string]any{"reset": true, "force_change": forceChange})
}
