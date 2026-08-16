package httpapi

import (
	"net/http"

	"github.com/authcenter/authcenter/internal/service"
)

// adminHandlers 管理员会话相关 handlers（文档 05 §4.1）。
type adminHandlers struct {
	sessions *service.SessionService
}

// loginRequest 登录请求（05 §4.1）。
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleLogin POST /api/v1/admin/login：成功 Set-Cookie auth_session + 审计 admin.login。
func (h *adminHandlers) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := DecodeJSON(w, r, &req); err != nil {
		return
	}
	if req.Username == "" || req.Password == "" {
		fail(w, http.StatusBadRequest, CodeInvalidParam, "用户名与密码不能为空")
		return
	}
	user, token, err := h.sessions.Login(r.Context(), req.Username, req.Password, clientIP(r), r.UserAgent())
	if err != nil {
		failService(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   7 * 24 * 3600, // 7 天（文档 06 §3.2）
	})
	ok(w, map[string]any{
		"user": map[string]any{
			"username":      user.Username,
			"created_at":    user.CreatedAt,
			"last_login_at": user.LastLoginAt,
			"last_login_ip": user.LastLoginIP,
		},
	})
}

// handleLogout POST /api/v1/admin/logout：删除会话 + 清 cookie + 审计 admin.logout。
func (h *adminHandlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	sess := currentSession(r)
	if err := h.sessions.Logout(r.Context(), sess, user, clientIP(r)); err != nil {
		failService(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1, // 立即过期
	})
	ok(w, nil)
}

// handleMe GET /api/v1/admin/me：返回当前用户。
func (h *adminHandlers) handleMe(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	ok(w, map[string]any{
		"user": map[string]any{
			"username":      user.Username,
			"created_at":    user.CreatedAt,
			"last_login_at": user.LastLoginAt,
		},
	})
}

// changePasswordRequest 改密请求（05 §4.1；新密码 ≥12 位含字母数字）。
type changePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// handleChangePassword PUT /api/v1/admin/password：改密后全部会话失效。
func (h *adminHandlers) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if err := DecodeJSON(w, r, &req); err != nil {
		return
	}
	if req.OldPassword == "" || req.NewPassword == "" {
		fail(w, http.StatusBadRequest, CodeInvalidParam, "旧密码与新密码不能为空")
		return
	}
	user := currentUser(r)
	if err := h.sessions.ChangePassword(r.Context(), user, req.OldPassword, req.NewPassword); err != nil {
		failService(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	ok(w, nil)
}
