package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/authcenter/authcenter/internal/service"
)

// 认证专用业务码（文档 05 §2：HTTP 一律 200，业务结果放 body，客户端只看 code==0）。
const (
	authCodeProjectNotFound     = 10001 // project_not_found
	authCodeProjectDisabled     = 10002 // project_disabled
	authCodeVersionTooOld       = 10003 // version_too_old
	authCodeKeyNotFound         = 10004 // key_not_found
	authCodeKeyDisabled         = 10005 // key_disabled
	authCodeKeyExpired          = 10006 // key_expired
	authCodeFingerprintMismatch = 10007 // fingerprint_mismatch
	authCodeFingerprintRequired = 10008 // fingerprint_required
	// CodeRateLimited = 10009（已在 respond.go 定义）
)

// authHandlers 对外认证 API handlers（文档 05 §3）。
type authHandlers struct {
	auths *service.AuthService
}

// authenticateRequest 认证请求（05 §3.1）。
type authenticateRequest struct {
	ProjectName string `json:"project_name"`
	Version     string `json:"version"`
	Fingerprint string `json:"fingerprint"`
	Key         string `json:"key"`
	IssueToken  bool   `json:"issue_token"`
}

// handleAuthenticate POST /api/v1/authenticate（公开，无会话）：
// 认证结果一律 HTTP 200 + 业务码（文档 05 §2「认证接口专用」），
// 仅服务器内部错误（50000）使用 HTTP 500。
func (h *authHandlers) handleAuthenticate(w http.ResponseWriter, r *http.Request) {
	var req authenticateRequest
	if err := DecodeJSON(w, r, &req); err != nil {
		// DecodeJSON 已输出 400/20002；认证接口统一 200 语义下重写为业务码响应。
		failAuth(w, CodeInvalidJSON, "invalid_json", "JSON 解析失败")
		return
	}
	req.ProjectName = strings.TrimSpace(req.ProjectName)
	req.Version = strings.TrimSpace(req.Version)
	req.Fingerprint = strings.TrimSpace(req.Fingerprint)
	req.Key = strings.TrimSpace(req.Key)
	if req.ProjectName == "" || req.Version == "" || req.Fingerprint == "" || req.Key == "" {
		failAuth(w, CodeInvalidParam, "invalid_parameter", "参数缺失或非法")
		return
	}

	result, err := h.auths.Authenticate(r.Context(), service.AuthenticateRequest{
		ProjectName: req.ProjectName,
		Version:     req.Version,
		Fingerprint: req.Fingerprint,
		Key:         req.Key,
		IssueToken:  req.IssueToken,
	}, clientIP(r))
	if err != nil {
		code, reason, message, ok := authError(err)
		if !ok {
			// 服务器内部错误（数据库故障等）：HTTP 500 + 50000。
			fail(w, http.StatusInternalServerError, CodeInternal, "服务器内部错误")
			return
		}
		failAuth(w, code, reason, message)
		return
	}

	data := map[string]any{
		"authenticated": true,
		"project": map[string]any{
			"name":            result.ProjectName,
			"current_version": result.CurrentVersion,
		},
		"server_time": result.ServerTime,
		"token":       nil,
	}
	if result.Token != "" {
		data["token"] = map[string]any{
			"token":      result.Token,
			"algorithm":  "HS256",
			"expires_at": result.TokenExpiresAt,
		}
	}
	ok(w, data)
}

// failAuth 认证接口失败响应：HTTP 一律 200 + 业务码 + data.reason + request_id。
func failAuth(w http.ResponseWriter, code int, reason, message string) {
	writeJSON(w, http.StatusOK, response{
		Code:    code,
		Message: message,
		Data: map[string]any{
			"authenticated": false,
			"reason":        reason,
		},
		RequestID: RequestIDFrom(w),
	})
}

// authError 将认证业务错误映射为 (业务码, reason, message, 是否认证业务)。
// 非认证业务错误（数据库故障等）返回 ok=false，由调用方按 500 处理。
func authError(err error) (code int, reason, message string, ok bool) {
	switch {
	case errors.Is(err, service.ErrRateLimited):
		return CodeRateLimited, "rate_limited", "触发限流，请稍后再试", true
	case errors.Is(err, service.ErrProjectNotFound):
		return authCodeProjectNotFound, "project_not_found", "项目不存在", true
	case errors.Is(err, service.ErrProjectDisabled):
		return authCodeProjectDisabled, "project_disabled", "项目已停用", true
	case errors.Is(err, service.ErrVersionTooOld):
		return authCodeVersionTooOld, "version_too_old", "版本过低", true
	case errors.Is(err, service.ErrKeyNotFound):
		return authCodeKeyNotFound, "key_not_found", "密钥不存在", true
	case errors.Is(err, service.ErrKeyDisabled):
		return authCodeKeyDisabled, "key_disabled", "密钥已停用", true
	case errors.Is(err, service.ErrKeyExpired):
		return authCodeKeyExpired, "key_expired", "密钥已过期", true
	case errors.Is(err, service.ErrFingerprintMismatch):
		return authCodeFingerprintMismatch, "fingerprint_mismatch", "指纹不匹配", true
	case errors.Is(err, service.ErrFingerprintRequired):
		return authCodeFingerprintRequired, "fingerprint_required", "未绑定指纹但系统要求绑定", true
	case errors.Is(err, service.ErrInvalidParameter):
		return CodeInvalidParam, "invalid_parameter", "参数缺失或非法", true
	default:
		return 0, "", "", false
	}
}
