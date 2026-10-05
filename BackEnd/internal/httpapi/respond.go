// Package httpapi HTTP 层：路由、中间件、请求/响应编解码（文档 04 §4）。
package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/authcenter/authcenter/internal/service"
	"github.com/authcenter/authcenter/internal/store"
)

// 业务错误码（文档 05 §2 错误码总表）。
const (
	CodeOK               = 0
	CodeInvalidParam     = 20001 // 参数缺失/非法
	CodeInvalidJSON      = 20002 // JSON 解析失败
	CodeValidationFailed = 20003 // 校验失败
	CodeBadCredentials   = 20101 // 用户名或密码错误
	CodeAccountDisabled  = 20102 // 账号已停用
	CodeSessionExpired   = 20103 // 会话缺失或过期
	CodeForbidden        = 20104 // 无权限
	CodeNotFound         = 20200 // 资源不存在
	CodeNameConflict     = 20201 // 名称冲突
	CodeStateConflict    = 20202 // 资源状态不允许
	CodeRateLimited      = 10009 // 触发限流
	CodeInternal         = 50000 // 服务器内部错误
)

// 统一响应结构（文档 04 §4.3 / 05 §1）：
//
//	成功 { "code": 0, "message": "ok", "data": {...} }
//	失败 { "code": 20001, "message": "...", "request_id": "..." }
type response struct {
	Code      int    `json:"code"`
	Message   string `json:"message"`
	Data      any    `json:"data,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// writeJSON 输出统一 JSON 响应。
func writeJSON(w http.ResponseWriter, status int, resp response) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// ok 成功响应：code=0, message="ok"。
func ok(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, response{Code: 0, Message: "ok", Data: data})
}

// okStatus 指定状态码的成功响应（如 201 创建）。
func okStatus(w http.ResponseWriter, status int, data any) {
	writeJSON(w, status, response{Code: 0, Message: "ok", Data: data})
}

// fail 失败响应：携带业务码与 request_id（从响应头回读）。
func fail(w http.ResponseWriter, status, code int, message string) {
	writeJSON(w, status, response{
		Code:      code,
		Message:   message,
		RequestID: RequestIDFrom(w),
	})
}

func failService(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrBadCredentials):
		fail(w, http.StatusUnauthorized, CodeBadCredentials, "用户名或密码错误")
	case errors.Is(err, service.ErrAccountDisabled):
		fail(w, http.StatusUnauthorized, CodeAccountDisabled, "账号已停用")
	case errors.Is(err, service.ErrRateLimited):
		fail(w, http.StatusTooManyRequests, CodeRateLimited, "操作过于频繁，请稍后再试")
	case errors.Is(err, service.ErrSessionExpired):
		fail(w, http.StatusUnauthorized, CodeSessionExpired, "会话缺失或过期")
	case errors.Is(err, service.ErrPasswordTooWeak):
		fail(w, http.StatusBadRequest, CodeValidationFailed, err.Error())
	case errors.Is(err, service.ErrInvalidParameter):
		fail(w, http.StatusBadRequest, CodeInvalidParam, "参数缺失或非法")
	case errors.Is(err, service.ErrProjectDisabled):
		fail(w, http.StatusConflict, CodeStateConflict, "项目已停用")
	case errors.Is(err, service.ErrJobRunning):
		fail(w, http.StatusConflict, CodeStateConflict, "任务已在运行，请稍后再试")
	case errors.Is(err, service.ErrStateConflict):
		fail(w, http.StatusConflict, CodeStateConflict, "资源状态不允许")
	case errors.Is(err, service.ErrForbidden):
		fail(w, http.StatusForbidden, CodeForbidden, "无权限")
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, CodeNotFound, "资源不存在")
	case errors.Is(err, store.ErrConflict):
		fail(w, http.StatusConflict, CodeNameConflict, "名称已存在")
	default:
		fail(w, http.StatusInternalServerError, CodeInternal, "服务器内部错误")
	}
}

// DecodeJSON 解析请求体 JSON 到 v；超过 1MB（LimitBody 中间件）返回 20002。
func DecodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, CodeInvalidJSON, "JSON 解析失败: "+err.Error())
		return err
	}
	return nil
}

// parsePagination 解析 page/size 查询参数（默认 page=1, size=20，上限 100）。
func parsePagination(r *http.Request) (page, size int) {
	page = 1
	size = 20
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			page = n
		}
	}
	if v := r.URL.Query().Get("size"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 100 {
			size = n
		}
	}
	return page, size
}

// parseBoolParam 解析布尔查询参数（空返回 nil=不过滤）。
func parseBoolParam(r *http.Request, key string) *bool {
	v := r.URL.Query().Get(key)
	if v == "" {
		return nil
	}
	b := v == "1" || v == "true" || v == "on"
	return &b
}
