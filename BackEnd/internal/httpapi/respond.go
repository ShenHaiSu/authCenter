// Package httpapi HTTP 层：路由、中间件、请求/响应编解码（文档 04 §4）。
package httpapi

import (
	"encoding/json"
	"net/http"
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

// fail 失败响应：携带业务码与 request_id（从上下文取）。
func fail(w http.ResponseWriter, status, code int, message string) {
	writeJSON(w, status, response{
		Code:      code,
		Message:   message,
		RequestID: RequestIDFrom(w),
	})
}

// DecodeJSON 解析请求体 JSON 到 v；超过 1MB（LimitBody 中间件）返回 20002。
func DecodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, 20002, "JSON 解析失败: "+err.Error())
		return err
	}
	return nil
}
