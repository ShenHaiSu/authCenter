package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"
)

// 中间件链（文档 04 §4.2）：RequestID / AccessLog / Recover / LimitBody。
// 会话鉴权（RequireAdmin）与限流（RateLimit）随 M2/M3 加入。

// ctxKey 上下文键类型，避免与其他包冲突。
type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyStartTime
)

// MaxBodyBytes 请求体上限 1MB（文档 02 §8）。
const MaxBodyBytes = 1 << 20

// RequestID 生成/透传 X-Request-Id，写入请求上下文（全链路追踪）。
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" || len(id) > 64 {
			id = newRequestID()
		}
		w.Header().Set("X-Request-Id", id)
		ctx := context.WithValue(r.Context(), ctxKeyRequestID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDFrom 从请求上下文取 request id（响应错误码用）。
func RequestIDFrom(w http.ResponseWriter) string {
	// 中间件已把 id 写入响应头，直接回读即可。
	return w.Header().Get("X-Request-Id")
}

// newRequestID 生成 16 字节随机 hex（32 字符）。
func newRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}

// AccessLog 结构化访问日志：method/path/status/duration/ip（文档 04 §6）。
func AccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ctx := context.WithValue(r.Context(), ctxKeyStartTime, start)
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r.WithContext(ctx))
			logger.Info("http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"ip", clientIP(r),
				"request_id", r.Header.Get("X-Request-Id"),
			)
		})
	}
}

// Recover panic 恢复：panic → 500 JSON（文档 04 §4.2）。
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				fail(w, http.StatusInternalServerError, 50000, "服务器内部错误")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// LimitBody 请求体上限 1MB（http.MaxBytesReader，文档 02 §8 / 05 §1）。
func LimitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// statusWriter 捕获响应状态码供访问日志使用。
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// clientIP 从 RemoteAddr 提取客户端 IP（不含端口）。
func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}
