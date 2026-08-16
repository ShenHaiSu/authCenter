package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/service"
	"github.com/authcenter/authcenter/internal/store"
)

// 中间件链（文档 04 §4.2）：RequestID / AccessLog / Recover / LimitBody / RequireAdmin。
// RateLimit 在 service 层按接口内建（登录防爆破，06 §7；认证限流 M3 加）。

// ctxKey 上下文键类型，避免与其他包冲突。
type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyStartTime
	ctxKeyUser
	ctxKeySession
)

// SessionCookieName 会话 cookie 名（文档 06 §3.2）。
const SessionCookieName = "auth_session"

// MaxBodyBytes 请求体上限 1MB（文档 02 §8）。
const MaxBodyBytes = 1 << 20

// RequestID 生成/透传 X-Request-Id，写入请求上下文（全链路追踪）。
// 同时以 service.CtxKeyRequestID 注入，供 service 层审计记录 request_id（04 §6）。
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" || len(id) > 64 {
			id = newRequestID()
		}
		w.Header().Set("X-Request-Id", id)
		ctx := context.WithValue(r.Context(), ctxKeyRequestID, id)
		ctx = context.WithValue(ctx, service.CtxKeyRequestID, id)
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
				fail(w, http.StatusInternalServerError, CodeInternal, "服务器内部错误")
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

// RequireAdmin 会话鉴权中间件（文档 04 §3.4 / 06 §3.2）：
// 读 auth_session cookie → SHA-256 查会话 → 过期校验 → 注入当前用户与会话到 context。
// 失败返回 401/20103（文档 05 §2）。静态资源路径不挂（router 装配处控制）。
func RequireAdmin(st *store.Store) func(func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(next func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(SessionCookieName)
			if err != nil || cookie.Value == "" {
				fail(w, http.StatusUnauthorized, CodeSessionExpired, "会话缺失或过期")
				return
			}
			sum := sha256.Sum256([]byte(cookie.Value))
			sess, err := st.GetSessionByTokenHash(r.Context(), hex.EncodeToString(sum[:]))
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					fail(w, http.StatusUnauthorized, CodeSessionExpired, "会话缺失或过期")
					return
				}
				failService(w, err)
				return
			}
			if sess.ExpiresAt.Before(time.Now().UTC()) {
				// 惰性清理过期会话（03 §7）。
				_ = st.DeleteSession(r.Context(), sess.ID)
				fail(w, http.StatusUnauthorized, CodeSessionExpired, "会话缺失或过期")
				return
			}
			user, err := st.GetAdminByUsername(r.Context(), "admin")
			if err != nil {
				failService(w, err)
				return
			}
			if !user.IsActive {
				fail(w, http.StatusUnauthorized, CodeAccountDisabled, "账号已停用")
				return
			}
			ctx := context.WithValue(r.Context(), ctxKeyUser, user)
			ctx = context.WithValue(ctx, ctxKeySession, sess)
			next(w, r.WithContext(ctx))
		}
	}
}

// currentUser 从请求上下文取当前管理员（RequireAdmin 注入）。
func currentUser(r *http.Request) *model.AdminUser {
	if v, ok := r.Context().Value(ctxKeyUser).(*model.AdminUser); ok {
		return v
	}
	return nil
}

// currentSession 从请求上下文取当前会话（RequireAdmin 注入）。
func currentSession(r *http.Request) *model.AdminSession {
	if v, ok := r.Context().Value(ctxKeySession).(*model.AdminSession); ok {
		return v
	}
	return nil
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
// 兼容 IPv6（如 "[::1]:53779" 与 "::1"），提取失败时回退原值。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// 无端口形式（IPv6 裸地址或测试构造）：去掉 IPv6 方括号后返回。
		return strings.Trim(r.RemoteAddr, "[]")
	}
	return host
}
