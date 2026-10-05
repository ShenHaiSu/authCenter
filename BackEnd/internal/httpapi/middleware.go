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

// forceChangeAllowedPaths 强制改密期间允许访问的路径白名单（need01 02 §4.2）。
// 白名单外的任何管理 API 都返回 403：强制改密必须在后端拦截，
// 只靠前端跳页则攻击者拿到 cookie 可直接打 API，改密形同虚设。
var forceChangeAllowedPaths = map[string]bool{
	"/api/v1/admin/me":       true,
	"/api/v1/admin/logout":   true,
	"/api/v1/admin/password": true,
	"/healthz":               true,
}

// forceChangeAllowed 判断该路径是否在强制改密白名单内。
func forceChangeAllowed(path string) bool { return forceChangeAllowedPaths[path] }

// RequireAdmin 会话鉴权中间件（文档 04 §3.4 / 06 §3.2）：
// 读 auth_session cookie → SHA-256 查会话 → 过期校验 → **按 sess.AdminUserID 取用户**
// → 账号启用校验（停用即刻吊销其全部会话）→ 强制改密拦截 → 注入当前用户与会话到 context。
// 失败返回 401/20103（会话）或 401/20102（停用）/403/20104（强制改密）。
// 静态资源路径不挂（router 装配处控制）。
//
// F-020：原实现按固定用户名 "admin" 取用户，多账号下会把所有会话都解析成 admin，
// 导致 is_active 与角色判断全部失真——此处改为按会话归属取人（need01 02 §2 P0 必改项）。
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
			// F-020：按会话归属取当前管理员（会话行已记录 admin_user_id）。
			// 原实现按固定用户名 "admin" 取人，多账号下会把所有会话都解析成 admin。
			user, err := st.GetAdminByID(r.Context(), sess.AdminUserID)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					// 会话指向的用户已不存在（被删/库被换）→ 视为会话失效。
					_ = st.DeleteSession(r.Context(), sess.ID)
					fail(w, http.StatusUnauthorized, CodeSessionExpired, "会话缺失或过期")
					return
				}
				failService(w, err)
				return
			}
			if !user.IsActive {
				// 停用即刻失效：顺带吊销其全部会话（不只拦当前请求）。
				_ = st.DeleteSessionsByUser(r.Context(), user.ID)
				fail(w, http.StatusUnauthorized, CodeAccountDisabled, "账号已停用")
				return
			}
			if user.ForcePasswordChange && !forceChangeAllowed(r.URL.Path) {
				// 强制改密拦截：仅放行白名单路径（改密/登出/查自己/healthz）。
				fail(w, http.StatusForbidden, CodeForbidden, "请先修改初始密码")
				return
			}
			ctx := context.WithValue(r.Context(), ctxKeyUser, user)
			ctx = context.WithValue(ctx, ctxKeySession, sess)
			next(w, r.WithContext(ctx))
		}
	}
}

// requireOwner 要求当前会话用户角色为 owner（F-020：管理员账号管理仅 owner 可操作）。
// 必须挂在 RequireAdmin 之后：requireAdmin(requireOwner(handler))，见 router.go 装配。
func requireOwner(next func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if u := currentUser(r); u == nil || u.Role != model.RoleOwner {
			fail(w, http.StatusForbidden, CodeForbidden, "仅超级管理员可执行此操作")
			return
		}
		next(w, r)
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

// clientIP 解析客户端真实 IP：优先 X-Forwarded-For（前置 caddy 已先删后设覆盖该头，
// 见部署 Caddyfile），取最左首个合法 IP；缺失或非法时回落 RemoteAddr
// （服务仅监听 127.0.0.1，即回落为 127.0.0.1）。
func clientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		for _, part := range strings.Split(xff, ",") {
			ip := strings.TrimSpace(part)
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host // 兼容带端口形式
			}
			ip = strings.Trim(ip, "[]")
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	// 回落：RemoteAddr 解析（本架构下为 127.0.0.1）。
	// 兼容 IPv6（如 "[::1]:53779" 与 "::1"），提取失败时回退原值。
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// 无端口形式（IPv6 裸地址或测试构造）：去掉 IPv6 方括号后返回。
		return strings.Trim(r.RemoteAddr, "[]")
	}
	return host
}
