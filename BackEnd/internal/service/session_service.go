package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

// 会话与登录安全参数（文档 04 §3.4 / 06 §3.2/§7）。
const (
	SessionTTL       = 7 * 24 * time.Hour // 会话 7 天
	loginIPRate      = 5                  // 每 IP 5 次/分钟
	loginMaxFailures = 5                  // 连续失败锁定阈值
	loginLockMinutes = 15                 // 锁定 15 分钟
	minPasswordLen   = 12                 // 新密码最短长度（06 §3.1）
)

// 业务错误（httpapi 层映射 HTTP 状态码与业务码，文档 05 §2）。
var (
	ErrBadCredentials   = errors.New("bad credentials")
	ErrAccountDisabled  = errors.New("account disabled")
	ErrRateLimited      = errors.New("rate limited")
	ErrSessionExpired   = errors.New("session expired")
	ErrPasswordTooWeak  = errors.New("password too weak")
	ErrInvalidParameter = errors.New("invalid parameter")
	ErrProjectDisabled  = errors.New("project disabled")
)

// SessionService 管理员会话业务（文档 04 §3.4：登录/登出/改密）。
type SessionService struct {
	store    *store.Store
	logger   *slog.Logger
	throttle *LoginThrottle
}

// NewSessionService 构造 SessionService。
func NewSessionService(st *store.Store, logger *slog.Logger) *SessionService {
	return &SessionService{store: st, logger: logger, throttle: newLoginThrottle()}
}

// Login 校验用户名/密码，成功则签发会话：
//   - 生成 32B 随机 token → 库中只存 SHA-256（06 §3.2）
//   - 写 admin.login 审计；失败写 admin.login_failed（统一 bad_credentials 提示，不泄露账号是否存在）
//
// 返回 (用户, 明文 token, err)。token 由 httpapi 层写入 httpOnly cookie。
func (s *SessionService) Login(ctx context.Context, username, password, ip, userAgent string) (*model.AdminUser, string, error) {
	// 1. IP 维度限流（5 次/分钟，06 §7）。
	if !s.throttle.AllowIP(ip) {
		return nil, "", ErrRateLimited
	}
	// 2. 用户名连续失败锁定检查。
	if s.throttle.IsLocked(username) {
		return nil, "", ErrRateLimited
	}

	failAudit := func(reason string) {
		s.writeAudit(ctx, &model.AuditLog{
			EventType: model.EventAdminLoginFailed, ActorType: model.ActorTypeAdmin,
			ActorName: username, TargetType: model.TargetTypeSession,
			Result: model.ResultFailure, Detail: fmt.Sprintf(`{"reason":%q}`, reason),
			IP: ip, RequestID: requestIDFrom(ctx),
		})
	}

	user, err := s.store.GetAdminByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.throttle.RecordFailure(username)
			failAudit("user_not_found")
			return nil, "", ErrBadCredentials
		}
		return nil, "", err
	}
	if !VerifyPassword(user.PasswordHash, password) {
		s.throttle.RecordFailure(username)
		failAudit("bad_password")
		return nil, "", ErrBadCredentials
	}
	if !user.IsActive {
		failAudit("account_disabled")
		return nil, "", ErrAccountDisabled
	}

	// 3. 登录成功：生成会话 token（32B 随机，hex 编码明文）。
	//    库中只存 token 明文的 SHA-256（06 §3.2），RequireAdmin 校验同源。
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", fmt.Errorf("生成会话 token 失败: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)
	sum := sha256.Sum256([]byte(token))

	now := timeNowUTC()
	sess := &model.AdminSession{
		TokenHash:   hex.EncodeToString(sum[:]),
		AdminUserID: user.ID,
		ExpiresAt:   now.Add(SessionTTL),
		IP:          ip,
		UserAgent:   userAgent,
		CreatedAt:   now,
	}
	if err := s.store.CreateSession(ctx, sess); err != nil {
		return nil, "", err
	}

	// 4. 更新 last_login_at/ip，惰性清理过期会话（03 §7）。
	if _, err := s.store.DB().ExecContext(ctx,
		`UPDATE admin_user SET last_login_at = ?, last_login_ip = ? WHERE id = ?`,
		database.FormatTime(now), ip, user.ID); err != nil {
		s.logger.Error("更新 last_login 失败", "err", err)
	}
	_ = s.store.CleanupExpired(ctx, database.FormatTime(now))

	// 5. 审计 + 重置失败计数。
	s.throttle.Reset(username)
	s.writeAudit(ctx, &model.AuditLog{
		EventType: model.EventAdminLogin, ActorType: model.ActorTypeAdmin,
		ActorID: strconv.FormatInt(user.ID, 10), ActorName: user.Username,
		TargetType: model.TargetTypeSession, TargetID: sess.ID, TargetName: "auth_session",
		Result: model.ResultSuccess, IP: ip, RequestID: requestIDFrom(ctx),
	})
	return user, token, nil
}

// Logout 删除会话并写 admin.logout 审计。
func (s *SessionService) Logout(ctx context.Context, sess *model.AdminSession, user *model.AdminUser, ip string) error {
	if err := s.store.DeleteSession(ctx, sess.ID); err != nil {
		return err
	}
	s.writeAudit(ctx, &model.AuditLog{
		EventType: model.EventAdminLogout, ActorType: model.ActorTypeAdmin,
		ActorID: strconv.FormatInt(user.ID, 10), ActorName: user.Username,
		TargetType: model.TargetTypeSession, TargetID: sess.ID, TargetName: "auth_session",
		Result: model.ResultSuccess, IP: ip, RequestID: requestIDFrom(ctx),
	})
	return nil
}

// ChangePassword 改密：校验旧密码 → 新密码强度（≥12 位含字母数字）→
// argon2id 更新 → 该用户全部会话失效（06 §3.1、04 §3.4）。
func (s *SessionService) ChangePassword(ctx context.Context, user *model.AdminUser, oldPassword, newPassword string) error {
	if !VerifyPassword(user.PasswordHash, oldPassword) {
		return ErrBadCredentials
	}
	if err := validatePasswordStrength(newPassword); err != nil {
		return err
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	// F-020：改密成功同时清 force_password_change，否则被 owner 重置密码的用户
	// 改完自己的密码后仍会被 RequireAdmin 的强制改密拦截挡住（死循环）。
	if err := s.store.UpdateAdminPassword(ctx, user.ID, hash, false); err != nil {
		return err
	}
	if err := s.store.DeleteSessionsByUser(ctx, user.ID); err != nil {
		return err
	}
	s.writeAudit(ctx, &model.AuditLog{
		EventType: model.EventAdminPasswordChange, ActorType: model.ActorTypeAdmin,
		ActorID: strconv.FormatInt(user.ID, 10), ActorName: user.Username,
		TargetType: model.TargetTypeSession, TargetName: "all_sessions",
		Result: model.ResultSuccess, RequestID: requestIDFrom(ctx),
	})
	return nil
}

// validatePasswordStrength 新密码强度：≥12 位，必含字母与数字（06 §3.1）。
func validatePasswordStrength(p string) error {
	if len(p) < minPasswordLen {
		return fmt.Errorf("%w: 密码至少 %d 位", ErrPasswordTooWeak, minPasswordLen)
	}
	hasLetter, hasDigit := false, false
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			hasLetter = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit {
		return fmt.Errorf("%w: 密码必须同时包含字母与数字", ErrPasswordTooWeak)
	}
	return nil
}

// writeAudit 写审计，失败仅记日志不阻断业务。
func (s *SessionService) writeAudit(ctx context.Context, e *model.AuditLog) {
	if err := s.store.InsertAudit(ctx, e); err != nil {
		s.logger.Error("写入审计失败", "err", err, "event_type", e.EventType)
	}
}

// CtxKey 服务层上下文键类型（httpapi 中间件注入，见 middleware.go）。
type CtxKey string

// CtxKeyRequestID 请求上下文中的 request id（httpapi 中间件注入）。
const CtxKeyRequestID CtxKey = "request_id"

// requestIDFrom 从上下文取 request id（httpapi 中间件注入）。
func requestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(CtxKeyRequestID).(string); ok {
		return v
	}
	return ""
}

// LoginThrottle 登录防爆破（06 §7）：IP 令牌桶 5/min + 用户名连续失败锁定。
type LoginThrottle struct {
	mu        sync.Mutex
	ipLimiter map[string]*rate.Limiter
	failures  map[string]*failInfo
}

type failInfo struct {
	count       int
	lockedUntil time.Time
}

func newLoginThrottle() *LoginThrottle {
	return &LoginThrottle{
		ipLimiter: make(map[string]*rate.Limiter),
		failures:  make(map[string]*failInfo),
	}
}

// AllowIP 每 IP 5 次/分钟（令牌桶，突发上限 5）。
func (t *LoginThrottle) AllowIP(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	lim, ok := t.ipLimiter[ip]
	if !ok {
		// 5 次/分钟 = 5/60 每秒，突发容量 5。
		lim = rate.NewLimiter(rate.Limit(loginIPRate)/60, loginIPRate)
		t.ipLimiter[ip] = lim
	}
	return lim.Allow()
}

// RecordFailure 记录一次失败；达到阈值进入锁定（15 分钟）。
func (t *LoginThrottle) RecordFailure(username string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.failures[username]
	if f == nil {
		f = &failInfo{}
		t.failures[username] = f
	}
	f.count++
	if f.count >= loginMaxFailures {
		f.lockedUntil = timeNowUTC().Add(loginLockMinutes * time.Minute)
		f.count = 0
	}
}

// IsLocked 用户名是否处于锁定中。
func (t *LoginThrottle) IsLocked(username string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.failures[username]
	if f == nil {
		return false
	}
	if f.lockedUntil.After(timeNowUTC()) {
		return true
	}
	return false
}

// Reset 登录成功后清零失败计数。
func (t *LoginThrottle) Reset(username string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.failures, username)
}
