package service

import (
	"context"
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

// 认证限流与校验参数（文档 06 §7 / 04 §3.2）。
const (
	DefaultAuthRatePerMin = 100 // 认证接口每 IP 每分钟次数，settings.rate_limit_auth_per_min 可配
	// lastUsedUpdateWindow 同一密钥 last_used_at 低频更新窗口（60s，文档 04 §7 防写放大）。
	lastUsedUpdateWindow = 60 * time.Second
)

// 认证业务错误（httpapi 层映射为认证专用业务码 10001-10009，文档 05 §2）。
var (
	ErrProjectNotFound     = errors.New("project not found")
	ErrVersionTooOld       = errors.New("version too old")
	ErrKeyNotFound         = errors.New("key not found")
	ErrKeyDisabled         = errors.New("key disabled")
	ErrKeyExpired          = errors.New("key expired")
	ErrFingerprintMismatch = errors.New("fingerprint mismatch")
	ErrFingerprintRequired = errors.New("fingerprint required")
)

// AuthenticateRequest 外部认证请求（文档 05 §3.1 / 04 §3.2 输入）。
type AuthenticateRequest struct {
	ProjectName string
	Version     string
	Fingerprint string
	Key         string
	IssueToken  bool
}

// AuthResult 认证结果（文档 05 §3.1 响应 data）。
type AuthResult struct {
	Authenticated  bool
	ProjectName    string
	CurrentVersion string
	ServerTime     time.Time
	Token          string     // issue_token=true 且认证成功时非空
	TokenExpiresAt *time.Time // 令牌过期时间（随 Token 返回）
}

// AuthService 外部认证业务（文档 04 §3.2 校验链 + 06 §7 限流 + D2 审计）。
type AuthService struct {
	store              *store.Store
	audit              *AuditService
	tokens             *TokenService
	logger             *slog.Logger
	limiter            *authLimiter
	requireFingerprint bool // settings.require_fingerprint=1 时未绑定指纹的密钥一律拒绝

	mu       sync.Mutex
	lastUsed map[int64]time.Time // keyID → 最近 last_used 更新时间（60s 窗口）
}

// NewAuthService 构造 AuthService：读取 settings
// （rate_limit_auth_per_min 默认 100、require_fingerprint 默认 0）。
func NewAuthService(ctx context.Context, st *store.Store, audit *AuditService, tokens *TokenService, logger *slog.Logger) *AuthService {
	perMin := DefaultAuthRatePerMin
	if v, err := st.GetSetting(ctx, model.SettingRateLimitAuthPerMin); err == nil && v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			perMin = n
		}
	}
	requireFp := false
	if v, err := st.GetSetting(ctx, model.SettingRequireFp); err == nil && v == "1" {
		requireFp = true
	}
	return &AuthService{
		store:              st,
		audit:              audit,
		tokens:             tokens,
		logger:             logger,
		limiter:            newAuthLimiter(perMin),
		requireFingerprint: requireFp,
		lastUsed:           make(map[int64]time.Time),
	}
}

// Authenticate 执行外部认证校验链（文档 04 §3.2，顺序严格，失败即返回并写审计）：
//
//  1. 限流检查（IP 维度）                    → rate_limited
//  2. GetProjectByName                        → project_not_found
//  3. project.IsActive                        → project_disabled
//  4. 版本校验 min_version 语义化比较          → version_too_old
//  5. GetKeyByValue                           → key_not_found
//  6. key.ProjectID == project.ID             → key_not_found（对外不区分，detail 记 key_mismatch）
//  7. key.IsActive                            → key_disabled
//  8. key.ExpiresAt 未过期（NULL 永不过期）    → key_expired
//  9. 指纹校验（绑定/强制策略）                → fingerprint_mismatch / fingerprint_required
//  10. 更新 last_used_at / last_used_ip（60s 窗口低频）
//  11. 审计 success，返回项目信息 + current_version
//  12. 若 IssueToken：TokenService.Issue → 附带 token / expires_at
func (s *AuthService) Authenticate(ctx context.Context, req AuthenticateRequest, ip string) (*AuthResult, error) {
	// 1. 限流检查（IP 维度，06 §7：每 IP 100 次/分钟可配）。
	if !s.limiter.Allow(ip) {
		s.writeFailAudit(ctx, "rate_limited", req, ip)
		return nil, ErrRateLimited
	}

	// 2-3. 项目存在且启用。
	project, err := s.store.GetProjectByName(ctx, req.ProjectName)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeFailAudit(ctx, "project_not_found", req, ip)
			return nil, ErrProjectNotFound
		}
		return nil, err
	}
	if !project.IsActive {
		s.writeFailAudit(ctx, "project_disabled", req, ip)
		return nil, ErrProjectDisabled
	}

	// 4. 版本校验（可选 min_version，语义化比较）。
	var minVersion string
	if project.MinVersion != nil {
		minVersion = *project.MinVersion
	}
	if !versionAtLeast(req.Version, minVersion) {
		s.writeFailAudit(ctx, "version_too_old", req, ip)
		return nil, ErrVersionTooOld
	}

	// 5-8. 密钥存在、属于该项目、启用、未过期。
	key, err := s.store.GetKeyByValue(ctx, req.Key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeFailAudit(ctx, "key_not_found", req, ip)
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	if key.ProjectID != project.ID {
		// 对外与「密钥不存在」同语义（05 §2 错误码表无 key_mismatch，避免泄露密钥归属）。
		s.writeFailAudit(ctx, "key_mismatch", req, ip)
		return nil, ErrKeyNotFound
	}
	if !key.IsActive {
		s.writeFailAudit(ctx, "key_disabled", req, ip)
		return nil, ErrKeyDisabled
	}
	if key.ExpiresAt != nil && !key.ExpiresAt.After(timeNowUTC()) {
		s.writeFailAudit(ctx, "key_expired", req, ip)
		return nil, ErrKeyExpired
	}

	// 9. 指纹校验（06 §4：绑定指纹必须精确匹配；未绑定但系统强制时拒绝）。
	if key.Fingerprint != nil {
		if *key.Fingerprint != req.Fingerprint {
			s.writeFailAudit(ctx, "fingerprint_mismatch", req, ip)
			return nil, ErrFingerprintMismatch
		}
	} else if s.requireFingerprint {
		s.writeFailAudit(ctx, "fingerprint_required", req, ip)
		return nil, ErrFingerprintRequired
	}

	// 10. 更新 last_used_at / last_used_ip（60s 窗口低频，文档 04 §7 防写放大）。
	s.touchLastUsed(ctx, key, ip)

	// 11. 审计成功（detail 含版本与指纹，脱敏红线：不含密钥明文，06 §6）。
	s.audit.Log(ctx, &model.AuditLog{
		EventType: model.EventAuthAuthenticate, ActorType: model.ActorTypeClient,
		ActorID: strconv.FormatInt(project.ID, 10), ActorName: project.Name,
		TargetType: model.TargetTypeProject, TargetID: project.ID, TargetName: project.Name,
		Result: model.ResultSuccess,
		Detail: fmt.Sprintf(`{"version":%q,"fingerprint":%q,"key_id":%d}`, req.Version, req.Fingerprint, key.ID),
		IP:     ip, RequestID: requestIDFrom(ctx),
	})

	result := &AuthResult{
		Authenticated:  true,
		ProjectName:    project.Name,
		CurrentVersion: project.CurrentVersion,
		ServerTime:     timeNowUTC(),
	}

	// 12. 可选令牌签发（决策 D1 / F-013）。
	if req.IssueToken {
		token, expiresAt, err := s.tokens.Issue(project, key, req.Version)
		if err != nil {
			return nil, err
		}
		result.Token = token
		result.TokenExpiresAt = &expiresAt
	}
	return result, nil
}

// touchLastUsed 低频更新密钥 last_used_at/last_used_ip（60s 窗口内同一密钥只写一次）。
func (s *AuthService) touchLastUsed(ctx context.Context, key *model.APIKey, ip string) {
	s.mu.Lock()
	now := timeNowUTC()
	if last, ok := s.lastUsed[key.ID]; ok && now.Sub(last) < lastUsedUpdateWindow {
		s.mu.Unlock()
		return
	}
	s.lastUsed[key.ID] = now
	s.mu.Unlock()

	if _, err := s.store.DB().ExecContext(ctx,
		`UPDATE api_key SET last_used_at = ?, last_used_ip = ? WHERE id = ?`,
		database.FormatTime(now), ip, key.ID); err != nil {
		s.logger.Error("更新 last_used 失败", "err", err, "key_id", key.ID)
	}
}

// writeFailAudit 写认证失败审计（detail 只记原因码/指纹/版本，不记密钥，06 §6）。
func (s *AuthService) writeFailAudit(ctx context.Context, reason string, req AuthenticateRequest, ip string) {
	s.audit.Log(ctx, &model.AuditLog{
		EventType: model.EventAuthAuthenticateFailed, ActorType: model.ActorTypeClient,
		ActorName:  req.ProjectName,
		TargetType: model.TargetTypeProject,
		Result:     model.ResultFailure,
		Detail:     fmt.Sprintf(`{"reason":%q,"version":%q,"fingerprint":%q}`, reason, req.Version, req.Fingerprint),
		IP:         ip, RequestID: requestIDFrom(ctx),
	})
}

// authLimiter 认证接口按 IP 限流（令牌桶，N 次/分钟，文档 06 §7）。
type authLimiter struct {
	mu       sync.Mutex
	perMin   int
	limiters map[string]*rate.Limiter
}

func newAuthLimiter(perMin int) *authLimiter {
	if perMin <= 0 {
		perMin = DefaultAuthRatePerMin
	}
	return &authLimiter{perMin: perMin, limiters: make(map[string]*rate.Limiter)}
}

// Allow 检查 IP 是否允许本次认证请求。
func (l *authLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim, ok := l.limiters[ip]
	if !ok {
		// perMin 次/分钟 = perMin/60 每秒，突发容量 perMin。
		lim = rate.NewLimiter(rate.Limit(l.perMin)/60, l.perMin)
		l.limiters[ip] = lim
	}
	return lim.Allow()
}
