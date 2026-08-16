package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

// 令牌参数（文档 04 §3.3 / 06 §3.4）。
const (
	DefaultTokenTTLSeconds = 86400 // 默认 TTL 24h（settings.token_ttl_seconds，可配置）
	tokenIssuer            = "authcenter"
)

// TokenClaims 自定义 Claims（文档 04 §3.3）：
// {sub: "project:{name}", pid: project_id, kid: key_id, ver: version, iat, exp, jti}。
type TokenClaims struct {
	PID int64  `json:"pid"` // project id
	KID int64  `json:"kid"` // api_key id
	Ver string `json:"ver"` // 认证时的项目版本
	jwt.RegisteredClaims
}

// TokenService JWT 签发/校验（文档 04 §3.3，算法 HS256）。
type TokenService struct {
	// jwtSecret 启动时读取 settings.jwt_secret（env AUTHCENTER_JWT_SECRET 覆盖优先，
	// 见 cmd/authcenter/main.go ensureJWTSecret），运行时不再变更。
	jwtSecret string
	// ttlSeconds 令牌有效期（settings.token_ttl_seconds，默认 86400）。
	ttlSeconds int
}

// NewTokenService 构造 TokenService：从 settings 读取 jwt_secret 与 token_ttl_seconds。
// jwtSecret 为空时返回错误（启动自检：未配置则拒绝启动，避免签发不可校验的令牌）。
func NewTokenService(ctx context.Context, st *store.Store) (*TokenService, error) {
	secret, err := st.GetSetting(ctx, model.SettingJWTSecret)
	if err != nil {
		return nil, err
	}
	if secret == "" {
		return nil, fmt.Errorf("settings 缺少 jwt_secret，无法初始化 TokenService")
	}
	ttl := DefaultTokenTTLSeconds
	if v, err := st.GetSetting(ctx, model.SettingTokenTTL); err != nil {
		return nil, err
	} else if v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ttl = n
		}
	}
	return &TokenService{jwtSecret: secret, ttlSeconds: ttl}, nil
}

// Issue 为认证成功的项目签发短期 JWT（HS256）：
// Claims 见 TokenClaims；jti 为 16 字节随机 base64（文档 04 §3.3）。
// 返回 (token 串, 过期时间, err)。
func (s *TokenService) Issue(project *model.Project, key *model.APIKey, version string) (string, time.Time, error) {
	expiresAt := timeNowUTC().Add(time.Duration(s.ttlSeconds) * time.Second)
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("生成 jti 失败: %w", err)
	}
	claims := TokenClaims{
		PID: project.ID,
		KID: key.ID,
		Ver: version,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("project:%s", project.Name), // sub（文档 04 §3.3）
			Issuer:    tokenIssuer,
			IssuedAt:  jwt.NewNumericDate(timeNowUTC()),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			ID:        base64.RawStdEncoding.EncodeToString(jtiBytes), // jti
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("签发令牌失败: %w", err)
	}
	return signed, expiresAt, nil
}

// Verify 本地校验令牌（调用方项目自持 secret 校验，或本服务内部校验；文档 04 §3.3）：
// 校验签名（HS256）、过期时间、issuer；返回 Claims。
func (s *TokenService) Verify(tokenString string) (*TokenClaims, error) {
	claims := &TokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("非预期签名算法: %v", t.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	}, jwt.WithIssuer(tokenIssuer), jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("令牌无效")
	}
	return claims, nil
}
