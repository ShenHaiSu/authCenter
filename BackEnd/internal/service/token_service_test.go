package service

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

// newTokenTestSvc 构造 TokenService：临时 SQLite + 指定 secret/ttl 写入 settings。
func newTokenTestSvc(t *testing.T, secret string, ttl int) *TokenService {
	t.Helper()
	dir := t.TempDir()
	db, err := database.Open(dir)
	if err != nil {
		t.Fatalf("database.Open 失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	st := store.New(db)
	ctx := context.Background()
	if err := st.SetSetting(ctx, model.SettingJWTSecret, secret); err != nil {
		t.Fatalf("写入 jwt_secret 失败: %v", err)
	}
	if ttl > 0 {
		if err := st.SetSetting(ctx, model.SettingTokenTTL, strconv.Itoa(ttl)); err != nil {
			t.Fatalf("写入 token_ttl 失败: %v", err)
		}
	}
	svc, err := NewTokenService(ctx, st)
	if err != nil {
		t.Fatalf("NewTokenService 失败: %v", err)
	}
	return svc
}

// sampleProjectKey 测试用项目与密钥。
func sampleProjectKey() (*model.Project, *model.APIKey) {
	return &model.Project{ID: 7, Name: "svc-token", CurrentVersion: "1.2.3"},
		&model.APIKey{ID: 42}
}

// TestTokenIssueVerify 签发-校验往返：Claims 字段齐全、可被 Verify 校验（08 §2 service/token）。
func TestTokenIssueVerify(t *testing.T) {
	svc := newTokenTestSvc(t, "test-secret-0123456789abcdef", 3600)
	project, key := sampleProjectKey()

	signed, expiresAt, err := svc.Issue(project, key, "1.2.3")
	if err != nil {
		t.Fatalf("Issue 失败: %v", err)
	}
	if signed == "" {
		t.Fatal("签发的 token 不应为空")
	}
	// 过期时间约等于 now + 3600s。
	if d := time.Until(expiresAt); d < 3590*time.Second || d > 3610*time.Second {
		t.Errorf("过期时间应在 3600s 附近，实际 %v", d)
	}

	claims, err := svc.Verify(signed)
	if err != nil {
		t.Fatalf("Verify 失败: %v", err)
	}
	if claims.Subject != "project:svc-token" {
		t.Errorf("sub = %q, 期望 project:svc-token", claims.Subject)
	}
	if claims.PID != 7 || claims.KID != 42 || claims.Ver != "1.2.3" {
		t.Errorf("claims 字段不正确: pid=%d kid=%d ver=%q", claims.PID, claims.KID, claims.Ver)
	}
	if claims.ID == "" {
		t.Error("jti 不应为空")
	}
	if claims.ExpiresAt == nil || claims.IssuedAt == nil {
		t.Error("exp/iat 应已设置")
	}
}

// TestTokenTampered 篡改拒绝：修改签名区后 Verify 失败（08 §2 service/token）。
func TestTokenTampered(t *testing.T) {
	svc := newTokenTestSvc(t, "test-secret-0123456789abcdef", 3600)
	project, key := sampleProjectKey()
	signed, _, err := svc.Issue(project, key, "1.0.0")
	if err != nil {
		t.Fatalf("Issue 失败: %v", err)
	}
	// 改动最后一个字符（破坏签名）。
	tampered := signed[:len(signed)-1] + "A"
	if _, err := svc.Verify(tampered); err == nil {
		t.Error("篡改后的 token 应校验失败")
	}
}

// TestTokenExpired 过期拒绝：签一个已过期 token（exp 设为过去时间）Verify 应拒绝。
func TestTokenExpired(t *testing.T) {
	svc := newTokenTestSvc(t, "test-secret-0123456789abcdef", 3600)
	claims := TokenClaims{
		PID: 1, KID: 2, Ver: "1.0.0",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "project:svc-old",
			Issuer:    tokenIssuer,
			IssuedAt:  jwt.NewNumericDate(timeNowUTC().Add(-2 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(timeNowUTC().Add(-1 * time.Hour)), // 已过期
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte("test-secret-0123456789abcdef"))
	if err != nil {
		t.Fatalf("签发测试 token 失败: %v", err)
	}
	if _, err := svc.Verify(signed); err == nil {
		t.Error("过期 token 应校验失败")
	} else if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Errorf("应报 token expired: %v", err)
	}
}

// TestTokenSecretOverride secret 覆盖：不同 secret 的实例无法校验对方 token（文档 06 §3.4）。
func TestTokenSecretOverride(t *testing.T) {
	svcA := newTokenTestSvc(t, "secret-AAAAAAAAAAAAAAAA", 3600)
	svcB := newTokenTestSvc(t, "secret-BBBBBBBBBBBBBBBB", 3600)
	project, key := sampleProjectKey()
	signed, _, err := svcA.Issue(project, key, "1.0.0")
	if err != nil {
		t.Fatalf("Issue 失败: %v", err)
	}
	if _, err := svcB.Verify(signed); err == nil {
		t.Error("不同 secret 校验应失败")
	}
}

// TestTokenTTLFromSettings TTL 读取 settings.token_ttl_seconds（可配置）。
func TestTokenTTLFromSettings(t *testing.T) {
	svc := newTokenTestSvc(t, "test-secret-0123456789abcdef", 120)
	project, key := sampleProjectKey()
	_, expiresAt, err := svc.Issue(project, key, "1.0.0")
	if err != nil {
		t.Fatalf("Issue 失败: %v", err)
	}
	if d := time.Until(expiresAt); d < 110*time.Second || d > 130*time.Second {
		t.Errorf("TTL 应为 settings 中的 120s，实际 %v", d)
	}
}

// TestNewTokenServiceMissingSecret 缺少 jwt_secret 应报错（启动自检）。
func TestNewTokenServiceMissingSecret(t *testing.T) {
	dir := t.TempDir()
	db, err := database.Open(dir)
	if err != nil {
		t.Fatalf("database.Open 失败: %v", err)
	}
	defer db.Close()
	_ = slog.Default() // 预热
	if _, err := NewTokenService(context.Background(), store.New(db)); err == nil {
		t.Error("缺少 jwt_secret 时应返回错误")
	}
}
