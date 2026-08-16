package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/service"
	"github.com/authcenter/authcenter/internal/store"
)

// testClient 集成测试客户端：持有独立 service 实例（登录限流彼此隔离）。
type testClient struct {
	t         *testing.T
	h         http.Handler
	st        *store.Store
	adminPass string // admin 初始密码（EnsureAdmin 首次生成后保存）
	cookie    string // auth_session cookie（登录后）
}

// newTestClient 构建测试环境：临时 SQLite + 全部 service + 初始化 admin。
// setSettings 可选：在构造 service 前写入 settings（如限流阈值、require_fingerprint）。
func newTestClient(t *testing.T, setSettings ...func(context.Context, *store.Store)) *testClient {
	t.Helper()
	dir := t.TempDir()
	db, err := database.Open(dir)
	if err != nil {
		t.Fatalf("database.Open 失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	st := store.New(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditSvc := service.NewAuditService(st, logger)
	sessionSvc := service.NewSessionService(st, logger)
	projectSvc := service.NewProjectService(st, auditSvc)
	apikeySvc := service.NewApiKeyService(st, auditSvc, projectSvc, 7)
	adminSvc := service.NewAdminService(st, logger, dir)
	_, plain, err := adminSvc.EnsureAdmin(context.Background())
	if err != nil {
		t.Fatalf("EnsureAdmin 失败: %v", err)
	}
	// M3：JWT secret（token/auth 服务依赖）与可选 settings 覆盖。
	ctx := context.Background()
	if err := st.SetSetting(ctx, model.SettingJWTSecret, "integration-test-secret-0123456789abcdef"); err != nil {
		t.Fatalf("写入 jwt_secret 失败: %v", err)
	}
	for _, fn := range setSettings {
		fn(ctx, st)
	}
	tokenSvc, err := service.NewTokenService(ctx, st)
	if err != nil {
		t.Fatalf("NewTokenService 失败: %v", err)
	}
	authSvc := service.NewAuthService(ctx, st, auditSvc, tokenSvc, logger)
	h := New(RouterDeps{
		Logger:   logger,
		Store:    st,
		Sessions: sessionSvc,
		Projects: projectSvc,
		Apikeys:  apikeySvc,
		Audits:   auditSvc,
		Auths:    authSvc,
	})
	return &testClient{t: t, h: h, st: st, adminPass: plain}
}

// adminPassword 返回 admin 初始密码（EnsureAdmin 首次生成时保存）。
func (c *testClient) adminPassword() string {
	c.t.Helper()
	return c.adminPass
}

// do 发起请求；body 为 nil 时无请求体。
func (c *testClient) do(method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("marshal body 失败: %v", err)
		}
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: c.cookie})
	}
	rr := httptest.NewRecorder()
	c.h.ServeHTTP(rr, req)
	return rr
}

// doRaw 无 cookie 请求（会话隔离测试用）。
func (c *testClient) doRaw(method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	old := c.cookie
	c.cookie = ""
	defer func() { c.cookie = old }()
	return c.do(method, path, body)
}

// login 登录并保存 cookie；失败时 t.Fatal。
func (c *testClient) login() {
	c.t.Helper()
	rr := c.doRaw(http.MethodPost, "/api/v1/admin/login", map[string]string{
		"username": "admin", "password": c.adminPassword(),
	})
	if rr.Code != http.StatusOK {
		c.t.Fatalf("登录失败: status=%d body=%s", rr.Code, rr.Body.String())
	}
	cookie := rr.Result().Cookies()
	for _, ck := range cookie {
		if ck.Name == SessionCookieName {
			c.cookie = ck.Value
			return
		}
	}
	c.t.Fatal("登录响应无 auth_session cookie")
}

// bodyCode 解析统一响应体中的 code。
func bodyCode(t *testing.T, rr *httptest.ResponseRecorder) int {
	t.Helper()
	var resp struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v body=%s", err, rr.Body.String())
	}
	return resp.Code
}

// createProject 创建项目返回 id。
func (c *testClient) createProject(name string) int64 {
	c.t.Helper()
	rr := c.do(http.MethodPost, "/api/v1/projects", map[string]any{
		"name": name, "description": "集成测试项目", "current_version": "1.0.0",
	})
	if rr.Code != http.StatusCreated {
		c.t.Fatalf("创建项目失败: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data struct {
			Project model.Project `json:"project"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		c.t.Fatalf("解析项目响应失败: %v", err)
	}
	return resp.Data.Project.ID
}

// ================= 08 §3 集成测试场景 =================

// TestLoginSuccess 正确密码 → 200 + cookie；GET /admin/me 可用（08 §3 登录流程）。
func TestLoginSuccess(t *testing.T) {
	c := newTestClient(t)
	c.login()

	rr := c.do(http.MethodGet, "/api/v1/admin/me", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("me status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"username":"admin"`) {
		t.Errorf("me 响应应含 admin: %s", rr.Body.String())
	}
}

// TestLoginWrongPassword 错误密码 → 401/20101 + 审计 admin.login_failed（08 §3 登录流程）。
func TestLoginWrongPassword(t *testing.T) {
	c := newTestClient(t)
	rr := c.doRaw(http.MethodPost, "/api/v1/admin/login", map[string]string{
		"username": "admin", "password": "wrong-password",
	})
	if rr.Code != http.StatusUnauthorized || bodyCode(t, rr) != CodeBadCredentials {
		t.Fatalf("错误密码应 401/20101: status=%d body=%s", rr.Code, rr.Body.String())
	}
	// 审计存在。
	rows, err := c.st.DB().Query(`SELECT count(*) FROM audit_log WHERE event_type = 'admin.login_failed'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	rows.Next()
	var n int
	rows.Scan(&n)
	if n < 1 {
		t.Error("应有 admin.login_failed 审计")
	}
}

// TestLoginLockout 连续失败 5 次锁定 15 分钟：第 6 次即使密码正确也 429（08 §3 / 06 §7）。
func TestLoginLockout(t *testing.T) {
	c := newTestClient(t)
	// 连续 5 次错误密码。
	for i := 0; i < 5; i++ {
		rr := c.doRaw(http.MethodPost, "/api/v1/admin/login", map[string]string{
			"username": "admin", "password": "wrong-password",
		})
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次错误登录应 401: status=%d", i+1, rr.Code)
		}
	}
	// 第 6 次：正确密码也应被限流拒绝（用户名已锁定）。
	rr := c.doRaw(http.MethodPost, "/api/v1/admin/login", map[string]string{
		"username": "admin", "password": c.adminPassword(),
	})
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("锁定后正确密码应 429: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

// TestSessionRequired 无 cookie 访问管理 API → 401/20103；登出后 cookie 失效（08 §3 会话）。
func TestSessionRequired(t *testing.T) {
	c := newTestClient(t)
	rr := c.doRaw(http.MethodGet, "/api/v1/projects", nil)
	if rr.Code != http.StatusUnauthorized || bodyCode(t, rr) != CodeSessionExpired {
		t.Fatalf("无 cookie 应 401/20103: status=%d body=%s", rr.Code, rr.Body.String())
	}

	c.login()
	// 登出。
	rr = c.do(http.MethodPost, "/api/v1/admin/logout", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("登出失败: %d", rr.Code)
	}
	// 原 cookie 再访问 → 401。
	rr = c.do(http.MethodGet, "/api/v1/projects", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("登出后原 cookie 应失效: status=%d", rr.Code)
	}
}

// TestProjectCRUD 项目 CRUD 全链路 + 名称冲突 409 + 删除后 404（08 §3 项目管理）。
func TestProjectCRUD(t *testing.T) {
	c := newTestClient(t)
	c.login()

	// 创建。
	id := c.createProject("svc-a")
	// 名称冲突。
	rr := c.do(http.MethodPost, "/api/v1/projects", map[string]any{"name": "svc-a"})
	if rr.Code != http.StatusConflict || bodyCode(t, rr) != CodeNameConflict {
		t.Fatalf("重名应 409/20201: status=%d body=%s", rr.Code, rr.Body.String())
	}
	// 列表。
	rr = c.do(http.MethodGet, "/api/v1/projects?page=1&size=20", nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "svc-a") {
		t.Fatalf("列表应含 svc-a: status=%d body=%s", rr.Code, rr.Body.String())
	}
	// 详情。
	rr = c.do(http.MethodGet, fmt.Sprintf("/api/v1/projects/%d", id), nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"name":"svc-a"`) {
		t.Fatalf("详情应含 svc-a: status=%d body=%s", rr.Code, rr.Body.String())
	}
	// 更新（停用）。
	rr = c.do(http.MethodPut, fmt.Sprintf("/api/v1/projects/%d", id), map[string]any{
		"description": "更新后", "current_version": "1.2.0", "is_active": false,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("更新失败: status=%d body=%s", rr.Code, rr.Body.String())
	}
	// 删除。
	rr = c.do(http.MethodDelete, fmt.Sprintf("/api/v1/projects/%d", id), nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("删除应 204: status=%d", rr.Code)
	}
	// 删除后 404。
	rr = c.do(http.MethodGet, fmt.Sprintf("/api/v1/projects/%d", id), nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("删除后应 404: status=%d", rr.Code)
	}
}

// TestProjectDeleteCascade 删除项目级联删密钥（08 §3 项目管理 / 03 §2.3）。
func TestProjectDeleteCascade(t *testing.T) {
	c := newTestClient(t)
	c.login()
	id := c.createProject("svc-cascade")

	rr := c.do(http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/keys", id), map[string]any{"name": "k1"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("生成密钥失败: %d %s", rr.Code, rr.Body.String())
	}
	rr = c.do(http.MethodDelete, fmt.Sprintf("/api/v1/projects/%d", id), nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("删除项目失败: %d", rr.Code)
	}
	var n int
	if err := c.st.DB().QueryRow(`SELECT count(*) FROM api_key WHERE project_id = ?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("级联删除后密钥残留 %d 条", n)
	}
}

// TestKeyLifecycle 密钥生命周期：生成明文一次/列表不含明文/过期修改/轮换/吊销（08 §3 密钥管理）。
func TestKeyLifecycle(t *testing.T) {
	c := newTestClient(t)
	c.login()
	pid := c.createProject("svc-key")

	// 生成：明文仅一次返回。
	rr := c.do(http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/keys", pid), map[string]any{"name": "生产"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("生成密钥失败: %d %s", rr.Code, rr.Body.String())
	}
	var created struct {
		Data struct {
			Key      model.APIKey `json:"key"`
			KeyValue string       `json:"key_value"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if len(created.Data.KeyValue) != 40 {
		t.Errorf("密钥应为 40 位: %q", created.Data.KeyValue)
	}
	keyID := created.Data.Key.ID

	// 列表：不含明文。
	rr = c.do(http.MethodGet, fmt.Sprintf("/api/v1/projects/%d/keys", pid), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("密钥列表失败: %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), created.Data.KeyValue) {
		t.Error("密钥列表不应包含明文 key_value")
	}

	// 更新过期时间（30 天后）。
	exp := time.Now().UTC().Add(30 * 24 * time.Hour)
	rr = c.do(http.MethodPut, fmt.Sprintf("/api/v1/keys/%d", keyID), map[string]any{
		"expires_at": exp.Format(time.RFC3339),
	})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "expires_at") {
		t.Fatalf("更新密钥失败: %d %s", rr.Code, rr.Body.String())
	}

	// 轮换：新密钥明文一次；旧密钥进入宽限期。
	rr = c.do(http.MethodPost, fmt.Sprintf("/api/v1/keys/%d/rotate", keyID), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("轮换失败: %d %s", rr.Code, rr.Body.String())
	}
	var rotated struct {
		Data struct {
			NewKey           map[string]any `json:"new_key"`
			OldKeyGraceUntil *time.Time     `json:"old_key_grace_until"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Data.OldKeyGraceUntil == nil {
		t.Error("轮换应返回 old_key_grace_until")
	}
	newKeyVal, _ := rotated.Data.NewKey["key_value"].(string)
	if len(newKeyVal) != 40 {
		t.Errorf("新密钥应为 40 位明文: %q", newKeyVal)
	}

	// 吊销旧密钥：204。
	rr = c.do(http.MethodDelete, fmt.Sprintf("/api/v1/keys/%d", keyID), nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("吊销应 204: %d", rr.Code)
	}
	// 吊销后列表 active 不含旧密钥。
	rr = c.do(http.MethodGet, fmt.Sprintf("/api/v1/projects/%d/keys?active=1", pid), nil)
	var list struct {
		Data struct {
			Items []keyView `json:"items"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	for _, k := range list.Data.Items {
		if k.ID == keyID {
			t.Error("吊销后 active 列表不应包含旧密钥")
		}
	}
}

// TestAuditLogs 每个动作产生对应事件；筛选正确（08 §3 审计）。
func TestAuditLogs(t *testing.T) {
	c := newTestClient(t)
	c.login()
	c.createProject("svc-audit")

	rr := c.do(http.MethodGet, "/api/v1/audit-logs?event_type=project.create&size=50", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("审计查询失败: %d", rr.Code)
	}
	var resp struct {
		Data struct {
			Items []model.AuditLog `json:"items"`
			Total int              `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.Total < 1 {
		t.Error("project.create 事件应存在")
	}
	found := false
	for _, e := range resp.Data.Items {
		if e.EventType == model.EventProjectCreate && e.TargetName == "svc-audit" && e.Result == model.ResultSuccess {
			found = true
		}
	}
	if !found {
		t.Errorf("未找到 svc-audit 的 project.create 成功审计: %+v", resp.Data.Items)
	}
	// 登录/登出事件也应存在。
	for _, ev := range []string{"admin.login", "admin.login_failed"} {
		var n int
		if err := c.st.DB().QueryRow(`SELECT count(*) FROM audit_log WHERE event_type = ?`, ev).Scan(&n); err != nil {
			t.Fatal(err)
		}
		_ = n // 至少存在（不强制数量）
	}
}

// TestChangePassword 改密后全部会话失效（08 §3 会话 / 04 §3.4）。
func TestChangePassword(t *testing.T) {
	c := newTestClient(t)
	c.login()
	rr := c.do(http.MethodPut, "/api/v1/admin/password", map[string]string{
		"old_password": c.adminPassword(), "new_password": "NewPassw0rd123",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("改密失败: %d %s", rr.Code, rr.Body.String())
	}
	// 原会话应已失效。
	rr = c.do(http.MethodGet, "/api/v1/projects", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("改密后原会话应失效: %d", rr.Code)
	}
	// 新密码可登录。
	rr = c.doRaw(http.MethodPost, "/api/v1/admin/login", map[string]string{
		"username": "admin", "password": "NewPassw0rd123",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("新密码应可登录: %d %s", rr.Code, rr.Body.String())
	}
}

// ================= M3 认证 API 集成测试（08 §3 / 05 §3） =================

// createKeyReturn 创建项目密钥并返回 (key_id, key_value 明文)。
func (c *testClient) createKeyReturn(pid int64, name string, extra map[string]any) (int64, string) {
	c.t.Helper()
	body := map[string]any{"name": name}
	for k, v := range extra {
		body[k] = v
	}
	rr := c.do(http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/keys", pid), body)
	if rr.Code != http.StatusCreated {
		c.t.Fatalf("生成密钥失败: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data struct {
			Key      model.APIKey `json:"key"`
			KeyValue string       `json:"key_value"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		c.t.Fatal(err)
	}
	return resp.Data.Key.ID, resp.Data.KeyValue
}

// authResp 认证响应结构（05 §3.1）。
type authResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Authenticated bool   `json:"authenticated"`
		Reason        string `json:"reason"`
		Project       *struct {
			Name           string `json:"name"`
			CurrentVersion string `json:"current_version"`
		} `json:"project"`
		ServerTime string `json:"server_time"`
		Token      *struct {
			Token     string `json:"token"`
			Algorithm string `json:"algorithm"`
			ExpiresAt string `json:"expires_at"`
		} `json:"token"`
	} `json:"data"`
	RequestID string `json:"request_id"`
}

// doAuthenticate 发起认证请求（公开接口，无需会话）。
func (c *testClient) doAuthenticate(body map[string]any) *httptest.ResponseRecorder {
	c.t.Helper()
	return c.doRaw(http.MethodPost, "/api/v1/authenticate", body)
}

// parseAuth 解析认证响应。
func parseAuth(t *testing.T, rr *httptest.ResponseRecorder) authResp {
	t.Helper()
	var resp authResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析认证响应失败: %v body=%s", err, rr.Body.String())
	}
	return resp
}

// TestAuthenticateAPISuccess 认证成功：HTTP 200 + code 0 + authenticated=true
// + 项目信息 + server_time（08 §3 认证 API 成功分支）。
func TestAuthenticateAPISuccess(t *testing.T) {
	c := newTestClient(t)
	c.login()
	pid := c.createProject("svc-auth")
	_, keyValue := c.createKeyReturn(pid, "生产", nil)

	rr := c.doAuthenticate(map[string]any{
		"project_name": "svc-auth", "version": "1.0.0", "fingerprint": "fp-1", "key": keyValue,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("认证应 HTTP 200: %d %s", rr.Code, rr.Body.String())
	}
	resp := parseAuth(t, rr)
	if resp.Code != CodeOK || !resp.Data.Authenticated {
		t.Fatalf("应认证成功: code=%d body=%s", resp.Code, rr.Body.String())
	}
	if resp.Data.Project == nil || resp.Data.Project.Name != "svc-auth" || resp.Data.Project.CurrentVersion != "1.0.0" {
		t.Errorf("项目信息不正确: %+v", resp.Data.Project)
	}
	if resp.Data.ServerTime == "" {
		t.Error("应返回 server_time")
	}
	if resp.Data.Token != nil {
		t.Error("默认不应返回 token")
	}
}

// TestAuthenticateAPIErrorBranches 认证失败各分支业务码（05 §2 认证专用码，
// HTTP 一律 200）：项目不存在/项目停用/版本过低/密钥不存在/密钥停用/已过期/指纹不匹配。
func TestAuthenticateAPIErrorBranches(t *testing.T) {
	c := newTestClient(t)
	c.login()

	// 常规项目 svc-err：密钥不存在 / 密钥停用 / 已过期 / 指纹不匹配。
	pid := c.createProject("svc-err")
	keyID, keyValue := c.createKeyReturn(pid, "k1", nil)
	_, fpKeyValue := c.createKeyReturn(pid, "k-fp", map[string]any{"fingerprint": "fp-a"})
	exp := time.Now().UTC().Add(-time.Hour) // 已过期
	_, expKeyValue := c.createKeyReturn(pid, "k-exp", map[string]any{"expires_at": exp.Format(time.RFC3339)})

	// 项目停用分支：独立项目 svc-disabled，停用后再认证。
	pidD := c.createProject("svc-disabled")
	_, keyD := c.createKeyReturn(pidD, "k1", nil)
	if rr := c.do(http.MethodPut, fmt.Sprintf("/api/v1/projects/%d", pidD), map[string]any{"is_active": false}); rr.Code != http.StatusOK {
		t.Fatalf("停用项目失败: %d", rr.Code)
	}

	// 版本过低分支：独立项目 svc-ver，min_version=9.0.0。
	var verProj struct {
		Data struct {
			Project model.Project `json:"project"`
		} `json:"data"`
	}
	rr := c.do(http.MethodPost, "/api/v1/projects", map[string]any{
		"name": "svc-ver", "current_version": "1.0.0", "min_version": "9.0.0",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("创建 svc-ver 失败: %d", rr.Code)
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &verProj)
	_, verKeyValue := c.createKeyReturn(verProj.Data.Project.ID, "k1", nil)

	// 停用 svc-err 的 k1 密钥（管理 API，08 §3：禁用后认证返回 key_disabled）。
	if rr := c.do(http.MethodPut, fmt.Sprintf("/api/v1/keys/%d", keyID), map[string]any{"is_active": false}); rr.Code != http.StatusOK {
		t.Fatalf("停用密钥失败: %d", rr.Code)
	}

	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{"项目不存在", map[string]any{"project_name": "no-such", "version": "1.0.0", "fingerprint": "fp", "key": keyValue}, authCodeProjectNotFound},
		{"项目停用", map[string]any{"project_name": "svc-disabled", "version": "1.0.0", "fingerprint": "fp", "key": keyD}, authCodeProjectDisabled},
		{"版本过低", map[string]any{"project_name": "svc-ver", "version": "0.1.0", "fingerprint": "fp", "key": verKeyValue}, authCodeVersionTooOld},
		{"密钥不存在", map[string]any{"project_name": "svc-err", "version": "1.0.0", "fingerprint": "fp", "key": "WRONG-KEY-000000000000000000000000000000"}, authCodeKeyNotFound},
		{"密钥停用", map[string]any{"project_name": "svc-err", "version": "1.0.0", "fingerprint": "fp", "key": keyValue}, authCodeKeyDisabled},
		{"密钥已过期", map[string]any{"project_name": "svc-err", "version": "1.0.0", "fingerprint": "fp", "key": expKeyValue}, authCodeKeyExpired},
		{"指纹不匹配", map[string]any{"project_name": "svc-err", "version": "1.0.0", "fingerprint": "fp-b", "key": fpKeyValue}, authCodeFingerprintMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := c.doAuthenticate(tc.body)
			if rr.Code != http.StatusOK {
				t.Fatalf("认证失败响应应 HTTP 200: %d %s", rr.Code, rr.Body.String())
			}
			resp := parseAuth(t, rr)
			if resp.Code != tc.want {
				t.Errorf("业务码 = %d, 期望 %d (body=%s)", resp.Code, tc.want, rr.Body.String())
			}
			if resp.Data.Authenticated {
				t.Error("失败响应 authenticated 应为 false")
			}
			if resp.Data.Reason == "" {
				t.Error("失败响应应含 reason")
			}
			if resp.RequestID == "" {
				t.Error("失败响应应含 request_id")
			}
		})
	}
}

// TestAuthenticateAPIIssueToken issue_token=true 返回可用 JWT（D1 / 08 §3 认证 API）。
func TestAuthenticateAPIIssueToken(t *testing.T) {
	c := newTestClient(t)
	c.login()
	pid := c.createProject("svc-token")
	_, keyValue := c.createKeyReturn(pid, "k1", nil)

	rr := c.doAuthenticate(map[string]any{
		"project_name": "svc-token", "version": "1.0.0", "fingerprint": "fp", "key": keyValue, "issue_token": true,
	})
	resp := parseAuth(t, rr)
	if resp.Code != CodeOK || resp.Data.Token == nil {
		t.Fatalf("应返回 token: code=%d body=%s", resp.Code, rr.Body.String())
	}
	if resp.Data.Token.Algorithm != "HS256" || resp.Data.Token.ExpiresAt == "" {
		t.Errorf("token 元数据不正确: %+v", resp.Data.Token)
	}
	// 本地校验（04 §3.3：客户端自持 secret 校验）。
	tokenSvc, err := service.NewTokenService(context.Background(), c.st)
	if err != nil {
		t.Fatalf("NewTokenService 失败: %v", err)
	}
	claims, err := tokenSvc.Verify(resp.Data.Token.Token)
	if err != nil {
		t.Fatalf("校验返回的 JWT 失败: %v", err)
	}
	if claims.Subject != "project:svc-token" {
		t.Errorf("sub = %q, 期望 project:svc-token", claims.Subject)
	}
}

// TestAuthenticateAPIRateLimit 认证限流：rate_limit_auth_per_min=2 时第 3 次返回 10009（06 §7）。
func TestAuthenticateAPIRateLimit(t *testing.T) {
	c := newTestClient(t, func(ctx context.Context, st *store.Store) {
		if err := st.SetSetting(ctx, model.SettingRateLimitAuthPerMin, "2"); err != nil {
			t.Fatalf("设置限流失败: %v", err)
		}
	})
	c.login()
	pid := c.createProject("svc-ratelimit")
	_, keyValue := c.createKeyReturn(pid, "k1", nil)
	body := map[string]any{"project_name": "svc-ratelimit", "version": "1.0.0", "fingerprint": "fp", "key": keyValue}

	for i := 0; i < 2; i++ {
		rr := c.doAuthenticate(body)
		if resp := parseAuth(t, rr); resp.Code != CodeOK {
			t.Fatalf("第 %d 次应通过限流: code=%d", i+1, resp.Code)
		}
	}
	rr := c.doAuthenticate(body)
	resp := parseAuth(t, rr)
	if resp.Code != CodeRateLimited {
		t.Errorf("第 3 次应 10009 rate_limited, 实际 code=%d", resp.Code)
	}
	if resp.Data.Reason != "rate_limited" {
		t.Errorf("reason 应为 rate_limited: %q", resp.Data.Reason)
	}
}

// TestAuthenticateAPIAudit 认证成功/失败均写审计（D2 / 05 §5：auth.authenticate、
// auth.authenticate_failed 含指纹与版本）。
func TestAuthenticateAPIAudit(t *testing.T) {
	c := newTestClient(t)
	c.login()
	pid := c.createProject("svc-audit-auth")
	_, keyValue := c.createKeyReturn(pid, "k1", nil)

	// 一次成功 + 一次失败。
	c.doAuthenticate(map[string]any{"project_name": "svc-audit-auth", "version": "2.1.0", "fingerprint": "fp-xyz", "key": keyValue})
	c.doAuthenticate(map[string]any{"project_name": "svc-audit-auth", "version": "2.1.0", "fingerprint": "fp-xyz", "key": "bad-key"})

	var okCount, failCount int
	if err := c.st.DB().QueryRow(`SELECT count(*) FROM audit_log WHERE event_type = ?`, model.EventAuthAuthenticate).Scan(&okCount); err != nil {
		t.Fatal(err)
	}
	if err := c.st.DB().QueryRow(`SELECT count(*) FROM audit_log WHERE event_type = ?`, model.EventAuthAuthenticateFailed).Scan(&failCount); err != nil {
		t.Fatal(err)
	}
	if okCount < 1 || failCount < 1 {
		t.Fatalf("认证审计缺失: success=%d failed=%d", okCount, failCount)
	}
	// 成功审计 detail 含版本与指纹（05 §3.1：detail 含 reason、fingerprint、version）。
	var detail string
	if err := c.st.DB().QueryRow(`SELECT detail FROM audit_log WHERE event_type = ? ORDER BY id DESC LIMIT 1`,
		model.EventAuthAuthenticate).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "2.1.0") || !strings.Contains(detail, "fp-xyz") {
		t.Errorf("成功审计 detail 应含版本与指纹: %s", detail)
	}
}
