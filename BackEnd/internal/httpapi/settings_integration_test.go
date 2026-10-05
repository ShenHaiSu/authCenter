package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

func settingsBody(t *testing.T, body []byte) (map[string]any, map[string]any) {
	t.Helper()
	var resp struct {
		Data struct {
			Settings map[string]any `json:"settings"`
			Usage    map[string]any `json:"usage"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("解析 settings 响应失败: %v body=%s", err, string(body))
	}
	return resp.Data.Settings, resp.Data.Usage
}

// TestSettingsGetRedactsSecret GET /settings 不含 jwt_secret。
func TestSettingsGetRedactsSecret(t *testing.T) {
	c := newTestClient(t)
	c.login()
	rr := c.do(http.MethodGet, "/api/v1/settings", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "jwt_secret") {
		t.Fatalf("响应不应含 jwt_secret: %s", rr.Body.String())
	}
	s, u := settingsBody(t, rr.Body.Bytes())
	for _, k := range []string{"audit_retention_days", "audit_cleanup_interval_hours", "audit_min_keep_rows"} {
		if _, ok := s[k]; !ok {
			t.Errorf("settings 缺少 %s", k)
		}
	}
	if _, ok := u["total_rows"]; !ok {
		t.Error("usage 缺少 total_rows")
	}
}

// TestSettingsUpdateValidation 越界 400/20001，合法 200 + settings.update 审计。
func TestSettingsUpdateValidation(t *testing.T) {
	c := newTestClient(t)
	c.login()
	rr := c.do(http.MethodPut, "/api/v1/settings", map[string]any{"audit_retention_days": 3651})
	if rr.Code != http.StatusBadRequest || bodyCode(t, rr) != CodeInvalidParam {
		t.Fatalf("越界应 400/20001: status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = c.do(http.MethodPut, "/api/v1/settings", map[string]any{"audit_retention_days": 180})
	if rr.Code != http.StatusOK {
		t.Fatalf("合法应 200: status=%d body=%s", rr.Code, rr.Body.String())
	}
	items, _, err := c.st.ListAudits(context.Background(), store.AuditFilter{EventType: "settings.update"}, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range items {
		if it.EventType == "settings.update" {
			found = true
		}
	}
	if !found {
		t.Error("缺少 settings.update 审计")
	}
}

// TestAuditCleanupNowEndpoint POST cleanup-now 返回 deleted_rows 且审计一致。
func TestAuditCleanupNowEndpoint(t *testing.T) {
	c := newTestClient(t)
	c.login()
	c.do(http.MethodPut, "/api/v1/settings", map[string]any{"audit_retention_days": 1, "audit_min_keep_rows": 0})
	oldT := time.Now().UTC().Add(-48 * time.Hour)
	for i := 0; i < 2; i++ {
		if err := c.st.InsertAudit(context.Background(), &model.AuditLog{
			EventTime: oldT, EventType: model.EventAuthAuthenticate,
			ActorType: model.ActorTypeClient, ActorName: "old", Result: model.ResultSuccess,
		}); err != nil {
			t.Fatal(err)
		}
	}
	rr := c.do(http.MethodPost, "/api/v1/settings/audit/cleanup-now", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("cleanup-now status=%d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Data struct {
			DeletedRows int64 `json:"deleted_rows"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Data.DeletedRows < 2 {
		t.Fatalf("deleted_rows = %d，期望 >= 2", got.Data.DeletedRows)
	}
	items, _, err := c.st.ListAudits(context.Background(), store.AuditFilter{EventType: "system.audit_cleanup"}, 1, 10)
	if err != nil || len(items) == 0 {
		t.Fatalf("缺少 system.audit_cleanup 审计: %v", err)
	}
}

// TestAuditCleanupRequiresSession 无 cookie → 401/20103。
func TestAuditCleanupRequiresSession(t *testing.T) {
	c := newTestClient(t)
	if rr := c.doRaw(http.MethodGet, "/api/v1/settings", nil); rr.Code != http.StatusUnauthorized || bodyCode(t, rr) != CodeSessionExpired {
		t.Fatalf("GET /settings 无会话应 401/20103: status=%d body=%s", rr.Code, rr.Body.String())
	}
	for _, p := range []string{"/api/v1/settings/audit/cleanup-now", "/api/v1/settings/audit/checkpoint"} {
		if rr := c.doRaw(http.MethodPost, p, nil); rr.Code != http.StatusUnauthorized || bodyCode(t, rr) != CodeSessionExpired {
			t.Fatalf("POST %s 无会话应 401/20103: status=%d body=%s", p, rr.Code, rr.Body.String())
		}
	}
	rr := c.doRaw(http.MethodPut, "/api/v1/settings", map[string]any{"audit_retention_days": 90})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("PUT 无会话应 401: status=%d", rr.Code)
	}
}

// TestAuditRetentionKeepsRecentForUI 清理后近期记录仍可查。
func TestAuditRetentionKeepsRecentForUI(t *testing.T) {
	c := newTestClient(t)
	c.login()
	c.do(http.MethodPut, "/api/v1/settings", map[string]any{"audit_retention_days": 30, "audit_min_keep_rows": 0})
	rr := c.do(http.MethodPost, "/api/v1/settings/audit/cleanup-now", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("cleanup status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = c.do(http.MethodGet, "/api/v1/audit-logs?size=5", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("audit-logs status=%d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Data struct {
			Items []any `json:"items"`
			Total int   `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Data.Total == 0 {
		t.Fatal("近期记录不应被误删")
	}
}

// TestAuditCleanupDoesNotBreakAuth 清理后认证仍成功。
func TestAuditCleanupDoesNotBreakAuth(t *testing.T) {
	c := newTestClient(t)
	c.login()
	pid := c.createProject("svc-cleanup-auth")
	_, plain := c.createKeyReturn(pid, "k1", nil)
	c.do(http.MethodPut, "/api/v1/settings", map[string]any{"audit_retention_days": 30, "audit_min_keep_rows": 0})
	if rr := c.do(http.MethodPost, "/api/v1/settings/audit/cleanup-now", nil); rr.Code != http.StatusOK {
		t.Fatalf("cleanup status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr := c.doAuthenticate(map[string]any{"project_name": "svc-cleanup-auth", "version": "1.0.0", "fingerprint": "", "key": plain})
	if rr.Code != http.StatusOK {
		t.Fatalf("清理后认证应成功: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

// TestAuditCheckpointEndpoint checkpoint 端点可用。
func TestAuditCheckpointEndpoint(t *testing.T) {
	c := newTestClient(t)
	c.login()
	rr := c.do(http.MethodPost, "/api/v1/settings/audit/checkpoint", nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "truncated") {
		t.Fatalf("checkpoint 应 200 且含 truncated: status=%d body=%s", rr.Code, rr.Body.String())
	}
}
