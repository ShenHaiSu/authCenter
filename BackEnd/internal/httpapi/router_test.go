package httpapi

import (
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/service"
	"github.com/authcenter/authcenter/internal/store"
)

// testRouter 构造带完整依赖的测试路由（临时 SQLite + 全部 service）。
func testRouter(t *testing.T) http.Handler {
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
	return New(RouterDeps{
		Logger:   logger,
		Store:    st,
		Sessions: sessionSvc,
		Projects: projectSvc,
		Apikeys:  apikeySvc,
		Audits:   auditSvc,
		Stats:    service.NewStatsService(st),
		WebFS:    frontEndTestFS(t),
	})
}

// frontEndTestFS 返回 FrontEnd/ 源目录作为测试静态资源树。
// go test 的工作目录在不同调用方式下可能为包目录或仓库根，因此从
// os.Getwd() 逐级向上查找含 index.html 的 FrontEnd/ 目录（最多 5 级）。
func frontEndTestFS(t *testing.T) fs.FS {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd 失败: %v", err)
	}
	dir := wd
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(filepath.Join(dir, "FrontEnd", "index.html")); err == nil {
			return os.DirFS(filepath.Join(dir, "FrontEnd"))
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("未找到 FrontEnd/index.html（起点 %s）: 静态资源测试无法运行", wd)
	return nil
}

// TestHealthz GET /healthz 返回 200 "ok"（文档 07 §5.3）。
func TestHealthz(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	testRouter(t).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, 期望 200", rr.Code)
	}
	if body := rr.Body.String(); body != "ok" {
		t.Errorf("body = %q, 期望 ok", body)
	}
}

// TestRequestID 响应带 X-Request-Id；透传客户端提供的 id。
func TestRequestID(t *testing.T) {
	// 透传
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-Id", "client-trace-123")
	testRouter(t).ServeHTTP(rr, req)
	if got := rr.Header().Get("X-Request-Id"); got != "client-trace-123" {
		t.Errorf("透传 X-Request-Id = %q", got)
	}

	// 自动生成
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	testRouter(t).ServeHTTP(rr2, req2)
	got := rr2.Header().Get("X-Request-Id")
	if len(got) != 32 {
		t.Errorf("自动生成 X-Request-Id 长度 = %d, 期望 32", len(got))
	}
}

// TestUnknownAPIPath 未注册的 /api/v1/* 路径返回 404 JSON（业务码 20200）。
func TestUnknownAPIPath(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/not-exist", nil)
	testRouter(t).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, 期望 404", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"code":20200`) {
		t.Errorf("body 应含业务码 20200: %s", body)
	}
	if !strings.Contains(body, "request_id") {
		t.Errorf("失败响应应含 request_id: %s", body)
	}
}

// TestRootServesFrontEnd 根路径返回前端主界面 index.html（M4：内嵌/磁盘静态资源）。
func TestRootServesFrontEnd(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	testRouter(t).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, 期望 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "AuthCenter") {
		t.Errorf("首页应包含 AuthCenter: %s", rr.Body.String())
	}
}

// TestLoginHTML GET /login.html 返回登录页（08 §3 静态资源）。
func TestLoginHTML(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login.html", nil)
	testRouter(t).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, 期望 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "login-form") || !strings.Contains(body, "password") {
		t.Errorf("登录页应包含登录表单: %s", body)
	}
}

// TestStaticAssets 静态 css/js 资源可访问（02 §9：全部资源本地化、内嵌可用）。
func TestStaticAssets(t *testing.T) {
	for _, path := range []string{
		"/css/base.css", "/css/auth.css",
		"/js/api.js", "/js/common.js", "/js/login.js", "/js/app.js",
		"/js/dashboard.js", "/js/projects.js", "/js/keys.js", "/js/audit.js",
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		testRouter(t).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, 期望 200", path, rr.Code)
		}
	}
}

// TestRootNotFound 不存在的静态资源路径返回 404。
func TestRootNotFound(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	testRouter(t).ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, 期望 404", rr.Code)
	}
}

// TestDirListingBlocked 目录请求不返回目录列表（安全约束 06 §11）。
func TestDirListingBlocked(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/css/", nil)
	testRouter(t).ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("/css/ 目录请求 status = %d, 期望 404（禁止目录列表）", rr.Code)
	}
}

// TestLimitBody 请求体超过 1MB 时读取应报错（MaxBytesReader，文档 02 §8）。
func TestLimitBody(t *testing.T) {
	// 单独测中间件 + 读取 body 的 handler：超过上限时 Decode 失败。
	mux := http.NewServeMux()
	mux.HandleFunc("POST /echo", func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		if err != nil {
			// MaxBytesError 表示超限（http.MaxBytesError）。
			fail(w, http.StatusBadRequest, 20002, "请求体过大")
			return
		}
		ok(w, "read-ok")
	})
	h := LimitBody(mux)

	rr := httptest.NewRecorder()
	big := strings.Repeat("a", MaxBodyBytes+1024)
	req := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader(big))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("超大请求体 status = %d, 期望 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"code":20002`) {
		t.Errorf("body 应含业务码 20002: %s", rr.Body.String())
	}

	// 正常大小请求体不受影响。
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader(`{"ok":true}`))
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK || !strings.Contains(rr2.Body.String(), `"code":0`) {
		t.Errorf("正常请求体应成功: status=%d body=%s", rr2.Code, rr2.Body.String())
	}
}

// TestRecoverPanic panic 应被恢复为 500 JSON（业务码 50000）。
func TestRecoverPanic(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})
	h := Recover(mux)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, 期望 500", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"code":50000`) {
		t.Errorf("body 应含业务码 50000: %s", rr.Body.String())
	}
}
