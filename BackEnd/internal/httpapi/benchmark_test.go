package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/service"
	"github.com/authcenter/authcenter/internal/store"
)

// BenchmarkHealthz 测 HTTP 骨架（中间件链 + healthz）单请求延迟。
// 文档 01 §5 目标：认证接口 P99 < 50ms、≥100 QPS；healthz 应远低于该预算。
func BenchmarkHealthz(b *testing.B) {
	handler := benchRouter()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}

// BenchmarkUnknownAPI404 测完整中间件链 + 404 JSON 失败响应的固定开销
// （所有管理/认证 API 失败分支都走同一路径，需预留延迟预算）。
func BenchmarkUnknownAPI404(b *testing.B) {
	handler := benchRouter()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/not-exist", strings.NewReader(`{}`))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}

// benchRouter 构造带完整依赖的路由（M2 起 Router 需要 store/service 装配）。
func benchRouter() http.Handler {
	dir, err := os.MkdirTemp("", "acbench-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	db, err := database.Open(dir)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	st := store.New(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditSvc := service.NewAuditService(st, logger)
	sessionSvc := service.NewSessionService(st, logger)
	projectSvc := service.NewProjectService(st, auditSvc)
	apikeySvc := service.NewApiKeyService(st, auditSvc, projectSvc, 7, nil)
	return New(RouterDeps{
		Logger:   logger,
		Store:    st,
		Sessions: sessionSvc,
		Projects: projectSvc,
		Apikeys:  apikeySvc,
		Audits:   auditSvc,
	})
}
