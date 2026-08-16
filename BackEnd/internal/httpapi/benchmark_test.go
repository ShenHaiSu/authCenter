package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// BenchmarkHealthz 测 HTTP 骨架（中间件链 + healthz）单请求延迟。
// 文档 01 §5 目标：认证接口 P99 < 50ms、≥100 QPS；healthz 应远低于该预算。
func BenchmarkHealthz(b *testing.B) {
	handler := Router(slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}
}
