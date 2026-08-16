package httpapi

import (
	"log/slog"
	"net/http"
)

// Router 装配路由与中间件（M1 骨架：healthz + 占位根路径；管理/认证 API 随 M2/M3 加入）。
func Router(logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	// 运维接口（文档 07 §5.3）。
	mux.HandleFunc("GET /healthz", healthz)

	// 根路径占位：M1 尚无前端（M4/M5 内嵌 web 后替换为 http.FileServer）。
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			fail(w, http.StatusNotFound, 20200, "资源不存在")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>AuthCenter</title></head><body>
<h1>AuthCenter 中心认证服务</h1>
<p>服务运行中（M1 骨架）。管理界面将在后续里程碑提供。</p>
<p>健康检查：<a href="/healthz">/healthz</a></p>
</body></html>`))
	})

	// 中间件链（由外到内：Recover → RequestID → AccessLog → LimitBody）。
	return Recover(RequestID(AccessLog(logger)(LimitBody(mux))))
}
