package httpapi

import (
	"net/http"
)

// healthz 运维专用公开接口：返回 200 "ok"，不写审计（文档 07 §5.3）。
// 供 Caddy / systemd / 监控探测。
func healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
