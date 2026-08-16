package httpapi

import (
	"net/http"

	"github.com/authcenter/authcenter/internal/service"
)

// statsHandlers 仪表盘统计 handlers（后端架构文档 05 §4.5）。
type statsHandlers struct {
	stats *service.StatsService
}

// handleStats GET /api/v1/stats：返回仪表盘统计（需会话）。
func (h *statsHandlers) handleStats(w http.ResponseWriter, r *http.Request) {
	s, err := h.stats.Get(r.Context())
	if err != nil {
		failService(w, err)
		return
	}
	ok(w, s)
}
