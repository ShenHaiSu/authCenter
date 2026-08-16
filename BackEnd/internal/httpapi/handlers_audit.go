package httpapi

import (
	"net/http"
	"strings"

	"github.com/authcenter/authcenter/internal/service"
	"github.com/authcenter/authcenter/internal/store"
)

// auditHandlers 审计日志查询 handlers（文档 05 §4.4）。
type auditHandlers struct {
	audits *service.AuditService
}

// handleListAuditLogs GET /api/v1/audit-logs?page=&size=&event_type=&result=&actor=&from=&to=&q=
func (h *auditHandlers) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	page, size := parsePagination(r)
	q := r.URL.Query()
	filter := store.AuditFilter{
		EventType: strings.TrimSpace(q.Get("event_type")),
		Result:    strings.TrimSpace(q.Get("result")),
		Actor:     strings.TrimSpace(q.Get("actor")),
		From:      strings.TrimSpace(q.Get("from")),
		To:        strings.TrimSpace(q.Get("to")),
		Q:         strings.TrimSpace(q.Get("q")),
	}
	items, total, err := h.audits.List(r.Context(), filter, page, size)
	if err != nil {
		failService(w, err)
		return
	}
	ok(w, map[string]any{"items": items, "total": total, "page": page, "size": size})
}
