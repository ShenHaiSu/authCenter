package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/model"
)

// AuditFilter 审计日志查询筛选（文档 05 §4.4）。
type AuditFilter struct {
	EventType string
	Result    string
	Actor     string // 按 actor_id 或 actor_name 模糊匹配
	From      string // ISO8601 UTC（含）
	To        string // ISO8601 UTC（含）
	Q         string // 对 target_name / detail 模糊匹配
}

// ListAudits 分页查询审计日志，按时间倒序。
func (s *AuditStore) ListAudits(ctx context.Context, f AuditFilter, page, size int) ([]model.AuditLog, int, error) {
	where := []string{"1=1"}
	args := []any{}
	if f.EventType != "" {
		where = append(where, "event_type = ?")
		args = append(args, f.EventType)
	}
	if f.Result != "" {
		where = append(where, "result = ?")
		args = append(args, f.Result)
	}
	if f.Actor != "" {
		where = append(where, "(actor_id LIKE ? OR actor_name LIKE ?)")
		args = append(args, "%"+f.Actor+"%", "%"+f.Actor+"%")
	}
	if f.From != "" {
		where = append(where, "event_time >= ?")
		args = append(args, f.From)
	}
	if f.To != "" {
		where = append(where, "event_time <= ?")
		args = append(args, f.To)
	}
	if f.Q != "" {
		where = append(where, "(target_name LIKE ? OR detail LIKE ?)")
		args = append(args, "%"+f.Q+"%", "%"+f.Q+"%")
	}
	cond := "WHERE " + strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM audit_log `+cond, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计审计失败: %w", err)
	}

	limitArgs := append(append([]any{}, args...), size, (page-1)*size)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, event_time, event_type, actor_type, actor_id, actor_name,
		        target_type, target_id, target_name, result, detail, ip, request_id
		 FROM audit_log `+cond+` ORDER BY id DESC LIMIT ? OFFSET ?`, limitArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询审计失败: %w", err)
	}
	defer rows.Close()

	items := []model.AuditLog{}
	for rows.Next() {
		var e model.AuditLog
		var eventTime, actorType, actorName string
		var actorID, targetType, targetName, detail, ip, requestID sql.NullString
		var targetID sql.NullInt64
		if err := rows.Scan(&e.ID, &eventTime, &e.EventType, &actorType, &actorID, &actorName,
			&targetType, &targetID, &targetName, &e.Result, &detail, &ip, &requestID); err != nil {
			return nil, 0, fmt.Errorf("扫描审计失败: %w", err)
		}
		e.ActorType = actorType
		e.ActorID = actorID.String
		e.ActorName = actorName
		e.TargetType = targetType.String
		e.TargetID = targetID.Int64
		e.TargetName = targetName.String
		e.Detail = detail.String
		e.IP = ip.String
		e.RequestID = requestID.String
		if t, err := parseTime(eventTime); err != nil {
			return nil, 0, err
		} else {
			e.EventTime = t
		}
		items = append(items, e)
	}
	return items, total, rows.Err()
}

// CountAuthToday 统计今日认证次数：since 起（UTC 当日 0 点）的
// auth.authenticate（成功）与 auth.authenticate_failed（失败）计数
// （仪表盘 auth_today，05 §4.5 / 02 §3）。
func (s *AuditStore) CountAuthToday(ctx context.Context, since time.Time) (total, success, failure int, err error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT event_type, count(*) FROM audit_log
		 WHERE event_time >= ? AND event_type IN (?, ?)
		 GROUP BY event_type`,
		database.FormatTime(since), model.EventAuthAuthenticate, model.EventAuthAuthenticateFailed)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("统计今日认证失败: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ev string
		var n int
		if err := rows.Scan(&ev, &n); err != nil {
			return 0, 0, 0, fmt.Errorf("扫描今日认证统计失败: %w", err)
		}
		switch ev {
		case model.EventAuthAuthenticate:
			success = n
		case model.EventAuthAuthenticateFailed:
			failure = n
		}
	}
	if err := rows.Err(); err != nil {
		return 0, 0, 0, fmt.Errorf("今日认证统计迭代失败: %w", err)
	}
	total = success + failure
	return total, success, failure, nil
}
