package service

import (
	"context"
	"time"

	"github.com/authcenter/authcenter/internal/store"
)

// Stats 仪表盘统计（后端架构文档 05 §4.5 / 前端文档 02 §3）。
type Stats struct {
	Projects       int       `json:"projects"`         // 项目总数
	ActiveKeys     int       `json:"active_keys"`      // 启用状态密钥数
	ExpiringKeys7d int       `json:"expiring_keys_7d"` // 7 天内到期密钥数（不含已过期）
	AuthToday      AuthStats `json:"auth_today"`       // 今日认证次数
}

// AuthStats 今日认证统计（成功/失败/总数）。
type AuthStats struct {
	Total   int `json:"total"`
	Success int `json:"success"`
	Failure int `json:"failure"`
}

// StatsService 仪表盘统计服务（04 §1 目录结构 stats_service.go，P2 落地）。
type StatsService struct {
	store *store.Store
}

// NewStatsService 构造统计服务。
func NewStatsService(st *store.Store) *StatsService {
	return &StatsService{store: st}
}

// Get 汇总仪表盘统计：项目数 / 有效密钥数 / 7 天内到期密钥数 / 今日认证次数。
func (s *StatsService) Get(ctx context.Context) (*Stats, error) {
	now := time.Now().UTC()

	projects, err := s.store.CountProjects(ctx)
	if err != nil {
		return nil, err
	}
	activeKeys, err := s.store.CountActiveKeys(ctx)
	if err != nil {
		return nil, err
	}
	expiring, err := s.store.CountExpiringKeys(ctx, now, now.Add(7*24*time.Hour))
	if err != nil {
		return nil, err
	}
	// 今日 = UTC 当日 0 点起（审计 event_time 统一存 UTC，03 §5）。
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	total, success, failure, err := s.store.CountAuthToday(ctx, dayStart)
	if err != nil {
		return nil, err
	}

	return &Stats{
		Projects:       projects,
		ActiveKeys:     activeKeys,
		ExpiringKeys7d: expiring,
		AuthToday: AuthStats{
			Total:   total,
			Success: success,
			Failure: failure,
		},
	}, nil
}
