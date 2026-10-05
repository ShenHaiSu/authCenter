package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"strconv"

	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

// 保留策略默认值与范围（need01 01 §3 / 05 §1）。
const (
	DefaultAuditRetDays      = 90
	DefaultAuditCleanupHours = 24
	DefaultAuditMinKeepRows  = 1000
	MaxAuditRetDays          = 3650
	MaxAuditCleanupHours     = 720
)

// RetentionConfig 审计保留策略配置快照。
type RetentionConfig struct {
	Days            int    `json:"audit_retention_days"`
	IntervalHours   int    `json:"audit_cleanup_interval_hours"`
	MinKeepRows     int    `json:"audit_min_keep_rows"`
	LastCleanupAt   string `json:"audit_last_cleanup_at"`
	LastCleanupRows int64  `json:"audit_last_cleanup_rows"`
}

// SettingsService 白名单读写 + 校验 + settings.update 审计（need01 01 §9 步骤 3）。
type SettingsService struct {
	store  *store.Store
	audit  *AuditService
	logger *slog.Logger
}

// NewSettingsService 构造 SettingsService。
func NewSettingsService(st *store.Store, audit *AuditService, logger *slog.Logger) *SettingsService {
	if logger == nil {
		logger = slog.Default()
	}
	return &SettingsService{store: st, audit: audit, logger: logger}
}

func parseIntWithDefault(raw string, def int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

// LoadConfig 读取保留策略，非法字符串回退默认（沿用 loadRotateGraceDays 容错风格）。
func (s *SettingsService) LoadConfig(ctx context.Context) (RetentionConfig, error) {
	var cfg RetentionConfig
	rawDays, err := s.store.GetSetting(ctx, model.SettingAuditRetDays)
	if err != nil {
		return cfg, err
	}
	rawInterval, err := s.store.GetSetting(ctx, model.SettingAuditCleanupIntervalHours)
	if err != nil {
		return cfg, err
	}
	rawMinKeep, err := s.store.GetSetting(ctx, model.SettingAuditMinKeepRows)
	if err != nil {
		return cfg, err
	}
	cfg.Days = parseIntWithDefault(rawDays, DefaultAuditRetDays)
	if rawDays != "" {
		if _, err := strconv.Atoi(rawDays); err != nil {
			s.logger.Warn("audit_retention_days 非法，回退默认", "value", rawDays, "default", DefaultAuditRetDays)
		}
	}
	// 范围外的值在展示层仍回退默认，真正校验在 Update 时拒绝。
	if cfg.Days < 0 || cfg.Days > MaxAuditRetDays {
		s.logger.Warn("audit_retention_days 越界，回退默认", "value", cfg.Days)
		cfg.Days = DefaultAuditRetDays
	}
	cfg.IntervalHours = parseIntWithDefault(rawInterval, DefaultAuditCleanupHours)
	if rawInterval != "" {
		if _, err := strconv.Atoi(rawInterval); err != nil {
			s.logger.Warn("audit_cleanup_interval_hours 非法，回退默认", "value", rawInterval)
		}
	}
	if cfg.IntervalHours < 1 || cfg.IntervalHours > MaxAuditCleanupHours {
		s.logger.Warn("audit_cleanup_interval_hours 越界，回退默认", "value", cfg.IntervalHours)
		cfg.IntervalHours = DefaultAuditCleanupHours
	}
	cfg.MinKeepRows = parseIntWithDefault(rawMinKeep, DefaultAuditMinKeepRows)
	if rawMinKeep != "" {
		if _, err := strconv.Atoi(rawMinKeep); err != nil {
			s.logger.Warn("audit_min_keep_rows 非法，回退默认", "value", rawMinKeep)
		}
	}
	if cfg.MinKeepRows < 0 {
		s.logger.Warn("audit_min_keep_rows 越界，回退默认", "value", cfg.MinKeepRows)
		cfg.MinKeepRows = DefaultAuditMinKeepRows
	}
	if v, err := s.store.GetSetting(ctx, model.SettingAuditLastCleanupAt); err != nil {
		return cfg, err
	} else {
		cfg.LastCleanupAt = v
	}
	if v, err := s.store.GetSetting(ctx, model.SettingAuditLastCleanupRows); err != nil {
		return cfg, err
	} else {
		cfg.LastCleanupRows = int64(parseIntWithDefault(v, 0))
	}
	return cfg, nil
}

// ValidateRetention 校验三项范围，失败返回 ErrInvalidParameter（附字段说明）。
func ValidateRetention(days, intervalHours, minKeepRows *int) error {
	if days != nil {
		if *days < 0 || *days > MaxAuditRetDays {
			return fmt.Errorf("%w: audit_retention_days 必须在 0..3650", ErrInvalidParameter)
		}
	}
	if intervalHours != nil {
		if *intervalHours < 1 || *intervalHours > MaxAuditCleanupHours {
			return fmt.Errorf("%w: audit_cleanup_interval_hours 必须在 1..720", ErrInvalidParameter)
		}
	}
	if minKeepRows != nil {
		if *minKeepRows < 0 {
			return fmt.Errorf("%w: audit_min_keep_rows 必须 >= 0", ErrInvalidParameter)
		}
	}
	return nil
}

// UpdateConfig 部分更新保留策略（未出现的键保持不变），落 settings + 写 settings.update 审计。
func (s *SettingsService) UpdateConfig(ctx context.Context, actor *model.AdminUser, days, intervalHours, minKeepRows *int, ip string) (RetentionConfig, error) {
	if err := ValidateRetention(days, intervalHours, minKeepRows); err != nil {
		return RetentionConfig{}, err
	}
	changed := map[string]string{}
	if days != nil {
		if err := s.store.SetSetting(ctx, model.SettingAuditRetDays, strconv.Itoa(*days)); err != nil {
			return RetentionConfig{}, err
		}
		changed[model.SettingAuditRetDays] = strconv.Itoa(*days)
	}
	if intervalHours != nil {
		if err := s.store.SetSetting(ctx, model.SettingAuditCleanupIntervalHours, strconv.Itoa(*intervalHours)); err != nil {
			return RetentionConfig{}, err
		}
		changed[model.SettingAuditCleanupIntervalHours] = strconv.Itoa(*intervalHours)
	}
	if minKeepRows != nil {
		if err := s.store.SetSetting(ctx, model.SettingAuditMinKeepRows, strconv.Itoa(*minKeepRows)); err != nil {
			return RetentionConfig{}, err
		}
		changed[model.SettingAuditMinKeepRows] = strconv.Itoa(*minKeepRows)
	}
	// settings.update 审计：只记键名与值哈希，不记原值（need01 01 §7）。
	keys := make([]string, 0, len(changed))
	for k := range changed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	joined := ""
	for _, k := range keys {
		joined += k + "=" + changed[k] + ";"
	}
	sum := sha256.Sum256([]byte(joined))
	detail := fmt.Sprintf(`{"keys":%q,"values_hash":%q}`, keys, hex.EncodeToString(sum[:])[:16])
	actorID, actorName := "", ""
	if actor != nil {
		actorID = strconv.FormatInt(actor.ID, 10)
		actorName = actor.Username
	}
	s.audit.Log(ctx, &model.AuditLog{
		EventType: model.EventSettingsUpdate, ActorType: model.ActorTypeAdmin,
		ActorID: actorID, ActorName: actorName,
		TargetType: model.TargetTypeSystem,
		Result:     model.ResultSuccess, Detail: detail,
		IP: ip, RequestID: requestIDFrom(ctx),
	})
	return s.LoadConfig(ctx)
}
