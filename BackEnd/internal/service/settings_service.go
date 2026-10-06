package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
// F-021：新增密钥存储加密状态查询与「启用加密」（need01 03 §4.6）。
type SettingsService struct {
	store  *store.Store
	audit  *AuditService
	logger *slog.Logger
	cipher Cipher // F-021：未配置主密钥时为 PlainCipher
}

// NewSettingsService 构造 SettingsService（未配置主密钥：明文模式）。
func NewSettingsService(st *store.Store, audit *AuditService, logger *slog.Logger) *SettingsService {
	return NewSettingsServiceWithCipher(st, audit, logger, PlainCipher{})
}

// NewSettingsServiceWithCipher 构造带主密钥的 SettingsService（F-021 装配路径）。
func NewSettingsServiceWithCipher(st *store.Store, audit *AuditService, logger *slog.Logger, c Cipher) *SettingsService {
	if logger == nil {
		logger = slog.Default()
	}
	if c == nil {
		c = PlainCipher{}
	}
	return &SettingsService{store: st, audit: audit, logger: logger, cipher: c}
}

// CipherEnabled 报告进程是否持有可用主密钥（仅布尔，绝不返回密钥或其哈希）。
func (s *SettingsService) CipherEnabled() bool { return s.cipher.Enabled() }

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

// ================= F-021 密钥存储加密（need01 03 §4.6 / §5） =================

// keyEncryptBatchSize 启用加密时每批处理行数（need01 03 §4.6）。
const keyEncryptBatchSize = 1000

// maxEncryptBatches 单次启用动作的批数上限（防病态数据下无界循环）。
const maxEncryptBatches = 100000

// KeyEncryptionStatus 密钥存储加密状态（GET /api/v1/settings 展示，03 §5.1）。
type KeyEncryptionStatus struct {
	Enabled             bool   `json:"key_encryption_enabled"`
	Version             string `json:"key_encryption_version"`
	EncryptedCount      int64  `json:"key_encrypted_count"`
	MasterKeyConfigured bool   `json:"master_key_configured"`
	Mode                string `json:"mode"` // encrypted | plaintext
	BackfillState       string `json:"key_hash_backfill_state"`
	BackfillDoneAt      string `json:"key_hash_backfill_done_at"`
	TotalKeys           int64  `json:"total_keys"`
	PendingHashRows     int64  `json:"pending_hash_rows"`
}

// LoadKeyEncryption 读取加密状态（只读，无副作用）。
func (s *SettingsService) LoadKeyEncryption(ctx context.Context) (KeyEncryptionStatus, error) {
	var st KeyEncryptionStatus
	rawEnabled, err := s.store.GetSetting(ctx, model.SettingKeyEncryptionEnabled)
	if err != nil {
		return st, err
	}
	rawVersion, err := s.store.GetSetting(ctx, model.SettingKeyEncryptionVersion)
	if err != nil {
		return st, err
	}
	rawState, err := s.store.GetSetting(ctx, model.SettingKeyHashBackfillState)
	if err != nil {
		return st, err
	}
	rawDoneAt, err := s.store.GetSetting(ctx, model.SettingKeyHashBackfillDoneAt)
	if err != nil {
		return st, err
	}
	st.Enabled = rawEnabled == "1"
	st.Version = rawVersion
	st.BackfillState = rawState
	st.BackfillDoneAt = rawDoneAt
	st.MasterKeyConfigured = s.cipher.Enabled()
	// 展示口径以「主密钥已配置」为准：配置了主密钥即新写入走密文（预配置模式）。
	if s.cipher.Enabled() {
		st.Mode = "encrypted"
	} else {
		st.Mode = "plaintext"
	}
	if st.EncryptedCount, err = s.store.CountEncrypted(ctx); err != nil {
		return st, err
	}
	if st.TotalKeys, err = s.store.CountKeys(ctx); err != nil {
		return st, err
	}
	if st.PendingHashRows, err = s.store.CountKeysWithoutHash(ctx); err != nil {
		return st, err
	}
	return st, nil
}

// EnableKeyEncryption 启用密钥存储加密：把全部明文行原地加密（按批 1000 行）。
//
// 前置条件（03 §4.6）：env 已提供主密钥；key_hash 回填已完成（否则加密后
// 无 hash 的行将永远查不到，且回填会把密文当明文算 hash）。违反即 ErrStateConflict。
//
// 只提供启用，不提供运行时关闭（单向棘轮，03 §4.6）。
// 已提交批次不回滚，可重跑（未加密行会被再次处理）。
func (s *SettingsService) EnableKeyEncryption(ctx context.Context, actor *model.AdminUser, ip string) (int64, error) {
	if !s.cipher.Enabled() {
		return 0, stateConflictf("未配置 AUTHCENTER_KEY_ENC_KEY，无法启用加密")
	}
	enabled, err := s.store.GetSetting(ctx, model.SettingKeyEncryptionEnabled)
	if err != nil {
		return 0, err
	}
	if enabled == "1" {
		return 0, stateConflictf("密钥存储已处于加密模式")
	}
	pending, err := s.store.CountKeysWithoutHash(ctx)
	if err != nil {
		return 0, err
	}
	if pending > 0 {
		return 0, stateConflictf("存在 %d 行尚未回填 key_hash，请等待后台回填完成后再启用", pending)
	}

	var encrypted int64
	for i := 0; i < maxEncryptBatches; i++ {
		rows, err := s.store.ListPlainKeys(ctx, keyEncryptBatchSize)
		if err != nil {
			return encrypted, err
		}
		if len(rows) == 0 {
			break
		}
		for j := range rows {
			ct, err := s.cipher.Seal(rows[j].KeyValue)
			if err != nil {
				return encrypted, err
			}
			if err := s.store.EncryptRow(ctx, rows[j].ID, ct); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					continue // 并发下已被其它路径加密：幂等跳过
				}
				return encrypted, err
			}
			encrypted++
		}
		if len(rows) < keyEncryptBatchSize {
			break
		}
		select {
		case <-ctx.Done():
			return encrypted, ctx.Err()
		default:
		}
	}

	// 首次启用时写入主密钥自检密文（供后续启动 fail-fast 校验，03 §4.7 规则 3）。
	if err := EnsureKeyEncCheckBlob(ctx, s.store, s.cipher); err != nil {
		return encrypted, err
	}
	if err := s.store.SetSetting(ctx, model.SettingKeyEncryptionEnabled, "1"); err != nil {
		return encrypted, err
	}
	if err := s.store.SetSetting(ctx, model.SettingKeyEncryptionVersion, model.KeyEncVersion); err != nil {
		return encrypted, err
	}
	if err := s.store.SetSetting(ctx, model.SettingKeyEncryptedCount, strconv.FormatInt(encrypted, 10)); err != nil {
		return encrypted, err
	}
	// 审计：只记行数与模式，绝不含密钥内容（05 §2）。
	actorID, actorName := "", ""
	if actor != nil {
		actorID = strconv.FormatInt(actor.ID, 10)
		actorName = actor.Username
	}
	s.audit.Log(ctx, &model.AuditLog{
		EventType: model.EventSystemKeyEncryptionMigrated, ActorType: model.ActorTypeAdmin,
		ActorID: actorID, ActorName: actorName,
		TargetType: model.TargetTypeSystem,
		Result:     model.ResultSuccess,
		Detail: fmt.Sprintf(`{"to_encrypted":true,"rows":%d,"mode":"enable","version":%q}`,
			encrypted, model.KeyEncVersion),
		IP: ip, RequestID: requestIDFrom(ctx),
	})
	s.logger.Info("密钥存储加密已启用", "encrypted_rows", encrypted)
	return encrypted, nil
}

// ================= F-021 主密钥自检（need01 03 §4.7 规则 3） =================

// keyEncCheckPlain 主密钥自检用的固定已知明文（不是秘密，只是让自检密文可解）。
//
// 为什么需要它：03 §4.3 让密文的 AAD 绑定明文密钥本身，因此「用主密钥试解库中一条
// 业务密文」在数学上不可行（解密前拿不到明文 → 无法构造 AAD；密钥错与候选明文错
// 同样报 tag 校验失败，不可区分）。若不做真实校验，错误主密钥会导致服务「启动成功
// 但认证全断」，违背 §4.7 的 fail-fast 红线。
//
// 解法：把「已知明文」加密一次存入 settings.key_encryption_check（系统维护键），
// 启动时用它试解：解得开且内容相符 → 主密钥正确；否则写
// system.key_encryption_verify_failed 审计并拒绝启动。该密文不含任何业务密钥信息。
const keyEncCheckPlain = "authcenter:key-encryption:self-check:v1"

// SyncKeyEncCheckBlob 同步自检密文并（可选）校验主密钥，是启动自检的唯一入口。
//
// 语义（need01 03 §4.7 规则 3 + 一处必要的健壮性修正）：
//   - requireMatch=true（库中已有密文）：自检密文必须能用当前主密钥解开，否则返回
//     ErrCipherDecrypt（调用方拒绝启动，fail-fast）；
//   - requireMatch=false（库中尚无密文）：主密钥变更不应把服务锁死——此时自检密文与
//     业务数据无任何关联，直接按当前主密钥重写（自愈），避免「明文库 + 换过主密钥」
//     被误判为不可启动、以及自检密文残留旧密钥导致下次启用加密后无法启动。
//
// 自检密文只加密固定常量 keyEncCheckPlain，不含任何业务密钥信息。
func SyncKeyEncCheckBlob(ctx context.Context, st *store.Store, c Cipher, requireMatch bool) error {
	if !c.Enabled() {
		return nil
	}
	existing, err := st.GetSetting(ctx, model.SettingKeyEncryptionCheck)
	if err != nil {
		return err
	}
	if existing != "" {
		plain, err := c.Open(existing, keyEncCheckPlain)
		if err == nil && plain == keyEncCheckPlain {
			return nil // 主密钥与自检密文一致
		}
		if requireMatch {
			return ErrCipherDecrypt // 有密文却解不开 → 主密钥不匹配，拒绝启动
		}
		// 无密文：按当前主密钥重写（自愈），不阻断启动。
	}
	blob, err := c.Seal(keyEncCheckPlain)
	if err != nil {
		return err
	}
	return st.SetSetting(ctx, model.SettingKeyEncryptionCheck, blob)
}

// EnsureKeyEncCheckBlob 确保自检密文存在且与当前主密钥一致（启用加密时调用）。
// 此时若库中已有密文，不一致必须报错（由调用方转为启动/启用失败）。
func EnsureKeyEncCheckBlob(ctx context.Context, st *store.Store, c Cipher) error {
	return SyncKeyEncCheckBlob(ctx, st, c, true)
}

// stateConflictError 带可读原因的状态冲突错误：errors.Is(err, ErrStateConflict) 成立，
// 同时 err.Error() 就是给用户看的原因（handler 直接透出，见 05 §3）。
type stateConflictError struct{ msg string }

func (e *stateConflictError) Error() string { return e.msg }
func (e *stateConflictError) Unwrap() error { return ErrStateConflict }

// stateConflictf 构造带原因的状态冲突错误。
func stateConflictf(format string, args ...any) error {
	return &stateConflictError{msg: fmt.Sprintf(format, args...)}
}
