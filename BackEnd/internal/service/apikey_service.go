package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

// KeyValueLen 项目密钥长度（40 位 A-Za-z0-9，熵 238bit，文档 06 §2）。
const KeyValueLen = 40

// hashFillTimeout 自愈回填单行的超时（不阻塞认证响应，need01 03 §4.4）。
const hashFillTimeout = 5 * time.Second

// ApiKeyService 密钥业务（文档 04 §3.5：生成/编辑/轮换/吊销；F-021：加解密 + 认证取密钥）。
type ApiKeyService struct {
	store     *store.Store
	audit     *AuditService
	projects  *ProjectService
	graceDays int    // 轮换宽限期（settings.key_rotate_grace_days，默认 7）
	cipher    Cipher // F-021：明文模式为 PlainCipher（透传）
	logger    *slog.Logger

	// key_hash 回填状态进程内缓存（need01 03 §4.4：避免每次认证都查库）。
	bfState  atomic.Value // string
	bfLoaded atomic.Bool
}

// NewApiKeyService 构造 ApiKeyService（F-021：新增 cipher 依赖，nil 视为明文模式）。
func NewApiKeyService(st *store.Store, audit *AuditService, projects *ProjectService, graceDays int, c Cipher) *ApiKeyService {
	if graceDays <= 0 {
		graceDays = 7
	}
	if c == nil {
		c = PlainCipher{}
	}
	return &ApiKeyService{store: st, audit: audit, projects: projects, graceDays: graceDays, cipher: c, logger: slog.Default()}
}

// CipherEnabled 报告当前进程是否持有可用主密钥（GCM 模式）。
func (s *ApiKeyService) CipherEnabled() bool { return s.cipher.Enabled() }

// InvalidateBackfillCache 失效 key_hash 回填状态缓存（settings 写路径与回填 job 调用）。
func (s *ApiKeyService) InvalidateBackfillCache() { s.bfLoaded.Store(false) }

// storeKey 计算落库形态：启用加密时返回 (密文, KeyEncGCM)，否则 (明文, KeyEncPlain)。
func (s *ApiKeyService) storeKey(plain string) (string, int, error) {
	if !s.cipher.Enabled() {
		return plain, model.KeyEncPlain, nil
	}
	stored, err := s.cipher.Seal(plain)
	if err != nil {
		return "", 0, err
	}
	return stored, model.KeyEncGCM, nil
}

// Create 生成密钥：40 位随机明文仅本次返回（05 §4.3）。
func (s *ApiKeyService) Create(ctx context.Context, actor *model.AdminUser, projectID int64, name string, expiresAt *time.Time, fingerprint *string, ip string) (*model.APIKey, string, error) {
	if err := s.projects.CheckProjectActive(ctx, projectID); err != nil {
		return nil, "", err
	}
	plain, err := RandomString(KeyValueLen)
	if err != nil {
		return nil, "", err
	}
	stored, enc, err := s.storeKey(plain)
	if err != nil {
		return nil, "", err
	}
	now := timeNowUTC()
	k := &model.APIKey{
		ProjectID:   projectID,
		Name:        name,
		KeyValue:    stored,
		KeyValueEnc: enc,
		KeyHash:     HashKey(plain),
		Fingerprint: fingerprint,
		ExpiresAt:   expiresAt,
		IsActive:    true,
		CreatedBy:   actor.Username,
		CreatedAt:   now,
	}
	id, err := s.store.CreateKey(ctx, k)
	if err != nil {
		return nil, "", err
	}
	k.ID = id
	s.audit.Log(ctx, &model.AuditLog{
		EventType: model.EventKeyCreate, ActorType: model.ActorTypeAdmin,
		ActorID: strconv.FormatInt(actor.ID, 10), ActorName: actor.Username,
		TargetType: model.TargetTypeAPIKey, TargetID: id, TargetName: name,
		Result: model.ResultSuccess, IP: ip, RequestID: requestIDFrom(ctx),
	})
	return k, plain, nil
}

// List 分页查询某项目密钥（列表永不返回 key_value，model json:"-" 兜底）。
func (s *ApiKeyService) List(ctx context.Context, projectID int64, active *bool, page, size int) ([]model.APIKey, int, error) {
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 100 {
		size = 20
	}
	return s.store.ListKeysByProject(ctx, projectID, active, page, size)
}

// Get 按 id 取单个密钥（详情/编辑前置查询；不返回 key_value）。
func (s *ApiKeyService) Get(ctx context.Context, id int64) (*model.APIKey, error) {
	return s.store.GetKeyByID(ctx, id)
}

// Update 编辑密钥（备注/过期/指纹/启停）；is_active 变化补写 key.enable/key.disable 审计。
func (s *ApiKeyService) Update(ctx context.Context, actor *model.AdminUser, id int64, name string, expiresAt *time.Time, fingerprint *string, isActive bool, ip string) (*model.APIKey, error) {
	old, err := s.store.GetKeyByID(ctx, id)
	if err != nil {
		return nil, err
	}
	// 基于旧记录生成全量更新（响应字段完整，05 §4.3）。
	k := *old
	k.Name = name
	k.ExpiresAt = expiresAt
	k.Fingerprint = fingerprint
	k.IsActive = isActive
	if err := s.store.UpdateKey(ctx, &k); err != nil {
		return nil, err
	}
	s.audit.Log(ctx, &model.AuditLog{
		EventType: model.EventKeyUpdate, ActorType: model.ActorTypeAdmin,
		ActorID: strconv.FormatInt(actor.ID, 10), ActorName: actor.Username,
		TargetType: model.TargetTypeAPIKey, TargetID: id, TargetName: name,
		Result: model.ResultSuccess, IP: ip, RequestID: requestIDFrom(ctx),
	})
	if isActive != old.IsActive {
		ev := model.EventKeyDisable
		if isActive {
			ev = model.EventKeyEnable
		}
		s.audit.Log(ctx, &model.AuditLog{
			EventType: ev, ActorType: model.ActorTypeAdmin,
			ActorID: strconv.FormatInt(actor.ID, 10), ActorName: actor.Username,
			TargetType: model.TargetTypeAPIKey, TargetID: id, TargetName: name,
			Result: model.ResultSuccess, IP: ip, RequestID: requestIDFrom(ctx),
		})
	}
	return &k, nil
}

// Rotate 轮换密钥（文档 04 §3.5）：
//   - 新密钥立即生效（继承旧密钥指纹，便于灰度切换）；
//   - 旧密钥进入宽限期：expires_at = min(原 expires_at, now+graceDays)，
//     宽限期内仍可认证，期满自动过期失效。
//
// 返回 (新密钥, 新密钥明文, 旧密钥宽限期截止, err)。
func (s *ApiKeyService) Rotate(ctx context.Context, actor *model.AdminUser, id int64, ip string) (*model.APIKey, string, *time.Time, error) {
	old, err := s.store.GetKeyByID(ctx, id)
	if err != nil {
		return nil, "", nil, err
	}

	plain, err := RandomString(KeyValueLen)
	if err != nil {
		return nil, "", nil, err
	}
	stored, enc, err := s.storeKey(plain)
	if err != nil {
		return nil, "", nil, err
	}
	now := timeNowUTC()
	newKey := &model.APIKey{
		ProjectID:   old.ProjectID,
		Name:        old.Name,
		KeyValue:    stored,
		KeyValueEnc: enc,
		KeyHash:     HashKey(plain),
		Fingerprint: old.Fingerprint, // 继承指纹，保证切换期内可用
		IsActive:    true,
		CreatedBy:   actor.Username,
		CreatedAt:   now,
	}
	newID, err := s.store.CreateKey(ctx, newKey)
	if err != nil {
		return nil, "", nil, err
	}
	newKey.ID = newID

	// 旧密钥宽限期：取 min(原 expires_at, now+graceDays)。
	graceUntil := now.Add(time.Duration(s.graceDays) * 24 * time.Hour)
	if old.ExpiresAt != nil && old.ExpiresAt.Before(graceUntil) {
		graceUntil = *old.ExpiresAt
	}
	// 保留旧密钥的备注与指纹，仅收紧过期时间（进入宽限期）。
	upd := &model.APIKey{
		ID:          old.ID,
		Name:        old.Name,
		Fingerprint: old.Fingerprint,
		ExpiresAt:   &graceUntil,
		IsActive:    true,
	}
	if err := s.store.UpdateKey(ctx, upd); err != nil {
		return nil, "", nil, err
	}

	s.audit.Log(ctx, &model.AuditLog{
		EventType: model.EventKeyRotate, ActorType: model.ActorTypeAdmin,
		ActorID: strconv.FormatInt(actor.ID, 10), ActorName: actor.Username,
		TargetType: model.TargetTypeAPIKey, TargetID: id, TargetName: old.Name,
		Result: model.ResultSuccess,
		Detail: fmt.Sprintf(`{"new_key_id":%d,"old_key_grace_until":%q}`, newID, graceUntil.Format(time.RFC3339)),
		IP:     ip, RequestID: requestIDFrom(ctx),
	})
	return newKey, plain, &graceUntil, nil
}

// Delete 吊销密钥：立即失效（软删 is_active=0，文档 04 §3.5；可恢复 P2）。
func (s *ApiKeyService) Delete(ctx context.Context, actor *model.AdminUser, id int64, ip string) error {
	old, err := s.store.GetKeyByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.store.DeleteKey(ctx, id); err != nil {
		return err
	}
	s.audit.Log(ctx, &model.AuditLog{
		EventType: model.EventKeyDelete, ActorType: model.ActorTypeAdmin,
		ActorID: strconv.FormatInt(actor.ID, 10), ActorName: actor.Username,
		TargetType: model.TargetTypeAPIKey, TargetID: id, TargetName: old.Name,
		Result: model.ResultSuccess, IP: ip, RequestID: requestIDFrom(ctx),
	})
	return nil
}

// ================= F-021 认证取密钥（need01 03 §4.4） =================

// KeyForAuth 认证取密钥：先按 hash 索引定位记录，再用提交密钥完成解密/明文比对。
// 语义与旧 GetKeyByValue 完全一致：不存在 → store.ErrNotFound。
//
// 兼容分支（仅当 settings.key_hash_backfill_state != "done" 时启用）：
// 回填未完成期间仍可能有存量行的 key_hash 为 NULL，此时回落一次明文等值查询，
// 命中后顺手把该行 key_hash 补上（自愈式回填）；回填完成后自动失效。
func (s *ApiKeyService) KeyForAuth(ctx context.Context, plainKey string) (*model.APIKey, error) {
	k, err := s.store.GetKeyByHash(ctx, HashKey(plainKey))
	if err != nil && errors.Is(err, store.ErrNotFound) && s.backfillPending(ctx) {
		if k, err = s.store.GetKeyByValuePlain(ctx, plainKey); err == nil {
			go s.tryFillHashAsync(ctx, k.ID, plainKey) // 异步补 hash，不阻塞认证响应
		}
	}
	if err != nil {
		return nil, err // ErrNotFound → auth_service 记 key_not_found，对外 10004，语义不变
	}
	if _, err := ResolvePlain(k, s.cipher, plainKey); err != nil {
		// 密文/哈希不自洽或密钥不匹配 → 内部原因，对外仍按 key_not_found（05 §3 红线）。
		s.logger.Error("密钥解密失败", "key_id", k.ID, "err", err)
		s.audit.Log(ctx, &model.AuditLog{
			EventType: model.EventAuthAuthenticateFailed, ActorType: model.ActorTypeClient,
			TargetType: model.TargetTypeAPIKey, TargetID: k.ID,
			Result:    model.ResultFailure,
			Detail:    fmt.Sprintf(`{"reason":"decrypt_failed","key_id":%d}`, k.ID),
			RequestID: requestIDFrom(ctx),
		})
		return nil, store.ErrNotFound
	}
	return k, nil
}

// backfillPending 判断 key_hash 回填是否未完成（进程内缓存，变更时由写路径失效）。
// 读库失败时保守返回 true（走兼容分支，绝不误判为已完成而丢认证）。
func (s *ApiKeyService) backfillPending(ctx context.Context) bool {
	if s.bfLoaded.Load() {
		v, _ := s.bfState.Load().(string)
		return v != model.BackfillDone
	}
	state, err := s.store.GetSetting(ctx, model.SettingKeyHashBackfillState)
	if err != nil {
		s.logger.Warn("读取 key_hash 回填状态失败，按未完成处理", "err", err)
		return true
	}
	s.bfState.Store(state)
	s.bfLoaded.Store(true)
	return state != model.BackfillDone
}

// tryFillHashAsync 自愈式补写单行 key_hash；失败仅记日志（不阻塞认证）。
// 用 context.WithoutCancel 避免请求 ctx 取消导致补写丢失。
func (s *ApiKeyService) tryFillHashAsync(ctx context.Context, id int64, plain string) {
	fillCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), hashFillTimeout)
	defer cancel()
	if err := s.store.UpdateKeyHash(fillCtx, id, HashKey(plain)); err != nil {
		s.logger.Warn("自愈回填 key_hash 失败", "key_id", id, "err", err)
	}
}
