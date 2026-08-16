package service

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

// KeyValueLen 项目密钥长度（40 位 A-Za-z0-9，熵 238bit，文档 06 §2）。
const KeyValueLen = 40

// ApiKeyService 密钥业务（文档 04 §3.5：生成/编辑/轮换/吊销）。
type ApiKeyService struct {
	store     *store.Store
	audit     *AuditService
	projects  *ProjectService
	graceDays int // 轮换宽限期（settings.key_rotate_grace_days，默认 7）
}

// NewApiKeyService 构造 ApiKeyService。
func NewApiKeyService(st *store.Store, audit *AuditService, projects *ProjectService, graceDays int) *ApiKeyService {
	if graceDays <= 0 {
		graceDays = 7
	}
	return &ApiKeyService{store: st, audit: audit, projects: projects, graceDays: graceDays}
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
	now := timeNowUTC()
	k := &model.APIKey{
		ProjectID:   projectID,
		Name:        name,
		KeyValue:    plain,
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
	now := timeNowUTC()
	newKey := &model.APIKey{
		ProjectID:   old.ProjectID,
		Name:        old.Name,
		KeyValue:    plain,
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
