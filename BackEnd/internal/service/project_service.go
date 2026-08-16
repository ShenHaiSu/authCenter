package service

import (
	"context"
	"strconv"
	"strings"

	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

// ProjectService 项目业务（文档 04 §1：project 管理；审计事件见 05 §5）。
type ProjectService struct {
	store *store.Store
	audit *AuditService
}

// NewProjectService 构造 ProjectService。
func NewProjectService(st *store.Store, audit *AuditService) *ProjectService {
	return &ProjectService{store: st, audit: audit}
}

// Create 创建项目；名称冲突返回 ErrConflict（409/20201）。
func (s *ProjectService) Create(ctx context.Context, actor *model.AdminUser, name, description, currentVersion string, minVersion *string, ip string) (*model.Project, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrInvalidParameter
	}
	now := timeNowUTC()
	p := &model.Project{
		Name:           name,
		Description:    description,
		CurrentVersion: currentVersion,
		MinVersion:     minVersion,
		IsActive:       true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	id, err := s.store.CreateProject(ctx, p)
	if err != nil {
		return nil, err
	}
	p.ID = id
	s.audit.Log(ctx, &model.AuditLog{
		EventType: model.EventProjectCreate, ActorType: model.ActorTypeAdmin,
		ActorID: strconv.FormatInt(actor.ID, 10), ActorName: actor.Username,
		TargetType: model.TargetTypeProject, TargetID: id, TargetName: p.Name,
		Result: model.ResultSuccess, IP: ip, RequestID: requestIDFrom(ctx),
	})
	return p, nil
}

// Get 按 id 取项目（含密钥列表由 httpapi 层二次查询）。
func (s *ProjectService) Get(ctx context.Context, id int64) (*model.Project, error) {
	return s.store.GetProjectByID(ctx, id)
}

// List 分页查询项目列表（q 名称模糊、active 状态筛选）。
func (s *ProjectService) List(ctx context.Context, q string, active *bool, page, size int) ([]model.Project, int, error) {
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 100 {
		size = 20
	}
	return s.store.ListProjects(ctx, q, active, page, size)
}

// Update 更新项目；is_active 变化时补写 project.enable/project.disable 审计（05 §5）。
func (s *ProjectService) Update(ctx context.Context, actor *model.AdminUser, id int64, description, currentVersion string, minVersion *string, isActive bool, ip string) (*model.Project, error) {
	old, err := s.store.GetProjectByID(ctx, id)
	if err != nil {
		return nil, err
	}
	p := &model.Project{
		ID:             old.ID,
		Name:           old.Name,
		Description:    description,
		CurrentVersion: currentVersion,
		MinVersion:     minVersion,
		IsActive:       isActive,
		UpdatedAt:      timeNowUTC(),
	}
	if err := s.store.UpdateProject(ctx, p); err != nil {
		return nil, err
	}

	s.audit.Log(ctx, &model.AuditLog{
		EventType: model.EventProjectUpdate, ActorType: model.ActorTypeAdmin,
		ActorID: strconv.FormatInt(actor.ID, 10), ActorName: actor.Username,
		TargetType: model.TargetTypeProject, TargetID: id, TargetName: old.Name,
		Result: model.ResultSuccess, IP: ip, RequestID: requestIDFrom(ctx),
	})
	if isActive != old.IsActive {
		ev := model.EventProjectDisable
		if isActive {
			ev = model.EventProjectEnable
		}
		s.audit.Log(ctx, &model.AuditLog{
			EventType: ev, ActorType: model.ActorTypeAdmin,
			ActorID: strconv.FormatInt(actor.ID, 10), ActorName: actor.Username,
			TargetType: model.TargetTypeProject, TargetID: id, TargetName: old.Name,
			Result: model.ResultSuccess, IP: ip, RequestID: requestIDFrom(ctx),
		})
	}
	p.CreatedAt = old.CreatedAt
	return p, nil
}

// Delete 删除项目（级联删密钥，文档 05 §4.2 二次确认由前端保证）。
func (s *ProjectService) Delete(ctx context.Context, actor *model.AdminUser, id int64, ip string) error {
	old, err := s.store.GetProjectByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.store.DeleteProject(ctx, id); err != nil {
		return err
	}
	s.audit.Log(ctx, &model.AuditLog{
		EventType: model.EventProjectDelete, ActorType: model.ActorTypeAdmin,
		ActorID: strconv.FormatInt(actor.ID, 10), ActorName: actor.Username,
		TargetType: model.TargetTypeProject, TargetID: id, TargetName: old.Name,
		Result: model.ResultSuccess, IP: ip, RequestID: requestIDFrom(ctx),
	})
	return nil
}

// CheckProjectActive 检查项目存在且启用（密钥创建前置校验，文档 02 §7.2）。
// 项目不存在返回 store.ErrNotFound；停用返回业务错误（409/20202 语义）。
func (s *ProjectService) CheckProjectActive(ctx context.Context, projectID int64) error {
	p, err := s.store.GetProjectByID(ctx, projectID)
	if err != nil {
		return err
	}
	if !p.IsActive {
		return ErrProjectDisabled
	}
	return nil
}
