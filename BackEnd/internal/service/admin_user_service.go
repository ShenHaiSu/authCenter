// admin_user_service.go — F-020 多管理员与 RBAC 的业务规则（need01 02 §4）。
//
// 承载四条护栏：
//
//	R1 至少保留一个启用 owner（前置 CountActiveOwners 校验 + 条件 UPDATE 原子兜底）
//	R2 不能对自己执行停用/降级/重置
//	R3 停用即吊销该用户全部会话
//	R4 用户名规则 ^[a-zA-Z0-9_.-]{3,32}$ 与唯一冲突
package service

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

// adminUsernamePattern 用户名规则（R4）：3-32 位字母、数字、下划线、点、短横。
var adminUsernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,32}$`)

// errLastOwnerMessage R1 的统一提示（前端与测试按此文案核对）。
const errLastOwnerMessage = "系统必须至少保留一个启用的超级管理员"

// errSelfMessage R2 的统一提示。
const errSelfMessage = "不能对自己执行此操作"

// AdminUserService 管理员账号管理（仅 owner 可调用，由 httpapi 的 requireOwner 保证）。
type AdminUserService struct {
	store  *store.Store
	audit  *AuditService
	logger *slog.Logger
}

// NewAdminUserService 构造 AdminUserService。
func NewAdminUserService(st *store.Store, audit *AuditService, logger *slog.Logger) *AdminUserService {
	if logger == nil {
		logger = slog.Default()
	}
	return &AdminUserService{store: st, audit: audit, logger: logger}
}

// List 分页列出管理员。
func (s *AdminUserService) List(ctx context.Context, page, size int) ([]model.AdminUser, int, error) {
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 100 {
		size = 20
	}
	return s.store.ListAdmins(ctx, page, size)
}

// Get 按 id 取单个管理员（更新后回读用）；不存在返回 store.ErrNotFound。
func (s *AdminUserService) Get(ctx context.Context, id int64) (*model.AdminUser, error) {
	return s.store.GetAdminByID(ctx, id)
}

// Create 新增管理员：校验用户名（R4）与密码强度 → argon2id 哈希入库 → 写 admin.create 审计。
// 初始密码由 owner 在管理端输入（不走 auth.log / 控制台通道——那只是启动初始化的特例）。
func (s *AdminUserService) Create(ctx context.Context, actor *model.AdminUser, username, password, role string, forceChange bool, ip string) (*model.AdminUser, error) {
	username = strings.TrimSpace(username)
	if !adminUsernamePattern.MatchString(username) {
		return nil, fmt.Errorf("%w: 用户名必须是 3-32 位字母、数字、下划线、点或短横线", ErrInvalidParameter)
	}
	if err := validatePasswordStrength(password); err != nil {
		return nil, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("哈希密码失败: %w", err)
	}
	u := &model.AdminUser{
		Username:            username,
		PasswordHash:        hash,
		Role:                normalizeRoleInput(role),
		IsActive:            true,
		ForcePasswordChange: forceChange,
		CreatedAt:           timeNowUTC(),
	}
	id, err := s.store.CreateAdminUser(ctx, u)
	if err != nil {
		return nil, err // store.ErrConflict → 409/20201（R4）
	}
	u.ID = id

	s.writeAudit(ctx, actor, model.EventAdminCreate, u,
		fmt.Sprintf(`{"username":%q,"role":%q,"force_password_change":%t}`, u.Username, u.Role, forceChange), ip)
	return u, nil
}

// SetActive 启用/停用管理员（R3 停用即吊销全部会话；R2 拒绝操作自己；R1 保护最后一个 owner）。
// 幂等：目标已是目标状态时直接返回，不重复吊销会话、不重复审计。
func (s *AdminUserService) SetActive(ctx context.Context, actor *model.AdminUser, id int64, isActive bool, ip string) error {
	target, err := s.mustGetNotSelf(ctx, actor, id)
	if err != nil {
		return err
	}
	if target.IsActive == isActive {
		return nil
	}
	if !isActive && target.Role == model.RoleOwner {
		// R1：停用启用的 owner 前先计数（给出可读报错），
		// 再由条件 UPDATE 做原子兜底（防并发窗口）。
		if err := s.guardLastOwner(ctx); err != nil {
			return err
		}
		affected, err := s.store.DeactivateGuarded(ctx, id)
		if err != nil {
			return err
		}
		if affected == 0 {
			return s.resolveZeroRows(ctx, id)
		}
	} else if err := s.store.UpdateAdminUser(ctx, id, store.AdminUpdate{IsActive: &isActive}); err != nil {
		return err
	}

	target.IsActive = isActive
	if isActive {
		s.writeAudit(ctx, actor, model.EventAdminEnable, target,
			fmt.Sprintf(`{"username":%q}`, target.Username), ip)
		return nil
	}
	// R3：停用即刻失效其全部会话（不只拦当前请求）。
	revoked, err := s.countSessions(ctx, id)
	if err != nil {
		return err
	}
	if err := s.store.DeleteSessionsByUser(ctx, id); err != nil {
		return err
	}
	s.writeAudit(ctx, actor, model.EventAdminDisable, target,
		fmt.Sprintf(`{"username":%q,"sessions_revoked":%d}`, target.Username, revoked), ip)
	return nil
}

// SetRole 调整角色（R2 拒绝操作自己；R1 拒绝把最后一个启用 owner 降级）。
func (s *AdminUserService) SetRole(ctx context.Context, actor *model.AdminUser, id int64, role, ip string) error {
	role = normalizeRoleInput(role)
	target, err := s.mustGetNotSelf(ctx, actor, id)
	if err != nil {
		return err
	}
	if target.Role == role {
		return nil
	}
	if target.Role == model.RoleOwner && target.IsActive && role != model.RoleOwner {
		// R1：启用 owner → 非 owner 的降级会使 owner 归零则拒绝。
		if err := s.guardLastOwner(ctx); err != nil {
			return err
		}
		affected, err := s.store.DemoteOwnerGuarded(ctx, id, role)
		if err != nil {
			return err
		}
		if affected == 0 {
			return s.resolveZeroRows(ctx, id)
		}
	} else if err := s.store.UpdateAdminUser(ctx, id, store.AdminUpdate{Role: &role}); err != nil {
		return err
	}

	from := target.Role
	target.Role = role
	s.writeAudit(ctx, actor, model.EventAdminRoleChange, target,
		fmt.Sprintf(`{"username":%q,"from_role":%q,"to_role":%q}`, target.Username, from, role), ip)
	return nil
}

// SetForcePasswordChange 要求/取消目标用户下次登录强制改密（R2 同样拒绝操作自己）。
func (s *AdminUserService) SetForcePasswordChange(ctx context.Context, actor *model.AdminUser, id int64, force bool, ip string) error {
	target, err := s.mustGetNotSelf(ctx, actor, id)
	if err != nil {
		return err
	}
	if target.ForcePasswordChange == force {
		return nil
	}
	if err := s.store.UpdateAdminUser(ctx, id, store.AdminUpdate{ForcePasswordChange: &force}); err != nil {
		return err
	}
	target.ForcePasswordChange = force
	s.writeAudit(ctx, actor, model.EventAdminUpdate, target,
		fmt.Sprintf(`{"username":%q,"fields":["force_password_change"],"force_password_change":%t}`, target.Username, force), ip)
	return nil
}

// ResetPassword owner 重置他人密码：同一强度校验 → 写哈希 → 吊销目标全部会话 →
// 写 admin.password_reset 审计。R2 拒绝重置自己（否则可绕过旧密码校验与强制改密流程）。
func (s *AdminUserService) ResetPassword(ctx context.Context, actor *model.AdminUser, id int64, newPassword string, forceChange bool, ip string) error {
	target, err := s.mustGetNotSelf(ctx, actor, id)
	if err != nil {
		return err
	}
	if err := validatePasswordStrength(newPassword); err != nil {
		return err
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("哈希新密码失败: %w", err)
	}
	if err := s.store.UpdateAdminPassword(ctx, id, hash, forceChange); err != nil {
		return err
	}
	if err := s.store.DeleteSessionsByUser(ctx, id); err != nil {
		return err
	}
	s.writeAudit(ctx, actor, model.EventAdminPasswordReset, target,
		fmt.Sprintf(`{"username":%q,"force_change":%t}`, target.Username, forceChange), ip)
	return nil
}

// guardLastOwner R1 前置校验：启用 owner 数必须 > 1。
func (s *AdminUserService) guardLastOwner(ctx context.Context) error {
	n, err := s.store.CountActiveOwners(ctx)
	if err != nil {
		return err
	}
	if n <= 1 {
		return fmt.Errorf("%w: %s", ErrStateConflict, errLastOwnerMessage)
	}
	return nil
}

// resolveZeroRows 条件 UPDATE 影响 0 行时区分「目标不存在」（404）与「被 R1 拦下」（409）。
func (s *AdminUserService) resolveZeroRows(ctx context.Context, id int64) error {
	if _, err := s.store.GetAdminByID(ctx, id); err != nil {
		return err // store.ErrNotFound → 404/20200
	}
	return fmt.Errorf("%w: %s", ErrStateConflict, errLastOwnerMessage)
}

// mustGetNotSelf 取目标用户并执行 R2（不能对自己执行此操作）。
func (s *AdminUserService) mustGetNotSelf(ctx context.Context, actor *model.AdminUser, id int64) (*model.AdminUser, error) {
	if actor != nil && actor.ID == id {
		return nil, fmt.Errorf("%w: %s", ErrStateConflict, errSelfMessage)
	}
	return s.store.GetAdminByID(ctx, id)
}

// countSessions 统计某用户当前会话数（供审计 detail 的 sessions_revoked）。
func (s *AdminUserService) countSessions(ctx context.Context, id int64) (int, error) {
	var n int
	if err := s.store.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM admin_session WHERE admin_user_id = ?`, id).Scan(&n); err != nil {
		return 0, fmt.Errorf("统计用户会话失败: %w", err)
	}
	return n, nil
}

// writeAudit 写管理员管理审计（actor=操作者本人，target=被操作账号；detail 禁含密码明文）。
func (s *AdminUserService) writeAudit(ctx context.Context, actor *model.AdminUser, event string, target *model.AdminUser, detail, ip string) {
	actorID, actorName := "", ""
	if actor != nil {
		actorID = strconv.FormatInt(actor.ID, 10)
		actorName = actor.Username
	}
	e := &model.AuditLog{
		EventType:  event,
		ActorType:  model.ActorTypeAdmin,
		ActorID:    actorID,
		ActorName:  actorName,
		TargetType: model.TargetTypeAdmin,
		Result:     model.ResultSuccess,
		Detail:     detail,
		IP:         ip,
		RequestID:  requestIDFrom(ctx),
	}
	if target != nil {
		e.TargetID = target.ID
		e.TargetName = target.Username
	}
	if s.audit != nil {
		s.audit.Log(ctx, e)
		return
	}
	if err := s.store.InsertAudit(ctx, e); err != nil {
		s.logger.Error("写入审计失败", "err", err, "event_type", event)
	}
}

// normalizeRoleInput 归一化入参角色：仅精确 owner 为 owner，其余（含空串与脏值）为 admin。
func normalizeRoleInput(s string) string {
	s = strings.TrimSpace(s)
	if s == model.RoleOwner {
		return model.RoleOwner
	}
	return model.RoleAdmin
}
