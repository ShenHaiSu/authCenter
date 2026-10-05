// Package store 数据访问层：database/sql 按实体拆分（文档 04 §1）。
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/model"
)

// ErrNotFound 资源不存在哨兵错误。
var ErrNotFound = errors.New("not found")

// ErrConflict 唯一约束/名称冲突哨兵错误（映射 409/20201，文档 05 §2）。
var ErrConflict = errors.New("conflict")

// Store 汇总各实体数据访问接口，供服务层注入。
type Store struct {
	db *sql.DB
	*AdminStore
	*SettingsStore
	*AuditStore
	*SessionStore
	*ProjectStore
	*ApiKeyStore
}

// New 基于已迁移的 *sql.DB 构造 Store。
func New(db *sql.DB) *Store {
	return &Store{
		db:            db,
		AdminStore:    &AdminStore{db: db},
		SettingsStore: &SettingsStore{db: db},
		AuditStore:    &AuditStore{db: db},
		SessionStore:  &SessionStore{db: db},
		ProjectStore:  &ProjectStore{db: db},
		ApiKeyStore:   &ApiKeyStore{db: db},
	}
}

// DB 暴露底层连接（迁移/备份等场景）。
func (s *Store) DB() *sql.DB { return s.db }

// isUniqueViolation 判断错误是否为 SQLite UNIQUE 约束冲突
// （modernc.org/sqlite 错误文本含 "UNIQUE constraint failed"）。
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// AdminStore admin_user 表访问（M1：Exists / Create / 校验用）。
type AdminStore struct {
	db *sql.DB
}

// AdminExists 判断用户名是否存在（幂等判断依据，username='admin'）。
func (s *AdminStore) AdminExists(ctx context.Context, username string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM admin_user WHERE username = ? LIMIT 1`, username).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("查询 admin 失败: %w", err)
	}
	return true, nil
}

// adminUserCols admin_user 查询列（F-020 新增 role/force_password_change/updated_at）。
const adminUserCols = `id, username, password_hash, role, is_active, force_password_change, created_at, updated_at, last_login_at, last_login_ip`

// normalizeRole 归一化角色：仅 owner 保留 owner，其余一律 admin（fail-safe 降权，
// 杜绝库中脏值导致越权，见 need01 02 §3.3）。
func normalizeRole(s string) string {
	if s == model.RoleOwner {
		return model.RoleOwner
	}
	return model.RoleAdmin
}

// scanAdminUser 扫描 admin_user 一行并归一化角色。
func scanAdminUser(sc interface{ Scan(...any) error }) (*model.AdminUser, error) {
	var u model.AdminUser
	var role string
	var isActive, forceChange int
	var createdAt string
	var updatedAt, lastLoginAt, lastLoginIP sql.NullString
	if err := sc.Scan(&u.ID, &u.Username, &u.PasswordHash, &role, &isActive, &forceChange,
		&createdAt, &updatedAt, &lastLoginAt, &lastLoginIP); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("扫描管理员失败: %w", err)
	}
	u.Role = normalizeRole(role)
	u.IsActive = isActive == 1
	u.ForcePasswordChange = forceChange == 1
	t, err := parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	u.CreatedAt = t
	if updatedAt.Valid {
		if t, err := parseTime(updatedAt.String); err != nil {
			return nil, err
		} else {
			u.UpdatedAt = &t
		}
	}
	if lastLoginAt.Valid {
		if t, err := parseTime(lastLoginAt.String); err != nil {
			return nil, err
		} else {
			u.LastLoginAt = &t
		}
	}
	if lastLoginIP.Valid {
		u.LastLoginIP = lastLoginIP.String
	}
	return &u, nil
}

// GetAdminByUsername 按用户名取管理员（含密码哈希，仅内部校验用）。
func (s *AdminStore) GetAdminByUsername(ctx context.Context, username string) (*model.AdminUser, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+adminUserCols+` FROM admin_user WHERE username = ?`, username)
	u, err := scanAdminUser(row)
	if err != nil {
		return nil, fmt.Errorf("查询 admin 失败: %w", err)
	}
	return u, nil
}

// GetAdminByID 按 id 取管理员（F-020：RequireAdmin 按会话归属取当前用户）。
func (s *AdminStore) GetAdminByID(ctx context.Context, id int64) (*model.AdminUser, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+adminUserCols+` FROM admin_user WHERE id = ?`, id)
	u, err := scanAdminUser(row)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// CreateAdmin 插入**启用状态**的初始 admin（引导路径，M1 起语义不变）：
// 恒写 is_active=1；role 缺省按 admin 归一化，EnsureAdmin 传入 owner。
func (s *AdminStore) CreateAdmin(ctx context.Context, u *model.AdminUser) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_user (username, password_hash, role, is_active, force_password_change, created_at)
		 VALUES (?, ?, ?, 1, ?, ?)`,
		u.Username, u.PasswordHash, normalizeRole(u.Role),
		boolToInt(u.ForcePasswordChange), database.FormatTime(u.CreatedAt)); err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return fmt.Errorf("创建 admin 失败: %w", err)
	}
	return nil
}

// CreateAdminUser 插入管理员并回填自增 id；用户名冲突返回 ErrConflict（映射 409/20201）。
func (s *AdminStore) CreateAdminUser(ctx context.Context, u *model.AdminUser) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_user (username, password_hash, role, is_active, force_password_change, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		u.Username, u.PasswordHash, normalizeRole(u.Role), boolToInt(u.IsActive),
		boolToInt(u.ForcePasswordChange), database.FormatTime(u.CreatedAt))
	if err != nil {
		if isUniqueViolation(err) {
			return 0, ErrConflict
		}
		return 0, fmt.Errorf("创建管理员失败: %w", err)
	}
	return res.LastInsertId()
}

// ListAdmins 分页查询管理员（按 id 升序），返回 (items, total)。
func (s *AdminStore) ListAdmins(ctx context.Context, page, size int) ([]model.AdminUser, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM admin_user`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计管理员失败: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+adminUserCols+` FROM admin_user ORDER BY id LIMIT ? OFFSET ?`, size, (page-1)*size)
	if err != nil {
		return nil, 0, fmt.Errorf("查询管理员列表失败: %w", err)
	}
	defer rows.Close()
	items := []model.AdminUser{}
	for rows.Next() {
		u, err := scanAdminUser(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, *u)
	}
	return items, total, rows.Err()
}

// AdminUpdate 管理员属性部分更新参数（nil = 该字段不变）。
type AdminUpdate struct {
	Role                *string
	IsActive            *bool
	ForcePasswordChange *bool
}

// UpdateAdminUser 更新管理员属性（role/is_active/force_password_change）+ updated_at；
// 目标不存在返回 ErrNotFound。
func (s *AdminStore) UpdateAdminUser(ctx context.Context, id int64, up AdminUpdate) error {
	sets := []string{"updated_at = ?"}
	args := []any{database.FormatTime(database.NowUTC())}
	if up.Role != nil {
		sets = append(sets, "role = ?")
		args = append(args, normalizeRole(*up.Role))
	}
	if up.IsActive != nil {
		sets = append(sets, "is_active = ?")
		args = append(args, boolToInt(*up.IsActive))
	}
	if up.ForcePasswordChange != nil {
		sets = append(sets, "force_password_change = ?")
		args = append(args, boolToInt(*up.ForcePasswordChange))
	}
	args = append(args, id)
	res, err := s.db.ExecContext(ctx,
		`UPDATE admin_user SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...)
	if err != nil {
		return fmt.Errorf("更新管理员失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeactivateGuarded 条件停用（F-020 R1 原子护栏）：仅当系统中还存在另一个启用的
// owner 时才把目标置为停用，返回受影响行数（0 = 被护栏拦下或目标不存在/本已停用）。
func (s *AdminStore) DeactivateGuarded(ctx context.Context, id int64) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE admin_user SET is_active = 0, updated_at = ?
		 WHERE id = ? AND role = ? AND is_active = 1
		   AND (SELECT count(*) FROM admin_user WHERE role = ? AND is_active = 1) > 1`,
		database.FormatTime(database.NowUTC()), id, model.RoleOwner, model.RoleOwner)
	if err != nil {
		return 0, fmt.Errorf("条件停用管理员失败: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// DemoteOwnerGuarded 条件降级（F-020 R1 原子护栏）：把启用的 owner 降为 newRole，
// 仅当系统中还存在另一个启用的 owner 时生效，返回受影响行数。
func (s *AdminStore) DemoteOwnerGuarded(ctx context.Context, id int64, newRole string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE admin_user SET role = ?, updated_at = ?
		 WHERE id = ? AND role = ? AND is_active = 1
		   AND (SELECT count(*) FROM admin_user WHERE role = ? AND is_active = 1) > 1`,
		normalizeRole(newRole), database.FormatTime(database.NowUTC()), id, model.RoleOwner, model.RoleOwner)
	if err != nil {
		return 0, fmt.Errorf("条件降级管理员失败: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// UpdateAdminPassword 更新管理员密码哈希并设置强制改密标记 + updated_at。
func (s *AdminStore) UpdateAdminPassword(ctx context.Context, id int64, hash string, forceChange bool) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE admin_user SET password_hash = ?, force_password_change = ?, updated_at = ? WHERE id = ?`,
		hash, boolToInt(forceChange), database.FormatTime(database.NowUTC()), id)
	if err != nil {
		return fmt.Errorf("更新管理员密码失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountActiveOwners 统计启用中的 owner 数量（R1：至少保留一个启用 owner）。
func (s *AdminStore) CountActiveOwners(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM admin_user WHERE role = ? AND is_active = 1`, model.RoleOwner).Scan(&n); err != nil {
		return 0, fmt.Errorf("统计启用 owner 失败: %w", err)
	}
	return n, nil
}

// ClearForcePasswordChange 清某用户的强制改密标记（本人改密成功后调用）。
func (s *AdminStore) ClearForcePasswordChange(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE admin_user SET force_password_change = 0 WHERE id = ?`, id); err != nil {
		return fmt.Errorf("清除强制改密标记失败: %w", err)
	}
	return nil
}

// SettingsStore settings 表访问。
type SettingsStore struct {
	db *sql.DB
}

// GetSetting 读取设置项；不存在返回 ("", nil)。
func (s *SettingsStore) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx,
		`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("读取设置 %s 失败: %w", key, err)
	}
	return value, nil
}

// SetSetting 插入或更新设置项（UPSERT）。
func (s *SettingsStore) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, database.FormatTime(database.NowUTC()))
	if err != nil {
		return fmt.Errorf("写入设置 %s 失败: %w", key, err)
	}
	return nil
}

// AuditStore audit_log 表访问（M1：写 system.* 事件；查询随 M2 补全）。
type AuditStore struct {
	db *sql.DB
}

// InsertAudit 写入一条审计记录（文档 03 §2.5）。
// EventTime 为零值时自动填充当前 UTC：event_time 是 NOT NULL 必填列，
// 存储入口兜底保证任何调用方漏设都不会产生 0001 年零值时间（修复 admin.login/logout 时间异常）。
func (s *AuditStore) InsertAudit(ctx context.Context, e *model.AuditLog) error {
	if e.EventTime.IsZero() {
		e.EventTime = database.NowUTC()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log
		   (event_time, event_type, actor_type, actor_id, actor_name,
		    target_type, target_id, target_name, result, detail, ip, request_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		database.FormatTime(e.EventTime), e.EventType, e.ActorType, e.ActorID, e.ActorName,
		e.TargetType, nullableInt64(e.TargetID), e.TargetName, e.Result, e.Detail, e.IP, e.RequestID)
	if err != nil {
		return fmt.Errorf("写入审计失败: %w", err)
	}
	return nil
}

func nullableInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("解析时间 %q 失败: %w", s, err)
	}
	return t, nil
}
