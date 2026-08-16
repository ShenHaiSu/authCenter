// Package store 数据访问层：database/sql 按实体拆分（文档 04 §1）。
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/model"
)

// ErrNotFound 资源不存在哨兵错误。
var ErrNotFound = errors.New("not found")

// Store 汇总各实体数据访问接口，供服务层注入（M1 最小集）。
type Store struct {
	db *sql.DB
	*AdminStore
	*SettingsStore
	*AuditStore
}

// New 基于已迁移的 *sql.DB 构造 Store。
func New(db *sql.DB) *Store {
	return &Store{
		db:            db,
		AdminStore:    &AdminStore{db: db},
		SettingsStore: &SettingsStore{db: db},
		AuditStore:    &AuditStore{db: db},
	}
}

// DB 暴露底层连接（迁移/备份等场景）。
func (s *Store) DB() *sql.DB { return s.db }

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

// GetAdminByUsername 按用户名取管理员（含密码哈希，仅内部校验用）。
func (s *AdminStore) GetAdminByUsername(ctx context.Context, username string) (*model.AdminUser, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, is_active, created_at, last_login_at, last_login_ip
		 FROM admin_user WHERE username = ?`, username)
	var u model.AdminUser
	var isActive int
	var createdAt string
	var lastLoginAt sql.NullString
	var lastLoginIP sql.NullString
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &isActive, &createdAt, &lastLoginAt, &lastLoginIP); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("查询 admin 失败: %w", err)
	}
	u.IsActive = isActive == 1
	var err error
	if u.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
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

// CreateAdmin 插入管理员（M1：初始 admin）。
func (s *AdminStore) CreateAdmin(ctx context.Context, u *model.AdminUser) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_user (username, password_hash, is_active, created_at)
		 VALUES (?, ?, 1, ?)`,
		u.Username, u.PasswordHash, database.FormatTime(u.CreatedAt))
	if err != nil {
		return fmt.Errorf("创建 admin 失败: %w", err)
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
func (s *AuditStore) InsertAudit(ctx context.Context, e *model.AuditLog) error {
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
