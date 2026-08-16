package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/model"
)

// SessionStore admin_session 表访问（文档 03 §2.2 / 04 §3.4）。
type SessionStore struct {
	db *sql.DB
}

// CreateSession 插入会话（库中只存 token 的 SHA-256）。
func (s *SessionStore) CreateSession(ctx context.Context, sess *model.AdminSession) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_session (token_hash, admin_user_id, expires_at, ip, user_agent, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sess.TokenHash, sess.AdminUserID, database.FormatTime(sess.ExpiresAt),
		nullableString(sess.IP), nullableString(sess.UserAgent), database.FormatTime(sess.CreatedAt))
	if err != nil {
		return fmt.Errorf("创建会话失败: %w", err)
	}
	return nil
}

// GetSessionByTokenHash 按 token 哈希取会话（未过期）；不存在返回 ErrNotFound。
func (s *SessionStore) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*model.AdminSession, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, token_hash, admin_user_id, expires_at, ip, user_agent, created_at
		 FROM admin_session WHERE token_hash = ?`, tokenHash)
	var sess model.AdminSession
	var expiresAt, createdAt string
	var ip, ua sql.NullString
	if err := row.Scan(&sess.ID, &sess.TokenHash, &sess.AdminUserID, &expiresAt, &ip, &ua, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("查询会话失败: %w", err)
	}
	var err error
	if sess.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return nil, err
	}
	if sess.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if ip.Valid {
		sess.IP = ip.String
	}
	if ua.Valid {
		sess.UserAgent = ua.String
	}
	return &sess, nil
}

// DeleteSession 删除单个会话（登出）。
func (s *SessionStore) DeleteSession(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM admin_session WHERE id = ?`, id); err != nil {
		return fmt.Errorf("删除会话失败: %w", err)
	}
	return nil
}

// DeleteSessionsByUser 删除某用户全部会话（改密后全部失效）。
func (s *SessionStore) DeleteSessionsByUser(ctx context.Context, adminUserID int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM admin_session WHERE admin_user_id = ?`, adminUserID); err != nil {
		return fmt.Errorf("删除用户会话失败: %w", err)
	}
	return nil
}

// CleanupExpired 惰性清理过期会话（文档 03 §7：登录/查询时顺带清理）。
func (s *SessionStore) CleanupExpired(ctx context.Context, now string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM admin_session WHERE expires_at < ?`, now); err != nil {
		return fmt.Errorf("清理过期会话失败: %w", err)
	}
	return nil
}

func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
}
