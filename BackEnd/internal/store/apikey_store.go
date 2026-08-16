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

// ApiKeyStore api_key 表访问（文档 03 §2.4）。
type ApiKeyStore struct {
	db *sql.DB
}

// CreateKey 插入密钥。
func (s *ApiKeyStore) CreateKey(ctx context.Context, k *model.APIKey) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO api_key (project_id, name, key_value, fingerprint, expires_at, is_active, created_by, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		k.ProjectID, k.Name, k.KeyValue, nullablePtrString(k.Fingerprint),
		nullableTime(k.ExpiresAt), boolToInt(k.IsActive), k.CreatedBy, database.FormatTime(k.CreatedAt))
	if err != nil {
		return 0, fmt.Errorf("创建密钥失败: %w", err)
	}
	return res.LastInsertId()
}

// GetKeyByID 按 id 取密钥；不存在返回 ErrNotFound。
func (s *ApiKeyStore) GetKeyByID(ctx context.Context, id int64) (*model.APIKey, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, project_id, name, key_value, fingerprint, expires_at,
		        last_used_at, last_used_ip, is_active, created_by, created_at
		 FROM api_key WHERE id = ?`, id)
	return scanKey(row)
}

// GetKeyByValue 按密钥值取密钥（M3 认证用）；不存在返回 ErrNotFound。
func (s *ApiKeyStore) GetKeyByValue(ctx context.Context, keyValue string) (*model.APIKey, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, project_id, name, key_value, fingerprint, expires_at,
		        last_used_at, last_used_ip, is_active, created_by, created_at
		 FROM api_key WHERE key_value = ?`, keyValue)
	return scanKey(row)
}

// ListKeysByProject 分页查询某项目密钥；永不返回 key_value（model json:"-" 兜底）。
func (s *ApiKeyStore) ListKeysByProject(ctx context.Context, projectID int64, active *bool, page, size int) ([]model.APIKey, int, error) {
	where := []string{"project_id = ?"}
	args := []any{projectID}
	if active != nil {
		where = append(where, "is_active = ?")
		args = append(args, boolToInt(*active))
	}
	cond := "WHERE " + strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM api_key `+cond, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计密钥失败: %w", err)
	}

	limitArgs := append(append([]any{}, args...), size, (page-1)*size)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project_id, name, key_value, fingerprint, expires_at,
		        last_used_at, last_used_ip, is_active, created_by, created_at
		 FROM api_key `+cond+` ORDER BY id LIMIT ? OFFSET ?`, limitArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询密钥列表失败: %w", err)
	}
	defer rows.Close()

	items := []model.APIKey{}
	for rows.Next() {
		var k model.APIKey
		if err := scanKeyRows(rows, &k); err != nil {
			return nil, 0, err
		}
		items = append(items, k)
	}
	return items, total, rows.Err()
}

// UpdateKey 更新密钥（name/expires_at/fingerprint/is_active）。
func (s *ApiKeyStore) UpdateKey(ctx context.Context, k *model.APIKey) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE api_key SET name = ?, expires_at = ?, fingerprint = ?, is_active = ?
		 WHERE id = ?`,
		k.Name, nullableTime(k.ExpiresAt), nullablePtrString(k.Fingerprint),
		boolToInt(k.IsActive), k.ID)
	if err != nil {
		return fmt.Errorf("更新密钥失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteKey 吊销密钥：立即失效（软删 is_active=0，文档 04 §3.5）。
func (s *ApiKeyStore) DeleteKey(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE api_key SET is_active = 0 WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("吊销密钥失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountKeysByProject 统计项目密钥数（项目管理详情/列表用）。
func (s *ApiKeyStore) CountKeysByProject(ctx context.Context, projectID int64) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM api_key WHERE project_id = ?`, projectID).Scan(&n); err != nil {
		return 0, fmt.Errorf("统计密钥失败: %w", err)
	}
	return n, nil
}

// CountActiveKeys 统计启用状态密钥总数（仪表盘统计 active_keys，05 §4.5）。
func (s *ApiKeyStore) CountActiveKeys(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM api_key WHERE is_active = 1`).Scan(&n); err != nil {
		return 0, fmt.Errorf("统计有效密钥失败: %w", err)
	}
	return n, nil
}

// CountExpiringKeys 统计在 [now, until] 之间到期的启用密钥数
// （仪表盘 expiring_keys_7d：7 天内到期，不含已过期，05 §4.5 / 02 §3）。
func (s *ApiKeyStore) CountExpiringKeys(ctx context.Context, now, until time.Time) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM api_key
		 WHERE is_active = 1 AND expires_at IS NOT NULL
		   AND expires_at > ? AND expires_at <= ?`,
		database.FormatTime(now), database.FormatTime(until)).Scan(&n); err != nil {
		return 0, fmt.Errorf("统计临期密钥失败: %w", err)
	}
	return n, nil
}

// scanKey 扫描单行密钥。
func scanKey(row *sql.Row) (*model.APIKey, error) {
	var k model.APIKey
	if err := scanKeyRows(row, &k); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &k, nil
}

// scanKeyRows 扫描密钥行（Row 或 Rows 共用）。
type rowScanner interface {
	Scan(dest ...any) error
}

func scanKeyRows(sc rowScanner, k *model.APIKey) error {
	var fingerprint, expiresAt, lastUsedAt sql.NullString
	var lastUsedIP sql.NullString
	var isActive int
	var createdAt string
	if err := sc.Scan(&k.ID, &k.ProjectID, &k.Name, &k.KeyValue, &fingerprint, &expiresAt,
		&lastUsedAt, &lastUsedIP, &isActive, &k.CreatedBy, &createdAt); err != nil {
		return err
	}
	if fingerprint.Valid {
		k.Fingerprint = &fingerprint.String
	}
	if expiresAt.Valid {
		if t, err := parseTime(expiresAt.String); err != nil {
			return err
		} else {
			k.ExpiresAt = &t
		}
	}
	if lastUsedAt.Valid {
		if t, err := parseTime(lastUsedAt.String); err != nil {
			return err
		} else {
			k.LastUsedAt = &t
		}
	}
	if lastUsedIP.Valid {
		k.LastUsedIP = lastUsedIP.String
	}
	k.IsActive = isActive == 1
	var err error
	if k.CreatedAt, err = parseTime(createdAt); err != nil {
		return err
	}
	return nil
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return database.FormatTime(*t)
}
