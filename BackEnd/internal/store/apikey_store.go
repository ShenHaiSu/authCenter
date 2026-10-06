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

// keyBackfillBatchSize key_hash 回填/加密启用的默认批大小（need01 03 §3.2）。
const keyBackfillBatchSize = 1000

// keyCols api_key 查询列（F-021 追加 key_value_enc / key_hash）。
// 顺序与 scanKeyRows 严格对应，改列请同步改两处。
const keyCols = `id, project_id, name, key_value, key_value_enc, key_hash, fingerprint,
	        expires_at, last_used_at, last_used_ip, is_active, created_by, created_at`

// CreateKey 插入密钥（F-021：必须同时写 key_hash 与 key_value_enc，
// 漏写会导致认证全部 key_not_found，见 need01 03 §4.5 易错点提醒）。
func (s *ApiKeyStore) CreateKey(ctx context.Context, k *model.APIKey) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO api_key (project_id, name, key_value, key_value_enc, key_hash,
		                      fingerprint, expires_at, is_active, created_by, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		k.ProjectID, k.Name, k.KeyValue, k.KeyValueEnc, nullableHash(k.KeyHash),
		nullablePtrString(k.Fingerprint), nullableTime(k.ExpiresAt),
		boolToInt(k.IsActive), k.CreatedBy, database.FormatTime(k.CreatedAt))
	if err != nil {
		if isUniqueViolation(err) {
			// key_hash 唯一索引冲突：理论上的 SHA-256 碰撞或库被手工改写。
			return 0, ErrConflict
		}
		return 0, fmt.Errorf("创建密钥失败: %w", err)
	}
	return res.LastInsertId()
}

// GetKeyByID 按 id 取密钥；不存在返回 ErrNotFound。
func (s *ApiKeyStore) GetKeyByID(ctx context.Context, id int64) (*model.APIKey, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+keyCols+` FROM api_key WHERE id = ?`, id)
	return scanKey(row)
}

// GetKeyByHash 按 key_hash 取密钥（F-021 认证主路径，走 idx_key_hash 唯一索引）；
// 不存在返回 ErrNotFound。
func (s *ApiKeyStore) GetKeyByHash(ctx context.Context, hash string) (*model.APIKey, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+keyCols+` FROM api_key WHERE key_hash = ?`, hash)
	return scanKey(row)
}

// GetKeyByValuePlain 按明文等值查询（仅供 key_hash 回填未完成期的兼容分支使用，
// 见 need01 03 §4.4）；不存在返回 ErrNotFound。
func (s *ApiKeyStore) GetKeyByValuePlain(ctx context.Context, keyValue string) (*model.APIKey, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+keyCols+` FROM api_key WHERE key_value = ?`, keyValue)
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
		`SELECT `+keyCols+` FROM api_key `+cond+` ORDER BY id LIMIT ? OFFSET ?`, limitArgs...)
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

// UpdateKey 更新密钥（name/expires_at/fingerprint/is_active）；
// 不触碰 key_value / key_value_enc / key_hash（F-021：加密列只在创建/轮换/回填时写）。
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

// UpdateKeyHash 回填单行 key_hash（后台 job 分批写回，need01 03 §3.2）。
// 条件 key_hash IS NULL 由调用方保证；此处仅在目标不存在时报 ErrNotFound。
func (s *ApiKeyStore) UpdateKeyHash(ctx context.Context, id int64, hash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE api_key SET key_hash = ? WHERE id = ?`, hash, id)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict // hash 碰撞：整批回滚并告警，不静默跳过
		}
		return fmt.Errorf("回填 key_hash 失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListKeysWithoutHash 分批取 key_hash 为空且 key_value 非空的存量行（按 id 升序）。
func (s *ApiKeyStore) ListKeysWithoutHash(ctx context.Context, limit int) ([]model.APIKey, error) {
	if limit <= 0 {
		limit = keyBackfillBatchSize
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+keyCols+` FROM api_key
		 WHERE key_hash IS NULL AND key_value <> '' ORDER BY id LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("查询待回填密钥失败: %w", err)
	}
	defer rows.Close()
	items := []model.APIKey{}
	for rows.Next() {
		var k model.APIKey
		if err := scanKeyRows(rows, &k); err != nil {
			return nil, err
		}
		items = append(items, k)
	}
	return items, rows.Err()
}

// CountKeysWithoutHash 统计尚未回填 key_hash 的行数（回填 job 判定完成用）。
func (s *ApiKeyStore) CountKeysWithoutHash(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM api_key WHERE key_hash IS NULL AND key_value <> ''`).Scan(&n); err != nil {
		return 0, fmt.Errorf("统计待回填密钥失败: %w", err)
	}
	return n, nil
}

// CountEncrypted 统计密文模式行数（模式一致性自检 / settings 展示）。
func (s *ApiKeyStore) CountEncrypted(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM api_key WHERE key_value_enc = ?`, model.KeyEncGCM).Scan(&n); err != nil {
		return 0, fmt.Errorf("统计密文密钥失败: %w", err)
	}
	return n, nil
}

// CountPlain 统计明文模式行数（模式一致性自检）。
func (s *ApiKeyStore) CountPlain(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM api_key WHERE key_value_enc = ?`, model.KeyEncPlain).Scan(&n); err != nil {
		return 0, fmt.Errorf("统计明文密钥失败: %w", err)
	}
	return n, nil
}

// ListEncryptedKeys 取前 limit 条密文模式行（启动自检试解 1 条用，need01 03 §4.7）。
func (s *ApiKeyStore) ListEncryptedKeys(ctx context.Context, limit int) ([]model.APIKey, error) {
	if limit <= 0 {
		limit = 1
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+keyCols+` FROM api_key WHERE key_value_enc = ? ORDER BY id LIMIT ?`,
		model.KeyEncGCM, limit)
	if err != nil {
		return nil, fmt.Errorf("查询密文密钥失败: %w", err)
	}
	defer rows.Close()
	items := []model.APIKey{}
	for rows.Next() {
		var k model.APIKey
		if err := scanKeyRows(rows, &k); err != nil {
			return nil, err
		}
		items = append(items, k)
	}
	return items, rows.Err()
}

// ListPlainKeys 分批取明文模式行（启用加密时逐行加密，need01 03 §4.6）。
func (s *ApiKeyStore) ListPlainKeys(ctx context.Context, limit int) ([]model.APIKey, error) {
	if limit <= 0 {
		limit = keyBackfillBatchSize
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+keyCols+` FROM api_key WHERE key_value_enc = ? ORDER BY id LIMIT ?`,
		model.KeyEncPlain, limit)
	if err != nil {
		return nil, fmt.Errorf("查询明文密钥失败: %w", err)
	}
	defer rows.Close()
	items := []model.APIKey{}
	for rows.Next() {
		var k model.APIKey
		if err := scanKeyRows(rows, &k); err != nil {
			return nil, err
		}
		items = append(items, k)
	}
	return items, rows.Err()
}

// EncryptRow 把单行切换为密文模式（启用加密的分批提交，按批 1000 行）。
func (s *ApiKeyStore) EncryptRow(ctx context.Context, id int64, cipherText string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE api_key SET key_value = ?, key_value_enc = ? WHERE id = ? AND key_value_enc = ?`,
		cipherText, model.KeyEncGCM, id, model.KeyEncPlain)
	if err != nil {
		return fmt.Errorf("加密密钥行失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountKeys 统计密钥总行数（前端「密文密钥数 N / 共 M 条」展示用）。
func (s *ApiKeyStore) CountKeys(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM api_key`).Scan(&n); err != nil {
		return 0, fmt.Errorf("统计密钥总数失败: %w", err)
	}
	return n, nil
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
	var keyHash sql.NullString
	var isActive int
	var createdAt string
	if err := sc.Scan(&k.ID, &k.ProjectID, &k.Name, &k.KeyValue, &k.KeyValueEnc, &keyHash,
		&fingerprint, &expiresAt, &lastUsedAt, &lastUsedIP, &isActive, &k.CreatedBy, &createdAt); err != nil {
		return err
	}
	// key_hash 可空（存量行回填前为 NULL）→ 空串表示「尚未回填」。
	k.KeyHash = keyHash.String
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

// nullableHash key_hash 为空时写 NULL（而非空串），
// 以配合「唯一索引允许多行 NULL」与「WHERE key_hash IS NULL」的回填条件。
func nullableHash(hash string) any {
	if hash == "" {
		return nil
	}
	return hash
}
