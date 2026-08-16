package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/model"
)

// ProjectStore project 表访问（文档 03 §2.3）。
type ProjectStore struct {
	db *sql.DB
}

const projectCols = `id, name, description, current_version, min_version, is_active, created_at, updated_at`

// CreateProject 插入项目；名称冲突返回 ErrConflict（20201）。
func (s *ProjectStore) CreateProject(ctx context.Context, p *model.Project) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO project (name, description, current_version, min_version, is_active, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.Name, nullableString(p.Description), nullableString(p.CurrentVersion),
		nullablePtrString(p.MinVersion), boolToInt(p.IsActive),
		database.FormatTime(p.CreatedAt), database.FormatTime(p.UpdatedAt))
	if err != nil {
		if isUniqueViolation(err) {
			return 0, ErrConflict
		}
		return 0, fmt.Errorf("创建项目失败: %w", err)
	}
	return res.LastInsertId()
}

// GetProjectByID 按 id 取项目；不存在返回 ErrNotFound。
func (s *ProjectStore) GetProjectByID(ctx context.Context, id int64) (*model.Project, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+projectCols+` FROM project WHERE id = ?`, id)
	return scanProject(row)
}

// GetProjectByName 按名称取项目（M3 认证用）；不存在返回 ErrNotFound。
func (s *ProjectStore) GetProjectByName(ctx context.Context, name string) (*model.Project, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+projectCols+` FROM project WHERE name = ?`, name)
	return scanProject(row)
}

// ListProjects 分页查询项目，附带 key_count；支持名称模糊（q）与状态筛选（active）。
func (s *ProjectStore) ListProjects(ctx context.Context, q string, active *bool, page, size int) ([]model.Project, int, error) {
	where := []string{"1=1"}
	args := []any{}
	if q != "" {
		where = append(where, "name LIKE ?")
		args = append(args, "%"+q+"%")
	}
	if active != nil {
		where = append(where, "is_active = ?")
		args = append(args, boolToInt(*active))
	}
	cond := "WHERE " + strings.Join(where, " AND ")

	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM project `+cond, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计项目失败: %w", err)
	}

	limitArgs := append(append([]any{}, args...), size, (page-1)*size)
	rows, err := s.db.QueryContext(ctx,
		`SELECT p.id, p.name, p.description, p.current_version, p.min_version, p.is_active,
		        p.created_at, p.updated_at,
		        (SELECT count(*) FROM api_key k WHERE k.project_id = p.id) AS key_count
		 FROM project p `+cond+` ORDER BY p.id LIMIT ? OFFSET ?`, limitArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询项目列表失败: %w", err)
	}
	defer rows.Close()

	items := []model.Project{}
	for rows.Next() {
		var p model.Project
		var desc, curVer sql.NullString
		var minVer sql.NullString
		var isActive int
		var createdAt, updatedAt string
		if err := rows.Scan(&p.ID, &p.Name, &desc, &curVer, &minVer, &isActive,
			&createdAt, &updatedAt, &p.KeyCount); err != nil {
			return nil, 0, fmt.Errorf("扫描项目失败: %w", err)
		}
		p.Description = desc.String
		p.CurrentVersion = curVer.String
		if minVer.Valid {
			p.MinVersion = &minVer.String
		}
		p.IsActive = isActive == 1
		if p.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, 0, err
		}
		if p.UpdatedAt, err = parseTime(updatedAt); err != nil {
			return nil, 0, err
		}
		items = append(items, p)
	}
	return items, total, rows.Err()
}

// UpdateProject 更新项目（description/current_version/min_version/is_active）。
func (s *ProjectStore) UpdateProject(ctx context.Context, p *model.Project) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE project SET description = ?, current_version = ?, min_version = ?, is_active = ?, updated_at = ?
		 WHERE id = ?`,
		nullableString(p.Description), nullableString(p.CurrentVersion),
		nullablePtrString(p.MinVersion), boolToInt(p.IsActive),
		database.FormatTime(p.UpdatedAt), p.ID)
	if err != nil {
		return fmt.Errorf("更新项目失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteProject 删除项目（外键级联删密钥，文档 03 §2.3）。
func (s *ProjectStore) DeleteProject(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM project WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("删除项目失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// scanProject 扫描单行 project（含子查询 key_count 时另走 ListProjects）。
func scanProject(row *sql.Row) (*model.Project, error) {
	var p model.Project
	var desc, curVer sql.NullString
	var minVer sql.NullString
	var isActive int
	var createdAt, updatedAt string
	if err := row.Scan(&p.ID, &p.Name, &desc, &curVer, &minVer, &isActive, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("查询项目失败: %w", err)
	}
	p.Description = desc.String
	p.CurrentVersion = curVer.String
	if minVer.Valid {
		p.MinVersion = &minVer.String
	}
	p.IsActive = isActive == 1
	var err error
	if p.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if p.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

func nullablePtrString(v *string) any {
	if v == nil {
		return nil
	}
	return *v
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
