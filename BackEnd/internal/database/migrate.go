// Package database 迁移框架：step 注册表 + PRAGMA user_version（need01 06 §3）。
package database

import (
	"database/sql"
	"fmt"
)

// step 单个迁移步骤：版本号单调递增，Name 仅用于日志/审计。
// Up 内部必须自身幂等，版本号只决定“该不该执行”。
type step struct {
	Version int
	Name    string
	Up      func(*sql.DB) error
}

// AppliedStep 本次实际执行的步骤（供启动日志与审计）。
type AppliedStep struct {
	Version int
	Name    string
}

// migrationSteps 迁移步骤表。只允许在末尾追加，禁止修改历史步骤。
// 版本号按落地顺序分配（《06》§3.1）：M7(F-019) 无 DDL 变更；
// M9(F-020) 先于 F-021 落地，故 admin_user_role 取 v2，F-021 的 api_key_hash 顺延为 v3。
var migrationSteps = []step{
	{Version: 1, Name: "baseline_tables", Up: upBaselineTables},
	{Version: 2, Name: "admin_user_role", Up: upAdminUserRole},
	{Version: 3, Name: "api_key_hash", Up: upApiKeyHashColumns},
}

// targetSchemaVersion 当前二进制期望的 schema 版本（= 最高注册版本）。
func targetSchemaVersion() int { return migrationSteps[len(migrationSteps)-1].Version }

// TargetSchemaVersion 对外暴露目标版本（main 启动日志 / -migrate-only）。
func TargetSchemaVersion() int { return targetSchemaVersion() }

// upBaselineTables v1 基线：现有 6 张表（从 migrations 迁入，存量库幂等空跑）。
func upBaselineTables(db *sql.DB) error {
	for i, stmt := range migrations {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("基线语句 #%d 失败: %w", i+1, err)
		}
	}
	return nil
}

// upAdminUserRole F-020（M9）：admin_user 新增 role/force_password_change/updated_at
// 三列（幂等 ensureColumn），并把存量初始账号 admin 回填为 owner。
//
// 回填条件说明（与《02》§3.2 的差异，刻意修正）：role 列定义为 NOT NULL DEFAULT 'admin'，
// SQLite 在 ADD COLUMN 时把存量行填成 admin 而非 NULL，故《02》§3.2 写的
// `role IS NULL OR role = 空串` 条件对存量库恒不命中 → 存量 admin 永远停留在 admin，
// 无人可管理管理员（把自己锁在门外）。因此改为 null-safe 的 `role IS NOT 'owner'`：
// 新装库此时表为空（EnsureAdmin 在迁移之后创建 admin 且直接写 owner），天然空跑；
// 存量库首次升 v2 时提为 owner，之后条件不再命中 → 幂等。
func upAdminUserRole(db *sql.DB) error {
	cols := []struct{ def, name string }{
		{"role TEXT NOT NULL DEFAULT 'admin'", "role"},
		{"force_password_change INTEGER NOT NULL DEFAULT 0", "force_password_change"},
		{"updated_at TEXT", "updated_at"},
	}
	for _, c := range cols {
		if err := ensureColumn(db, "admin_user", c.def, c.name); err != nil {
			return err
		}
	}
	if _, err := db.Exec(
		`UPDATE admin_user SET role = 'owner' WHERE username = 'admin' AND role IS NOT 'owner'`); err != nil {
		return fmt.Errorf("回填初始账号 admin 为 owner 失败: %w", err)
	}
	return nil
}

// upApiKeyHashColumns F-021（M8）：api_key 新增 key_hash / key_value_enc 两列
// （幂等 ensureColumn）与 key_hash 唯一索引。
//
// 设计要点（need01 03 §3.1）：
//   - key_hash 可空：存量行由后台 job 分批回填（不在启动路径上，见《06》§4）；
//   - key_value_enc NOT NULL DEFAULT 0：0=明文（key_value 存明文）、1=AES-256-GCM 密文；
//   - 唯一索引允许多行 NULL，因此「先建索引后回填」安全（《06》§7）。
func upApiKeyHashColumns(db *sql.DB) error {
	cols := []struct{ def, name string }{
		{"key_hash TEXT", "key_hash"},
		{"key_value_enc INTEGER NOT NULL DEFAULT 0", "key_value_enc"},
	}
	for _, c := range cols {
		if err := ensureColumn(db, "api_key", c.def, c.name); err != nil {
			return err
		}
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_key_hash ON api_key(key_hash)`); err != nil {
		return fmt.Errorf("创建 key_hash 唯一索引失败: %w", err)
	}
	return nil
}

// schemaVersion 读取 PRAGMA user_version。
func schemaVersion(db *sql.DB) (int, error) {
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return 0, fmt.Errorf("读取 schema 版本失败: %w", err)
	}
	return v, nil
}

// SchemaVersion 对外读取当前库版本（settings 展示用）。
func SchemaVersion(db *sql.DB) (int, error) { return schemaVersion(db) }

// setSchemaVersion 写入 PRAGMA user_version。
// 注意：PRAGMA user_version = N 不能用占位符传参，必须格式化拼接；
// N 来自代码内常量表（非用户输入），无注入面。
func setSchemaVersion(db *sql.DB, v int) error {
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", v)); err != nil {
		return fmt.Errorf("写入 schema 版本 %d 失败: %w", v, err)
	}
	return nil
}

// ensureColumn 幂等新增列：列已存在则直接返回 nil（迁移可重复执行）。
func ensureColumn(db *sql.DB, table, columnDef string, column string) error {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return fmt.Errorf("读取 %s 表结构失败: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dflt any
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return fmt.Errorf("扫描 %s 表结构失败: %w", table, err)
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", table, columnDef)); err != nil {
		return fmt.Errorf("为 %s 新增列 %s 失败: %w", table, column, err)
	}
	return nil
}

// applyMigrations 迁移主流程：
//  1. 读当前版本 cur；cur > target → 拒绝启动（防危险降级）
//  2. 按版本升序执行所有 version > cur 的 step（串行：先 Up 后写版本）
//  3. 返回本次实际执行的步骤列表
//
// 注意：本库 MaxOpenConns=1，禁止 Begin 后再用 db.Exec（会死锁）。
// 因此不使用显式事务；Up 自身幂等（IF NOT EXISTS / ensureColumn），
// 版本号仅在 Up 成功后写入，失败即中止启动，重跑可继续。
func applyMigrations(db *sql.DB) ([]AppliedStep, error) {
	cur, err := schemaVersion(db)
	if err != nil {
		return nil, err
	}
	target := targetSchemaVersion()
	if cur > target {
		return nil, fmt.Errorf("数据库 schema 版本 v%d 高于当前二进制支持的 v%d；请升级二进制，或用备份恢复数据库（旧二进制无法正确读取新版结构）", cur, target)
	}
	var applied []AppliedStep
	for _, st := range migrationSteps {
		if st.Version <= cur {
			continue
		}
		if err := st.Up(db); err != nil {
			return nil, fmt.Errorf("迁移步骤 %s(v%d) 失败: %w", st.Name, st.Version, err)
		}
		if err := setSchemaVersion(db, st.Version); err != nil {
			return nil, err
		}
		applied = append(applied, AppliedStep{Version: st.Version, Name: st.Name})
	}
	return applied, nil
}
