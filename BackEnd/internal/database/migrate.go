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
// 版本号按落地顺序分配；当前 M7(F-019)无 DDL 变更，仅 v1 基线。
var migrationSteps = []step{
	{Version: 1, Name: "baseline_tables", Up: upBaselineTables},
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
