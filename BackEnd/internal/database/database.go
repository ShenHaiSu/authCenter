// Package database 负责 SQLite 连接、PRAGMA 与幂等迁移（文档 03 §6、04 §1）。
// 驱动：modernc.org/sqlite（纯 Go，无 cgo，满足需求红线 C1）。
package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	_ "modernc.org/sqlite" // 纯 Go SQLite 驱动
)

// DBFileName 数据库文件名（文档 02 §6 启动流程）。
const DBFileName = "authcenter.db"

// migrate 迁移 DDL：CREATE TABLE IF NOT EXISTS，追加式演进（文档 03 §6）。
// 目标态 6 张表一次性建齐（admin_user / admin_session / project / api_key / audit_log / settings）。
var migrations = []string{
	// 2.1 admin_user
	`CREATE TABLE IF NOT EXISTS admin_user (
		id             INTEGER PRIMARY KEY AUTOINCREMENT,
		username       TEXT    NOT NULL UNIQUE,
		password_hash  TEXT    NOT NULL,
		is_active      INTEGER NOT NULL DEFAULT 1,
		created_at     TEXT    NOT NULL,
		last_login_at  TEXT,
		last_login_ip  TEXT
	);`,
	// 2.2 admin_session
	`CREATE TABLE IF NOT EXISTS admin_session (
		id             INTEGER PRIMARY KEY AUTOINCREMENT,
		token_hash     TEXT    NOT NULL UNIQUE,
		admin_user_id  INTEGER NOT NULL REFERENCES admin_user(id) ON DELETE CASCADE,
		expires_at     TEXT    NOT NULL,
		ip             TEXT,
		user_agent     TEXT,
		created_at     TEXT    NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_session_user   ON admin_session(admin_user_id);
	CREATE INDEX IF NOT EXISTS idx_session_expire ON admin_session(expires_at);`,
	// 2.3 project
	`CREATE TABLE IF NOT EXISTS project (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		name            TEXT    NOT NULL UNIQUE,
		description     TEXT,
		current_version TEXT,
		min_version     TEXT,
		is_active       INTEGER NOT NULL DEFAULT 1,
		created_at      TEXT    NOT NULL,
		updated_at      TEXT    NOT NULL
	);`,
	// 2.4 api_key
	`CREATE TABLE IF NOT EXISTS api_key (
		id             INTEGER PRIMARY KEY AUTOINCREMENT,
		project_id     INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
		name           TEXT    NOT NULL DEFAULT '',
		key_value      TEXT    NOT NULL,
		fingerprint    TEXT,
		expires_at     TEXT,
		last_used_at   TEXT,
		last_used_ip   TEXT,
		is_active      INTEGER NOT NULL DEFAULT 1,
		created_by     TEXT    NOT NULL DEFAULT 'admin',
		created_at     TEXT    NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_key_project ON api_key(project_id);
	CREATE INDEX IF NOT EXISTS idx_key_value   ON api_key(key_value);
	CREATE INDEX IF NOT EXISTS idx_key_expire  ON api_key(expires_at);`,
	// 2.5 audit_log
	`CREATE TABLE IF NOT EXISTS audit_log (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		event_time  TEXT    NOT NULL,
		event_type  TEXT    NOT NULL,
		actor_type  TEXT    NOT NULL,
		actor_id    TEXT,
		actor_name  TEXT,
		target_type TEXT,
		target_id   INTEGER,
		target_name TEXT,
		result      TEXT    NOT NULL,
		detail      TEXT,
		ip          TEXT,
		request_id  TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_audit_time  ON audit_log(event_time);
	CREATE INDEX IF NOT EXISTS idx_audit_type  ON audit_log(event_type);
	CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);`,
	// 2.6 settings
	`CREATE TABLE IF NOT EXISTS settings (
		key        TEXT PRIMARY KEY,
		value      TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);`,
}

// Open 打开（必要时创建）数据目录与 SQLite 数据库，设置 PRAGMA 并执行迁移。
//
// 目录权限：POSIX 下 chmod 0700；db 文件 0600（文档 06 §8）。
// Windows 依赖用户目录 ACL，chmod 仅尽力而为。
func Open(dataDir string) (*sql.DB, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(dataDir, 0o700)
	}

	dbPath := filepath.Join(dataDir, DBFileName)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}
	// 本机单实例：单连接即可规避写锁竞争（文档 03 §6 并发规范）。
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// PRAGMA（文档 02 §6 启动流程第 3 步）。
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("执行 PRAGMA 失败 %q: %w", p, err)
		}
	}

	if runtime.GOOS != "windows" {
		// WAL 附属文件与 db 同目录，目录 0700 已足够；db 文件尽力 0600。
		_ = os.Chmod(dbPath, 0o600)
	}

	// 迁移：启动时顺序执行幂等 DDL（文档 03 §6）。
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("数据库迁移失败: %w", err)
	}
	return db, nil
}

// migrate 顺序执行幂等 DDL；每条语句单独执行，失败即中止并报错（启动自检，文档 01 §5）。
func migrate(db *sql.DB) error {
	for i, stmt := range migrations {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("迁移语句 #%d 失败: %w", i+1, err)
		}
	}
	return nil
}

// NowUTC 返回当前 UTC 时间，格式化为 SQLite TEXT ISO8601（文档 03 §2）。
func NowUTC() time.Time {
	return time.Now().UTC()
}

// FormatTime 将 time.Time 格式化为 ISO8601 UTC（如 2026-01-01T00:00:00Z）。
func FormatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
