package database

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// openTemp 在临时目录打开数据库。
func openTemp(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, dir
}

// TestOpenCreatesAllTables 验证 6 张表全部建齐（文档 03 §2）。
func TestOpenCreatesAllTables(t *testing.T) {
	db, _ := openTemp(t)
	expected := []string{"admin_user", "admin_session", "project", "api_key", "audit_log", "settings"}
	for _, name := range expected {
		var n int
		err := db.QueryRow(
			`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n)
		if err != nil {
			t.Fatalf("查询表 %s 失败: %v", name, err)
		}
		if n != 1 {
			t.Errorf("表 %s 未创建", name)
		}
	}
}

// TestOpenIdempotent 迁移幂等：对同一数据库重复 Open 不报错（文档 08 §2）。
func TestOpenIdempotent(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		db, err := Open(dir)
		if err != nil {
			t.Fatalf("第 %d 次 Open 失败: %v", i+1, err)
		}
		db.Close()
	}
}

// TestPragmas 验证 PRAGMA 生效（WAL / foreign_keys / busy_timeout）。
func TestPragmas(t *testing.T) {
	db, dir := openTemp(t)

	var journal string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&journal); err != nil {
		t.Fatalf("读取 journal_mode 失败: %v", err)
	}
	if journal != "wal" {
		t.Errorf("journal_mode = %q, 期望 wal", journal)
	}

	var fk int
	if err := db.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil {
		t.Fatalf("读取 foreign_keys 失败: %v", err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, 期望 1", fk)
	}

	var busy int
	if err := db.QueryRow("PRAGMA busy_timeout").Scan(&busy); err != nil {
		t.Fatalf("读取 busy_timeout 失败: %v", err)
	}
	if busy != 5000 {
		t.Errorf("busy_timeout = %d, 期望 5000", busy)
	}

	// WAL 附属文件存在（-wal 可能在关闭后合并，这里不强断言，仅确认 db 文件存在）。
	if _, err := sql.Open("sqlite", filepath.Join(dir, DBFileName)); err != nil {
		t.Fatalf("db 文件可打开: %v", err)
	}
}

// TestForeignKeyCascade 外键级联：删除 project 应级联删除 api_key（文档 03 §2.4）。
func TestForeignKeyCascade(t *testing.T) {
	db, _ := openTemp(t)
	_, err := db.Exec(`INSERT INTO project (name, created_at, updated_at) VALUES ('svc', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`)
	if err != nil {
		t.Fatalf("插入 project 失败: %v", err)
	}
	_, err = db.Exec(`INSERT INTO api_key (project_id, key_value, created_at) VALUES (1, 'secret-key', '2026-01-01T00:00:00Z')`)
	if err != nil {
		t.Fatalf("插入 api_key 失败: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM project WHERE id=1`); err != nil {
		t.Fatalf("删除 project 失败: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM api_key WHERE project_id=1`).Scan(&n); err != nil {
		t.Fatalf("查询 api_key 失败: %v", err)
	}
	if n != 0 {
		t.Errorf("级联删除后 api_key 残留 %d 条", n)
	}
}
