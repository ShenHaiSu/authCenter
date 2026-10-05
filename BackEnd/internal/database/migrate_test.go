// migrate_test.go — F-020 迁移 step admin_user_role 的专项测试（need01 02 §7.2 / 06 §8）。
// 覆盖：幂等 ALTER、三列落地、存量 admin 回填为 owner（且幂等）、全新库 v3 空跑。
package database

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// columnExists 判断列是否存在（测试辅助）。
func columnExists(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatalf("读取 %s 表结构失败: %v", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("扫描表结构失败: %v", err)
		}
		if name == column {
			return true
		}
	}
	return false
}

// userVersion 读取 PRAGMA user_version。
func userVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		t.Fatalf("读取 user_version 失败: %v", err)
	}
	return v
}

// TestAdminUserRoleMigrationFreshDB 全新库：迁移到 target，三列齐全，user_version == target。
func TestAdminUserRoleMigrationFreshDB(t *testing.T) {
	dir := t.TempDir()
	db, applied, err := OpenWithApplied(dir)
	if err != nil {
		t.Fatalf("OpenWithApplied 失败: %v", err)
	}
	defer db.Close()

	for _, col := range []string{"role", "force_password_change", "updated_at"} {
		if !columnExists(t, db, "admin_user", col) {
			t.Errorf("全新库 admin_user 应有列 %s", col)
		}
	}
	if got := userVersion(t, db); got != targetSchemaVersion() {
		t.Errorf("user_version = %d, 期望 target %d", got, targetSchemaVersion())
	}
	if len(applied) != 2 || applied[1].Name != "admin_user_role" {
		t.Errorf("本次应执行 baseline_tables + admin_user_role, 实际 %+v", applied)
	}

	// 二次打开：applied 为空，版本不变（幂等）。
	db.Close()
	db2, applied2, err := OpenWithApplied(dir)
	if err != nil {
		t.Fatalf("二次 OpenWithApplied 失败: %v", err)
	}
	defer db2.Close()
	if len(applied2) != 0 {
		t.Errorf("二次打开不应执行任何 step, 实际 %+v", applied2)
	}
	if got := userVersion(t, db2); got != targetSchemaVersion() {
		t.Errorf("二次打开后 user_version = %d, 期望 %d", got, targetSchemaVersion())
	}
}

// legacyAdminUserDDL 存量库（v1 基线，无 F-020 三列）的 admin_user 建表语句。
const legacyAdminUserDDL = `CREATE TABLE admin_user (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	username       TEXT    NOT NULL UNIQUE,
	password_hash  TEXT    NOT NULL,
	is_active      INTEGER NOT NULL DEFAULT 1,
	created_at     TEXT    NOT NULL,
	last_login_at  TEXT,
	last_login_ip  TEXT
)`

// TestLegacyAdminBackfillOnStart F-020 §7.2 核心回归：
// 构造「只有 admin 且缺 role 列」的存量库 → 启动迁移 → 该行 role 回填为 owner；
// 再次启动值不变（幂等）。
func TestLegacyAdminBackfillOnStart(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, DBFileName)

	// 造存量库：只有 admin_user 表（无三列）+ 一个 admin 行 + user_version=0。
	legacy, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("打开存量库失败: %v", err)
	}
	if _, err := legacy.Exec(legacyAdminUserDDL); err != nil {
		t.Fatalf("创建存量 admin_user 失败: %v", err)
	}
	if _, err := legacy.Exec(
		`INSERT INTO admin_user (username, password_hash, is_active, created_at)
		 VALUES ('admin', 'legacy-hash', 1, '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("插入存量 admin 失败: %v", err)
	}
	// 确认迁移前确实没有 role 列。
	if columnExists(t, legacy, "admin_user", "role") {
		t.Fatal("迁移前的存量库不应有 role 列")
	}
	legacy.Close()

	// 启动迁移。
	db, applied, err := OpenWithApplied(dir)
	if err != nil {
		t.Fatalf("迁移存量库失败: %v", err)
	}
	var role string
	if err := db.QueryRow(`SELECT role FROM admin_user WHERE username = 'admin'`).Scan(&role); err != nil {
		t.Fatalf("读取回填后的 role 失败: %v", err)
	}
	if role != "owner" {
		t.Errorf("存量 admin 的 role = %q, 期望回填为 owner", role)
	}
	if len(applied) == 0 || applied[len(applied)-1].Name != "admin_user_role" {
		t.Errorf("应执行 admin_user_role 迁移, 实际 %+v", applied)
	}
	// 其余两列也应就位。
	for _, col := range []string{"force_password_change", "updated_at"} {
		if !columnExists(t, db, "admin_user", col) {
			t.Errorf("存量库迁移后应新增列 %s", col)
		}
	}
	// 存量行的 force_password_change 默认为 0（不强制改密）。
	var force int
	if err := db.QueryRow(
		`SELECT force_password_change FROM admin_user WHERE username = 'admin'`).Scan(&force); err != nil {
		t.Fatal(err)
	}
	if force != 0 {
		t.Errorf("存量行 force_password_change = %d, 期望 0", force)
	}
	// updated_at 存量为空（界面显示 —）。
	var updatedAt sql.NullString
	if err := db.QueryRow(
		`SELECT updated_at FROM admin_user WHERE username = 'admin'`).Scan(&updatedAt); err != nil {
		t.Fatal(err)
	}
	if updatedAt.Valid {
		t.Errorf("存量行 updated_at 应为空, 实际 %q", updatedAt.String)
	}

	// 幂等：再次启动不应改动 role。
	db.Close()
	db2, applied2, err := OpenWithApplied(dir)
	if err != nil {
		t.Fatalf("二次迁移失败: %v", err)
	}
	defer db2.Close()
	if len(applied2) != 0 {
		t.Errorf("二次启动不应执行 step, 实际 %+v", applied2)
	}
	if err := db2.QueryRow(`SELECT role FROM admin_user WHERE username = 'admin'`).Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "owner" {
		t.Errorf("二次启动后 role = %q, 应保持 owner", role)
	}
}

// TestBackfillOnlyTouchesAdmin F-020 §3.2：回填只针对初始账号 admin，不影响其它账号。
func TestBackfillOnlyTouchesAdmin(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, DBFileName)

	legacy, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("打开存量库失败: %v", err)
	}
	if _, err := legacy.Exec(legacyAdminUserDDL); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"admin", "alice", "bob"} {
		if _, err := legacy.Exec(
			`INSERT INTO admin_user (username, password_hash, is_active, created_at) VALUES (?, 'h', 1, '2026-01-01T00:00:00Z')`,
			u); err != nil {
			t.Fatal(err)
		}
	}
	legacy.Close()

	db, _, err := OpenWithApplied(dir)
	if err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	defer db.Close()

	roles := map[string]string{}
	rows, err := db.Query(`SELECT username, role FROM admin_user ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, role string
		if err := rows.Scan(&name, &role); err != nil {
			t.Fatal(err)
		}
		roles[name] = role
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if roles["admin"] != "owner" {
		t.Errorf("admin.role = %q, 期望 owner", roles["admin"])
	}
	// 其它存量账号保持默认 admin（不会被误提权）。
	for _, name := range []string{"alice", "bob"} {
		if roles[name] != "admin" {
			t.Errorf("%s.role = %q, 应保持默认 admin（回填只针对初始账号）", name, roles[name])
		}
	}
}

// TestRefuseDowngradeBinary 高版本库 + 低版本二进制 → 拒绝启动（need01 06 §8 回归）。
func TestRefuseDowngradeBinary(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, DBFileName)

	legacy, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	if _, err := legacy.Exec(`CREATE TABLE dummy (id INTEGER)`); err != nil {
		t.Fatal(err)
	}
	// 写入高于当前二进制的版本号。
	if _, err := legacy.Exec("PRAGMA user_version = " + itoa(targetSchemaVersion()+1)); err != nil {
		t.Fatal(err)
	}
	legacy.Close()

	if _, err := Open(dir); err == nil {
		t.Error("高版本库应拒绝启动")
	} else if !contains(err.Error(), "高于当前二进制") {
		t.Errorf("错误信息应提示版本过高, 实际: %v", err)
	}
}

// itoa 避免为一个数字引入 strconv（仅测试用）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// contains 判断字符串包含子串（避免为一个判断引入 strings，测试内聚即可）。
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
