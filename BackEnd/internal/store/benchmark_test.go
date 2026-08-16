// Package store 数据访问层基准：SQLite 读写核心路径（文档 01 §5 性能预算参考）。
package store

import (
	"context"
	"fmt"
	"testing"

	"github.com/authcenter/authcenter/internal/database"
)

// newBenchDB 打开临时数据库并预置 1 个项目 + 1 个密钥（模拟最小数据集）。
func newBenchDB(b *testing.B) (*Store, int64) {
	b.Helper()
	dir := b.TempDir()
	db, err := database.Open(dir)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { db.Close() })
	st := New(db)

	ctx := context.Background()
	now := database.FormatTime(database.NowUTC())
	res, err := db.ExecContext(ctx,
		`INSERT INTO project (name, description, current_version, min_version, is_active, created_at, updated_at)
		 VALUES ('bench-svc', '', '1.0.0', NULL, 1, ?, ?)`, now, now)
	if err != nil {
		b.Fatal(err)
	}
	pid, err := res.LastInsertId()
	if err != nil {
		b.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO api_key (project_id, name, key_value, fingerprint, expires_at, is_active, created_by, created_at)
		 VALUES (?, 'bench-key', 'Kx8benchmarkkey000000000000000000000000000', NULL, NULL, 1, 'admin', ?)`,
		pid, now); err != nil {
		b.Fatal(err)
	}
	return st, pid
}

// BenchmarkAuthLookup 测认证接口核心查询（文档 03 §3：project JOIN api_key，走索引）。
// M2/M3 认证接口主路径预算：本查询 + 审计写入 + JSON 编解码应 < 50ms（P99）。
func BenchmarkAuthLookup(b *testing.B) {
	st, _ := newBenchDB(b)
	ctx := context.Background()
	keyValue := "Kx8benchmarkkey000000000000000000000000000"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rows, err := st.DB().QueryContext(ctx,
			`SELECT k.id, k.key_value, k.fingerprint, k.expires_at, k.is_active,
			        p.id AS project_id, p.name, p.is_active AS project_active, p.current_version
			 FROM api_key k JOIN project p ON p.id = k.project_id
			 WHERE p.name = ? AND k.key_value = ?`, "bench-svc", keyValue)
		if err != nil {
			b.Fatal(err)
		}
		var (
			id, pid       int64
			keyVal        string
			fp, exp, ver  any
			kActive, pAct int
			pName         string
		)
		if rows.Next() {
			if err := rows.Scan(&id, &keyVal, &fp, &exp, &kActive, &pid, &pName, &pAct, &ver); err != nil {
				b.Fatal(err)
			}
		}
		rows.Close()
	}
}

// BenchmarkKeyInsert 测密钥写入（密钥生成路径，含索引更新；WAL 模式）。
func BenchmarkKeyInsert(b *testing.B) {
	st, pid := newBenchDB(b)
	ctx := context.Background()
	now := database.FormatTime(database.NowUTC())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := st.DB().ExecContext(ctx,
			`INSERT INTO api_key (project_id, name, key_value, is_active, created_by, created_at)
			 VALUES (?, 'bench', ?, 1, 'admin', ?)`,
			pid, fmt.Sprintf("bench-key-%d", i), now)
		if err != nil {
			b.Fatal(err)
		}
	}
}
