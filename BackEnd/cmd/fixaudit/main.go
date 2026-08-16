// Command fixaudit 一次性运维工具：清理 audit_log 中的零值时间记录。
//
// 背景：修复前 SessionService.writeAudit 漏设 EventTime，将 Go 零值时间
// （0001-01-01T00:00:00Z）写入 audit_log.event_time（admin.login / admin.logout /
// admin.login_failed / admin.password_change）。修复后新数据由 store.InsertAudit
// 兜底保证非零；本工具用于清理历史产生的零值记录。
//
// 用法：
//
//	go run ./cmd/fixaudit -db <authcenter.db 路径>         # dry-run：仅列出
//	go run ./cmd/fixaudit -db <authcenter.db 路径> -apply  # 执行删除
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

// zeroEventTime 修复前产生的零值时间字符串（Go time.Time{} 的 RFC3339 格式化）。
const zeroEventTime = "0001-01-01T00:00:00Z"

func main() {
	dbPath := flag.String("db", "", "SQLite 数据库文件路径（必填）")
	apply := flag.Bool("apply", false, "执行删除；默认仅 dry-run 报告")
	flag.Parse()
	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "缺少 -db 参数")
		flag.Usage()
		os.Exit(2)
	}

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "打开数据库失败: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	rows, err := db.Query(
		`SELECT id, event_type, actor_name, ip FROM audit_log WHERE event_time = ? ORDER BY id`,
		zeroEventTime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "查询失败: %v\n", err)
		os.Exit(1)
	}
	type rec struct {
		id          int
		eventType   string
		actor, ip   string
	}
	var recs []rec
	for rows.Next() {
		var r rec
		var actor, ip sql.NullString
		if err := rows.Scan(&r.id, &r.eventType, &actor, &ip); err != nil {
			rows.Close()
			fmt.Fprintf(os.Stderr, "扫描失败: %v\n", err)
			os.Exit(1)
		}
		r.actor, r.ip = actor.String, ip.String
		recs = append(recs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "迭代失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("零值时间记录 %d 条：\n", len(recs))
	for _, r := range recs {
		fmt.Printf("  id=%-4d event_type=%-22s actor=%-6s ip=%s\n", r.id, r.eventType, r.actor, r.ip)
	}
	if len(recs) == 0 {
		fmt.Println("无需清理。")
		return
	}

	if !*apply {
		fmt.Println("dry-run：未做任何修改。确认后加 -apply 执行删除。")
		return
	}
	res, err := db.Exec(`DELETE FROM audit_log WHERE event_time = ?`, zeroEventTime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "删除失败: %v\n", err)
		os.Exit(1)
	}
	n, _ := res.RowsAffected()
	fmt.Printf("已删除 %d 条零值时间记录。\n", n)
}
