package config

import "testing"

// BenchmarkConfigParse 测启动时配置解析开销（含 flag 解析 + validate）。
// M1 启动自检路径：每次进程启动执行一次，成本应可忽略。
func BenchmarkConfigParse(b *testing.B) {
	args := []string{"-listen", "127.0.0.1:53779", "-data-dir", "data",
		"-log-level", "info", "-log-format", "text", "-web-dir", ""}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Parse(args); err != nil {
			b.Fatal(err)
		}
	}
}
