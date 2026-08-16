package web

import (
	"io/fs"
	"testing"
)

// TestEmbeddedAssets 验证 go:embed 内嵌资源完整性（文档 07 §2 前端内嵌机制）。
//
// 开发态 web/ 目录仅 .gitkeep（构建脚本发布期复制 FrontEnd/* 后才含页面，
// 07 §2.2），因此无 index.html 时跳过；有页面时断言关键资源齐全且非空。
func TestEmbeddedAssets(t *testing.T) {
	_, err := fs.Stat(WebFS, "index.html")
	if err != nil {
		t.Skip("web/ 无内嵌页面（开发态，仅 .gitkeep；构建脚本复制 FrontEnd/* 后生效）")
	}
	required := []string{
		"index.html", "login.html",
		"css/base.css", "css/auth.css",
		"js/api.js", "js/common.js", "js/login.js", "js/app.js",
		"js/dashboard.js", "js/projects.js", "js/keys.js", "js/audit.js",
	}
	for _, name := range required {
		info, err := fs.Stat(WebFS, name)
		if err != nil {
			t.Errorf("内嵌资源缺失 %s: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("内嵌资源为空文件: %s", name)
		}
	}
}

// TestAssetsTree Assets() 返回的 FS 可正常打开根路径资源。
func TestAssetsTree(t *testing.T) {
	a, err := Assets()
	if err != nil {
		t.Fatalf("Assets() 失败: %v", err)
	}
	_ = a // 树可用性由 http.FileServer 消费；此处仅验证不报错
}
