// Package web 内嵌前端静态资源（后端架构文档 07 §2 前端内嵌机制）。
//
// 约束：go:embed 只能嵌入模块目录内文件，前端源文件在仓库根 FrontEnd/（模块外），
// 因此由构建脚本在发布期复制 FrontEnd/* → 本目录（保留 .gitkeep）后再编译
// （见 build.ps1/build.sh，文档 07 §2.2）。
//
// 开发模式：`go run ./cmd/authcenter -web-dir ../FrontEnd` 直接从磁盘目录服务前端，
// 不经过本内嵌（文档 07 §2.3 / 04 §2）。
package web

import (
	"embed"
	"io/fs"
)

// WebFS 内嵌的前端静态资源。
//
// 构建脚本将 FrontEnd/* 复制到本目录（与 embed.go 同级），因此用 `all:*`
// 匹配目录内全部文件（含隐藏文件如 .gitkeep）。路径前缀与本目录一致，
// 无需再剥离（见 Assets）。
//
//go:embed all:*
var WebFS embed.FS

// Assets 返回内嵌静态资源树，供 http.FileServer 直接使用。
// 内嵌目录为空（仅 .gitkeep，开发态）时也能安全返回。
func Assets() (fs.FS, error) {
	return fs.FS(WebFS), nil
}
