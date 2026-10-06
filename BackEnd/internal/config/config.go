// Package config 解析运行配置：flag 优先，环境变量补充。
// 无配置文件依赖，保持单二进制简洁（见后端架构文档 04 §2）。
package config

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Defaults 与文档一致（后端架构文档 04 §2）。
const (
	DefaultListen   = "127.0.0.1:53779"
	DefaultDataDir  = "data"
	DefaultLogLevel = "info"
	DefaultLogFmt   = "text"

	// EnvJWTSecret 用于覆盖 settings.jwt_secret（备份恢复场景必需）。
	EnvJWTSecret = "AUTHCENTER_JWT_SECRET"
	// EnvKeyEncKey F-021 密钥存储加密主密钥（base64(32B)）。
	// 只来自环境变量：不入库、不落盘、不进日志/审计（need01 03 §4.2/§4.8）。
	EnvKeyEncKey = "AUTHCENTER_KEY_ENC_KEY"
)

// Config 汇总运行配置。
type Config struct {
	Listen      string // 监听地址，需求固定本机 127.0.0.1:53779（C2）
	DataDir     string // 数据目录（db + auth.log）
	LogLevel    string // debug/info/warn/error
	LogFormat   string // text/json
	WebDir      string // 开发模式：从磁盘目录服务前端静态文件；空=不启用
	JWTSecret   string // 来自 env AUTHCENTER_JWT_SECRET，可覆盖 settings 中自动生成值
	KeyEncKey   string // 来自 env AUTHCENTER_KEY_ENC_KEY，base64(32B)；空=明文模式
	MigrateOnly bool   // 只做迁移与自检后退出，不监听端口（need01 06 §3.4）
}

// Parse 解析命令行 flag 与环境变量。
func Parse(args []string) (*Config, error) {
	fs := flag.NewFlagSet("authcenter", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "AuthCenter 中心认证服务（M1 骨架）\n\n用法: authcenter [flags]\n\nflags:\n")
		fs.PrintDefaults()
	}

	var cfg Config
	fs.StringVar(&cfg.Listen, "listen", DefaultListen, "监听地址（需求固定本机，一般不改）")
	fs.StringVar(&cfg.DataDir, "data-dir", DefaultDataDir, "数据目录（db + 日志）")
	fs.StringVar(&cfg.LogLevel, "log-level", DefaultLogLevel, "日志级别 debug/info/warn/error")
	fs.StringVar(&cfg.LogFormat, "log-format", DefaultLogFmt, "日志格式 text/json")
	fs.StringVar(&cfg.WebDir, "web-dir", "", "开发模式：从磁盘目录服务前端静态文件（默认内嵌）")
	fs.BoolVar(&cfg.MigrateOnly, "migrate-only", false, "只执行数据库迁移与自检后退出，不启动 HTTP 服务")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	cfg.JWTSecret = os.Getenv(EnvJWTSecret)
	cfg.KeyEncKey = os.Getenv(EnvKeyEncKey)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate 校验配置合法性。
func (c *Config) Validate() error {
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("非法 -log-level %q（可选 debug/info/warn/error）", c.LogLevel)
	}
	switch c.LogFormat {
	case "text", "json":
	default:
		return fmt.Errorf("非法 -log-format %q（可选 text/json）", c.LogFormat)
	}
	if c.Listen == "" {
		return fmt.Errorf("-listen 不能为空")
	}
	if !strings.Contains(c.Listen, ":") {
		return fmt.Errorf("-listen 缺少端口：%q（应为 host:port，如 127.0.0.1:53779）", c.Listen)
	}
	if c.DataDir == "" {
		return fmt.Errorf("-data-dir 不能为空")
	}
	return nil
}
