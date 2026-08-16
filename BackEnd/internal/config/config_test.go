package config

import (
	"os"
	"testing"
)

func TestParseDefaults(t *testing.T) {
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse(nil) 出错: %v", err)
	}
	if cfg.Listen != DefaultListen {
		t.Errorf("默认 Listen = %q, 期望 %q", cfg.Listen, DefaultListen)
	}
	if cfg.DataDir != DefaultDataDir {
		t.Errorf("默认 DataDir = %q, 期望 %q", cfg.DataDir, DefaultDataDir)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("默认 LogLevel = %q, 期望 info", cfg.LogLevel)
	}
	if cfg.LogFormat != "text" {
		t.Errorf("默认 LogFormat = %q, 期望 text", cfg.LogFormat)
	}
}

func TestParseFlags(t *testing.T) {
	cfg, err := Parse([]string{"-listen", "127.0.0.1:9999", "-data-dir", "/tmp/ac", "-log-level", "debug", "-log-format", "json"})
	if err != nil {
		t.Fatalf("Parse 出错: %v", err)
	}
	if cfg.Listen != "127.0.0.1:9999" || cfg.DataDir != "/tmp/ac" || cfg.LogLevel != "debug" || cfg.LogFormat != "json" {
		t.Errorf("flag 解析结果不符合预期: %+v", cfg)
	}
}

func TestParseEnvJWTSecret(t *testing.T) {
	t.Setenv(EnvJWTSecret, "env-secret-abc")
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse 出错: %v", err)
	}
	if cfg.JWTSecret != "env-secret-abc" {
		t.Errorf("JWTSecret = %q, 期望来自 env", cfg.JWTSecret)
	}
}

func TestParseInvalid(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"非法日志级别", []string{"-log-level", "verbose"}},
		{"非法日志格式", []string{"-log-format", "xml"}},
		{"空监听", []string{"-listen", ""}},
		{"监听缺端口", []string{"-listen", "127.0.0.1"}},
		{"空数据目录", []string{"-data-dir", ""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse(c.args); err == nil {
				t.Errorf("Parse(%v) 应报错，实际成功", c.args)
			}
		})
	}
}

func TestValidateEnvUnset(t *testing.T) {
	os.Unsetenv(EnvJWTSecret) // 确保不残留
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse 出错: %v", err)
	}
	if cfg.JWTSecret != "" {
		t.Errorf("未设置 env 时 JWTSecret 应为空，实际 %q", cfg.JWTSecret)
	}
}
