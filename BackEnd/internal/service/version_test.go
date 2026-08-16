package service

import "testing"

// versionAtLeast 语义化比较测试（文档 04 §3.2 校验链第 4 步）。
func TestVersionAtLeast(t *testing.T) {
	cases := []struct {
		name    string
		version string
		min     string
		want    bool
	}{
		{"无最低版本限制", "1.0.0", "", true},
		{"完全相等", "1.2.3", "1.2.3", true},
		{"高于最低", "2.0.0", "1.9.9", true},
		{"低于最低", "1.9.9", "2.0.0", false},
		{"缺省段补零相等", "1", "1.0.0", true},
		{"缺省段补零相等2", "1.2", "1.2.0", true},
		{"缺段低于", "1.9", "1.10.0", false},
		{"预发布后缀忽略", "1.2.3-beta.1", "1.2.0", true},
		{"构建元数据忽略", "1.2.3+build5", "1.2.3", true},
		{"两位版本高于三段", "1.10", "1.9.9", true},
		{"非法段视为0", "abc", "0.0.1", false},
		{"大版本号", "2026.01.01", "2025.12.31", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := versionAtLeast(c.version, c.min); got != c.want {
				t.Errorf("versionAtLeast(%q, %q) = %v, 期望 %v", c.version, c.min, got, c.want)
			}
		})
	}
}

// TestParseVersion 解析缺省段补 0 与后缀裁剪。
func TestParseVersion(t *testing.T) {
	if got := parseVersion("1.2"); got != [3]uint64{1, 2, 0} {
		t.Errorf("parseVersion(1.2) = %v", got)
	}
	if got := parseVersion("3"); got != [3]uint64{3, 0, 0} {
		t.Errorf("parseVersion(3) = %v", got)
	}
	if got := parseVersion("1.2.3-rc1"); got != [3]uint64{1, 2, 3} {
		t.Errorf("parseVersion(1.2.3-rc1) = %v", got)
	}
	if got := parseVersion(""); got != [3]uint64{0, 0, 0} {
		t.Errorf("parseVersion(空) = %v", got)
	}
}
