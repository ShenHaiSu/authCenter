package service

import (
	"strconv"
	"strings"
)

// 语义化版本比较（文档 04 §3.2 校验链第 4 步：min_version 可选）。
//
// 规则（宽松语义化，兼容 "1"、"1.2"、"1.2.3"）：
//   - 按点号分段，每段解析为无符号整数，缺省段补 0；
//   - 非数字段（如 "1.2.3-beta" 的预发布标记）忽略其后内容，仅比较数字主段；
//   - 返回 a >= b 是否成立。
//
// 说明：min_version 由管理员在管理界面配置，宽松解析避免误拒；
// 任何一段完全无法解析时视为 0（不构成限制）。

// versionAtLeast 判断 version 是否不低于 minVersion。
// 两者都为空时返回 true（无限制）。
func versionAtLeast(version, minVersion string) bool {
	if minVersion == "" {
		return true // 未配置最低版本：不限制
	}
	va := parseVersion(version)
	vb := parseVersion(minVersion)
	for i := 0; i < 3; i++ {
		if va[i] != vb[i] {
			return va[i] > vb[i]
		}
	}
	return true
}

// parseVersion 将版本串解析为 [major, minor, patch] 三段数字（缺省补 0）。
func parseVersion(v string) [3]uint64 {
	var out [3]uint64
	if v == "" {
		return out
	}
	// 去掉预发布/构建元数据后缀（"-beta" / "+build"），仅比较主三段。
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.ParseUint(parts[i], 10, 64)
		if err == nil {
			out[i] = n
		}
	}
	return out
}
