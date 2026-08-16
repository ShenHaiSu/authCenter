// Package service 业务层：纯逻辑，不感知 HTTP（文档 04 §1 依赖规则）。
package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id 参数（文档 06 §3.1）：memory=64MB, iterations=3, parallelism=2, salt=16B, key=32B。
const (
	argonMemory      = 64 * 1024 // 64 MiB（单位 KiB）
	argonIterations  = 3
	argonParallelism = 2
	argonSaltLen     = 16
	argonKeyLen      = 32
)

// HashPassword 使用 argon2id 哈希密码，返回标准编码串：
// $argon2id$v=19$m=65536,t=3,p=2$<salt_b64>$<hash_b64>
func HashPassword(plain string) (string, error) {
	if plain == "" {
		return "", fmt.Errorf("密码不能为空")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("生成 salt 失败: %w", err)
	}
	hash := argon2.IDKey([]byte(plain), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)
	enc := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonIterations, argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))
	return enc, nil
}

// VerifyPassword 校验密码与哈希串是否匹配（按串内参数重算，文档 06 §3.1）。
func VerifyPassword(hash, plain string) bool {
	parts := strings.Split(hash, "$")
	// ["", "argon2id", "v=19", "m=65536,t=3,p=2", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var memory uint32
	var iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(plain), salt, iterations, memory, parallelism, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// randomCharset 30 位 admin 初始密码字符集（A-Za-z0-9 共 62 种，文档 04 §3.1）。
const randomCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// RandomString 用 crypto/rand 生成 n 位随机字符串（字符集 A-Za-z0-9，索引均匀无偏）。
func RandomString(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("长度必须为正: %d", n)
	}
	buf := make([]byte, n)
	// 拒绝采样保证均匀：2^8=256，256/62 有余数，取 62 的最大倍数区间 0..247。
	const max = 256 - (256 % len(randomCharset))
	for i := 0; i < n; {
		tmp := make([]byte, n-i)
		if _, err := rand.Read(tmp); err != nil {
			return "", fmt.Errorf("随机数生成失败: %w", err)
		}
		for _, b := range tmp {
			if int(b) < max {
				buf[i] = randomCharset[int(b)%len(randomCharset)]
				i++
				if i == n {
					break
				}
			}
		}
	}
	return string(buf), nil
}
