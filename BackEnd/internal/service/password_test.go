package service

import (
	"regexp"
	"strings"
	"testing"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	plain := "Sup3r-Secret-Pass!"
	hash, err := HashPassword(plain)
	if err != nil {
		t.Fatalf("HashPassword 出错: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Errorf("哈希格式不符合 argon2id 标准编码: %q", hash)
	}
	if !VerifyPassword(hash, plain) {
		t.Error("正确密码应校验通过")
	}
	if VerifyPassword(hash, "wrong-password") {
		t.Error("错误密码不应校验通过")
	}
	if VerifyPassword("not-a-hash", plain) {
		t.Error("非法哈希串不应校验通过")
	}
}

func TestHashPasswordEmpty(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Error("空密码应报错")
	}
}

func TestHashUniqueSalt(t *testing.T) {
	h1, _ := HashPassword("same-password")
	h2, _ := HashPassword("same-password")
	if h1 == h2 {
		t.Error("相同密码两次哈希应因随机 salt 而不同")
	}
}

func TestRandomStringLengthCharset(t *testing.T) {
	for _, n := range []int{1, 16, 30, 40, 128} {
		s, err := RandomString(n)
		if err != nil {
			t.Fatalf("RandomString(%d) 出错: %v", n, err)
		}
		if len(s) != n {
			t.Errorf("RandomString(%d) 长度 = %d", n, len(s))
		}
		if !regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString(s) {
			t.Errorf("RandomString(%d) 含非法字符: %q", n, s)
		}
	}
}

func TestRandomStringEntropyAndUnique(t *testing.T) {
	// 30 位（admin 初始密码）与 40 位（项目密钥）均应满足字符集与随机性。
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		s, err := RandomString(30)
		if err != nil {
			t.Fatalf("RandomString 出错: %v", err)
		}
		if seen[s] {
			t.Fatalf("重复随机串: %s", s)
		}
		seen[s] = true
	}
	// 字符分布粗查：200×30=6000 字符，62 字符集每位期望 ~97 次，不应有 0 出现。
	counts := make(map[byte]int)
	for s := range seen {
		for i := 0; i < len(s); i++ {
			counts[s[i]]++
		}
	}
	if len(counts) < 50 {
		t.Errorf("字符集覆盖不足：仅出现 %d/62 种字符", len(counts))
	}
}

func TestRandomStringInvalid(t *testing.T) {
	if _, err := RandomString(0); err == nil {
		t.Error("RandomString(0) 应报错")
	}
	if _, err := RandomString(-5); err == nil {
		t.Error("RandomString(-5) 应报错")
	}
}

func TestAdminPasswordLenConst(t *testing.T) {
	if AdminPasswordLen != 30 {
		t.Errorf("AdminPasswordLen 应为 30（文档 04 §3.1），实际 %d", AdminPasswordLen)
	}
}
