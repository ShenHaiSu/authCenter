// cipher_test.go — F-021 密钥存储加密单元测试（need01 03 §7.1）。
package service

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/authcenter/authcenter/internal/model"
)

// testMasterKey32 32 字节主密钥（测试固定值，非生产密钥）。
func testMasterKey32() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// testMasterKeyB64 32 字节主密钥的标准 base64。
func testMasterKeyB64() string { return base64.StdEncoding.EncodeToString(testMasterKey32()) }

// TestParseMasterKey 空 → nil；合法 32B → 32 字节；长度 16/31/33 与非法 base64 → 报错。
func TestParseMasterKey(t *testing.T) {
	if got, err := ParseMasterKey(""); err != nil || got != nil {
		t.Errorf("空字符串应返回 (nil, nil)，实际 (%v, %v)", got, err)
	}
	got, err := ParseMasterKey(testMasterKeyB64())
	if err != nil {
		t.Fatalf("合法 32B base64 应解析成功: %v", err)
	}
	if len(got) != 32 {
		t.Errorf("解码后长度 = %d, 期望 32", len(got))
	}
	for _, n := range []int{16, 31, 33} {
		b64 := base64.StdEncoding.EncodeToString(make([]byte, n))
		if _, err := ParseMasterKey(b64); err == nil {
			t.Errorf("%d 字节应报错", n)
		}
	}
	if _, err := ParseMasterKey("!!!not-base64!!!"); err == nil {
		t.Error("非法 base64 应报错")
	}
}

// TestParseMasterKeyNoSecretInError 错误信息绝不包含主密钥内容（03 §4.2 红线）。
func TestParseMasterKeyNoSecretInError(t *testing.T) {
	const bad = "c2hvcnQ=" // "short"：合法 base64 但长度不符
	_, err := ParseMasterKey(bad)
	if err == nil {
		t.Fatal("长度不符应报错")
	}
	if strings.Contains(err.Error(), bad) {
		t.Errorf("错误信息不应包含主密钥原文: %v", err)
	}
}

// TestNewCipherFromEnv 空 → PlainCipher；非空合法 → GCMCipher。
func TestNewCipherFromEnv(t *testing.T) {
	c, err := NewCipherFromEnv("")
	if err != nil {
		t.Fatalf("空主密钥不应报错: %v", err)
	}
	if c.Enabled() {
		t.Error("空主密钥应装配明文模式")
	}
	c2, err := NewCipherFromEnv(testMasterKeyB64())
	if err != nil {
		t.Fatalf("合法主密钥应装配成功: %v", err)
	}
	if !c2.Enabled() {
		t.Error("合法主密钥应装配 GCM 模式")
	}
}

// TestSealOpenRoundTrip Open(Seal(p), p) == p。
func TestSealOpenRoundTrip(t *testing.T) {
	c, err := NewGCMCipher(testMasterKey32())
	if err != nil {
		t.Fatal(err)
	}
	const plain = "AbCdEf0123456789AbCdEf0123456789AbCdEf01" // 40 位
	ct, err := c.Seal(plain)
	if err != nil {
		t.Fatalf("Seal 失败: %v", err)
	}
	if ct == plain {
		t.Error("密文不应等于明文")
	}
	got, err := c.Open(ct, plain)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	if got != plain {
		t.Errorf("往返后明文 = %q, 期望 %q", got, plain)
	}
}

// TestSealRandomNonce 同一明文两次加密 → 密文不同（nonce 随机）。
func TestSealRandomNonce(t *testing.T) {
	c, _ := NewGCMCipher(testMasterKey32())
	a, err := c.Seal("same-plaintext-key")
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Seal("same-plaintext-key")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("两次加密结果不应相同（nonce 必须随机）")
	}
}

// TestOpenWrongCandidate 用错误候选明文解 → ErrCipherDecrypt（AAD 绑定生效）。
func TestOpenWrongCandidate(t *testing.T) {
	c, _ := NewGCMCipher(testMasterKey32())
	ct, err := c.Seal("correct-key-value")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Open(ct, "wrong-key-value"); !errors.Is(err, ErrCipherDecrypt) {
		t.Errorf("错误候选明文应 ErrCipherDecrypt，实际 %v", err)
	}
}

// TestOpenWrongMasterKey 错误主密钥 → ErrCipherDecrypt。
func TestOpenWrongMasterKey(t *testing.T) {
	c1, _ := NewGCMCipher(testMasterKey32())
	other := make([]byte, 32)
	for i := range other {
		other[i] = 0xEE
	}
	c2, _ := NewGCMCipher(other)
	ct, err := c1.Seal("some-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Open(ct, "some-key"); !errors.Is(err, ErrCipherDecrypt) {
		t.Errorf("错误主密钥应 ErrCipherDecrypt，实际 %v", err)
	}
}

// TestOpenMalformed 非法 base64 / 长度不足 / 篡改 1 bit → ErrCipherMalformed 或 ErrCipherDecrypt。
func TestOpenMalformed(t *testing.T) {
	c, _ := NewGCMCipher(testMasterKey32())
	if _, err := c.Open("!!!not-base64!!!", "cand"); !errors.Is(err, ErrCipherMalformed) {
		t.Errorf("非法 base64 应 ErrCipherMalformed，实际 %v", err)
	}
	short := base64.StdEncoding.EncodeToString(make([]byte, 20)) // < 12+16
	if _, err := c.Open(short, "cand"); !errors.Is(err, ErrCipherMalformed) {
		t.Errorf("长度不足应 ErrCipherMalformed，实际 %v", err)
	}
	ct, err := c.Seal("tamper-me")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01 // 篡改 1 bit
	tampered := base64.StdEncoding.EncodeToString(raw)
	if _, err := c.Open(tampered, "tamper-me"); err == nil {
		t.Error("篡改密文应解密失败")
	}
}

// TestHashKeyStable 同一明文 hash 相同；40 位固定输入的期望 hex（回归锚点）。
func TestHashKeyStable(t *testing.T) {
	const plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd" // 40 位 A-Za-z0-9
	const want = "9185b616b75ed0c5438957aaa57cc89179ee8a4eec8bf71049317b7f3aba8f1c"
	if got := HashKey(plain); got != want {
		t.Errorf("HashKey(%q) = %q, 期望 %q", plain, got, want)
	}
	if HashKey(plain) != HashKey(plain) {
		t.Error("同一明文 hash 应稳定")
	}
	if HashKey("a") == HashKey("b") {
		t.Error("不同明文 hash 应不同")
	}
	if len(HashKey("x")) != 64 {
		t.Error("hash 应为 64 位 hex")
	}
}

// TestPlainCipherPassthrough PlainCipher.Seal 透传，Enabled() == false。
func TestPlainCipherPassthrough(t *testing.T) {
	var c Cipher = PlainCipher{}
	if c.Enabled() {
		t.Error("PlainCipher.Enabled() 应为 false")
	}
	got, err := c.Seal("plain-key")
	if err != nil || got != "plain-key" {
		t.Errorf("Seal 应透传，实际 (%q, %v)", got, err)
	}
	got, err = c.Open("plain-key", "candidate")
	if err != nil || got != "plain-key" {
		t.Errorf("Open 应透传，实际 (%q, %v)", got, err)
	}
}

// TestResolvePlainPlainMode key_value_enc=0 → 直接返回 key_value。
func TestResolvePlainPlainMode(t *testing.T) {
	k := &model.APIKey{KeyValue: "PLAIN-KEY-VALUE", KeyValueEnc: model.KeyEncPlain, KeyHash: HashKey("PLAIN-KEY-VALUE")}
	got, err := ResolvePlain(k, PlainCipher{}, "PLAIN-KEY-VALUE")
	if err != nil || got != "PLAIN-KEY-VALUE" {
		t.Errorf("明文模式应直接返回 key_value，实际 (%q, %v)", got, err)
	}
	// 明文模式下即便候选不符也按旧行为放行（语义与旧 GetKeyByValue 一致：查得到即命中）。
	if got, err := ResolvePlain(k, PlainCipher{}, "whatever"); err != nil || got != "PLAIN-KEY-VALUE" {
		t.Errorf("明文模式不校验候选，实际 (%q, %v)", got, err)
	}
}

// TestResolvePlainEncMode 密文 + 正确候选 → 明文；key_hash 被篡改 → 报错。
func TestResolvePlainEncMode(t *testing.T) {
	c, _ := NewGCMCipher(testMasterKey32())
	const plain = "Zz0123456789Zz0123456789Zz0123456789Zz01"
	ct, err := c.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	k := &model.APIKey{KeyValue: ct, KeyValueEnc: model.KeyEncGCM, KeyHash: HashKey(plain)}
	got, err := ResolvePlain(k, c, plain)
	if err != nil || got != plain {
		t.Fatalf("密文模式应还原明文，实际 (%q, %v)", got, err)
	}
	// 篡改 key_hash（模拟「改库指路」）→ 密文与哈希不自洽 → 报错。
	bad := *k
	bad.KeyHash = HashKey("another-key")
	if _, err := ResolvePlain(&bad, c, plain); !errors.Is(err, ErrCipherDecrypt) {
		t.Errorf("key_hash 被篡改应报错，实际 %v", err)
	}
	// 候选明文与密文不符 → 报错。
	if _, err := ResolvePlain(k, c, "not-the-key"); !errors.Is(err, ErrCipherDecrypt) {
		t.Errorf("候选明文不符应报错，实际 %v", err)
	}
}
