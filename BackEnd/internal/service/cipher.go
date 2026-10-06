// cipher.go — F-021 密钥存储加密（need01 03 §4.1~§4.4）。
//
// 职责：把「api_key.key_value 存明文还是密文」这一决策收口到 Cipher 接口，
// 所有读取路径统一走 ResolvePlain，避免模式判断散落各处（03 §4.4）。
//
// 红线：主密钥只来自环境变量 AUTHCENTER_KEY_ENC_KEY，不入库、不落盘、不进日志/审计/错误信息。
package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/authcenter/authcenter/internal/model"
)

// 密文常量（need01 03 §4.3）。
const (
	cipherVersion = "aes-256-gcm-v1"        // 与 model.KeyEncVersion 保持一致（未来轮换用）
	aadPrefix     = "authcenter:api_key:v1" // AAD 前缀，版本演进时可区分
	nonceLen      = 12                      // GCM 标准 nonce 长度
	tagLen        = 16                      // GCM tag 长度
	masterKeyLen  = 32                      // AES-256 主密钥长度
	minCipherLen  = nonceLen + tagLen       // 密文最短长度（空明文时）
)

// 解密相关哨兵错误（对外一律归一为 key_not_found，见 05 §3）。
var (
	// ErrCipherMalformed 密文格式非法（base64 解析失败或长度不足）。
	ErrCipherMalformed = errors.New("cipher malformed")
	// ErrCipherDecrypt 解密失败（主密钥不符、AAD 不匹配或密文被篡改）。
	ErrCipherDecrypt = errors.New("cipher decrypt failed")
)

// Cipher 密钥存储加解密接口。
//
// Open 接收调用方手里的「候选明文」：GCM 的 AAD 绑定了明文密钥本身（03 §4.3），
// 而解密前明文未知，因此只有认证路径（天然持有客户端提交的 key）需要 Open，
// 管理路径（列表/详情）永不展示明文，故无需解密。
type Cipher interface {
	Seal(plain string) (string, error)
	Open(stored, candidate string) (string, error)
	Enabled() bool
}

// PlainCipher 加密关闭时的空实现（透传）：模式 0 下 key_value 即明文。
type PlainCipher struct{}

// Seal 明文模式下不做任何变换。
func (PlainCipher) Seal(plain string) (string, error) { return plain, nil }

// Open 明文模式下 key_value 本身即明文，直接返回（兼容分支兜底用）。
func (PlainCipher) Open(stored, _ string) (string, error) { return stored, nil }

// Enabled 明文模式恒为 false。
func (PlainCipher) Enabled() bool { return false }

// GCMCipher AES-256-GCM 实现。
type GCMCipher struct {
	aead cipher.AEAD
}

// NewGCMCipher 用 32 字节主密钥构造 GCM 加密器。
func NewGCMCipher(masterKey []byte) (*GCMCipher, error) {
	if len(masterKey) != masterKeyLen {
		// 错误信息绝不包含密钥内容（03 §4.2 红线）。
		return nil, fmt.Errorf("主密钥长度为 %d 字节，要求 %d 字节", len(masterKey), masterKeyLen)
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("初始化 AES 失败: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("初始化 GCM 失败: %w", err)
	}
	return &GCMCipher{aead: aead}, nil
}

// Enabled GCM 实现恒为 true。
func (c *GCMCipher) Enabled() bool { return true }

// Version 返回密文格式版本（settings.key_encryption_version 展示用）。
func (c *GCMCipher) Version() string { return cipherVersion }

// Seal 加密：nonce(12B, crypto/rand) ‖ ciphertext ‖ tag(16B) → base64(StdEncoding)。
// AAD 绑定「版本前缀 + 明文密钥本身」，使密文与 key_hash 必须自洽（03 §4.3）。
func (c *GCMCipher) Seal(plain string) (string, error) {
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("生成 nonce 失败: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(plain), []byte(aadPrefix+plain))
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open 解密：用候选明文构造 AAD；解不开即视为无效（ErrCipherDecrypt）。
// 错误信息不含密文与候选明文（避免把密钥写进日志）。
func (c *GCMCipher) Open(stored, candidate string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(stored)
	if err != nil || len(raw) < minCipherLen {
		return "", ErrCipherMalformed
	}
	nonce, body := raw[:nonceLen], raw[nonceLen:]
	plain, err := c.aead.Open(nil, nonce, body, []byte(aadPrefix+candidate))
	if err != nil {
		return "", ErrCipherDecrypt
	}
	return string(plain), nil
}

// ParseMasterKey 解析主密钥：base64(标准编码) 解码后必须恰好 32 字节。
//   - 空字符串 → (nil, nil)：调用方装配 PlainCipher（未启用加密）；
//   - 长度不符 / 非法 base64 → 报错，启动失败（fail-fast，绝不静默降级为明文模式）。
//
// 错误信息只含长度，绝不含密钥内容。
func ParseMasterKey(b64 string) ([]byte, error) {
	if b64 == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("AUTHCENTER_KEY_ENC_KEY 不是合法 base64: %w", err)
	}
	if len(raw) != masterKeyLen {
		return nil, fmt.Errorf("AUTHCENTER_KEY_ENC_KEY 解码后为 %d 字节，要求 %d 字节", len(raw), masterKeyLen)
	}
	return raw, nil
}

// NewCipherFromEnv 按环境变量值装配 Cipher：空 → PlainCipher；非空 → GCMCipher。
// 长度非法直接返回错误（启动失败，03 §4.2 fail-fast）。
func NewCipherFromEnv(masterKeyB64 string) (Cipher, error) {
	key, err := ParseMasterKey(masterKeyB64)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return PlainCipher{}, nil
	}
	return NewGCMCipher(key)
}

// HashKey 计算认证索引键：hex(SHA-256(明文密钥))。
//
// 哈希选型说明（03 §2）：密钥是 40 位 A-Za-z0-9 随机串（熵 ≈238bit），
// 无需抗 GPU 暴力破解，故用快哈希；慢哈希会把认证主路径拖慢三个数量级。
func HashKey(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// ResolvePlain 统一还原某条密钥记录对应的明文，并校验与 key_hash 自洽。
//
//	mode 0：key_value 即明文，直接返回（不校验，保持旧行为）；
//	mode 1：用候选明文 candidate 走 GCM 解密；解密后必须与 key_hash 匹配，
//	        且与候选明文恒定时间比对一致（纵深防御）。
//
// 调用约定：只有认证路径调用（其他路径按现状永不返回明文，03 §4.4）。
func ResolvePlain(k *model.APIKey, c Cipher, candidate string) (string, error) {
	if k.KeyValueEnc == 0 {
		return k.KeyValue, nil
	}
	plain, err := c.Open(k.KeyValue, candidate)
	if err != nil {
		return "", ErrCipherDecrypt
	}
	if err != nil {
		return "", ErrCipherDecrypt
	}
	if HashKey(plain) != k.KeyHash || subtle.ConstantTimeCompare([]byte(plain), []byte(candidate)) != 1 {
		return "", ErrCipherDecrypt // 密文与哈希不自洽 → 视为无效
	}
	return plain, nil
}
