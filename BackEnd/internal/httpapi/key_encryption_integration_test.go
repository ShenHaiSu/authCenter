// key_encryption_integration_test.go — F-021 密钥存储加密端到端测试（need01 03 §7.2）。
package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/service"
	"github.com/authcenter/authcenter/internal/store"
)

// testKeyEncMasterKey 32 字节主密钥的 base64（测试固定值，非生产密钥）。
func testKeyEncMasterKey() string {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(0x40 + i)
	}
	return base64.StdEncoding.EncodeToString(k)
}

// itoa64 int64 → 十进制字符串（拼路径用）。
func itoa64(v int64) string { return strconv.FormatInt(v, 10) }

// sleepMs 毫秒级等待（自愈回填是异步 goroutine，测试轮询用）。
func sleepMs(ms int) { time.Sleep(time.Duration(ms) * time.Millisecond) }

// newEncTestClient 构造启用加密（已配置主密钥）的测试客户端。
func newEncTestClient(t *testing.T, setSettings ...func(context.Context, *store.Store)) *testClient {
	t.Helper()
	c, err := service.NewCipherFromEnv(testKeyEncMasterKey())
	if err != nil {
		t.Fatalf("装配 Cipher 失败: %v", err)
	}
	return newTestClientWithCipher(t, c, setSettings...)
}

// runBackfill 同步驱动一轮 key_hash 回填（模拟启动后的后台任务）。
func (c *testClient) runBackfill() {
	c.t.Helper()
	if _, err := c.maint.RunNow(context.Background(), "key_hash_backfill"); err != nil {
		c.t.Fatalf("key_hash 回填失败: %v", err)
	}
}

// clearHashes 把全部 key_hash 置空，模拟 F-021 之前的存量明文库。
func (c *testClient) clearHashes() {
	c.t.Helper()
	if _, err := c.st.DB().Exec(`UPDATE api_key SET key_hash = NULL`); err != nil {
		c.t.Fatalf("清空 key_hash 失败: %v", err)
	}
	c.apikeys.InvalidateBackfillCache()
}

// keyRow 读取单行密钥的落库形态。
func (c *testClient) keyRow(id int64) (keyValue string, enc int, hash string) {
	c.t.Helper()
	var h *string
	if err := c.st.DB().QueryRow(
		`SELECT key_value, key_value_enc, key_hash FROM api_key WHERE id = ?`, id).
		Scan(&keyValue, &enc, &h); err != nil {
		c.t.Fatalf("读取密钥行失败: %v", err)
	}
	if h != nil {
		hash = *h
	}
	return keyValue, enc, hash
}

// countNullHash 统计 key_hash 为空的行数。
func (c *testClient) countNullHash() int {
	c.t.Helper()
	var n int
	if err := c.st.DB().QueryRow(`SELECT count(*) FROM api_key WHERE key_hash IS NULL`).Scan(&n); err != nil {
		c.t.Fatalf("统计 key_hash 为空的行数失败: %v", err)
	}
	return n
}

// hasAuditDetailLike 判断指定事件类型是否存在 detail 含子串的审计（内部原因可能写多条）。
func (c *testClient) hasAuditDetailLike(eventType, substr string) bool {
	c.t.Helper()
	var n int
	if err := c.st.DB().QueryRow(
		`SELECT count(*) FROM audit_log WHERE event_type = ? AND detail LIKE ?`,
		eventType, "%"+substr+"%").Scan(&n); err != nil {
		c.t.Fatalf("查询 %s 审计失败: %v", eventType, err)
	}
	return n > 0
}

// lastAuditDetail 取指定事件类型最新一条审计的 detail。
func (c *testClient) lastAuditDetail(eventType string) string {
	c.t.Helper()
	var detail string
	if err := c.st.DB().QueryRow(
		`SELECT detail FROM audit_log WHERE event_type = ? ORDER BY id DESC LIMIT 1`, eventType).
		Scan(&detail); err != nil {
		c.t.Fatalf("读取 %s 审计失败: %v", eventType, err)
	}
	return detail
}

// TestKeyCreatedEncryptedWhenEnabled 启用态创建密钥 → 库里非明文、key_value_enc=1、
// key_hash 正确；响应仍返回一次明文（need01 03 §7.2）。
func TestKeyCreatedEncryptedWhenEnabled(t *testing.T) {
	c := newEncTestClient(t)
	c.login()
	pid := c.createProject("svc-enc")
	keyID, plain := c.createKeyReturn(pid, "生产", nil)

	if len(plain) != 40 {
		t.Fatalf("响应应返回 40 位明文密钥: %q", plain)
	}
	stored, enc, hash := c.keyRow(keyID)
	if enc != model.KeyEncGCM {
		t.Errorf("key_value_enc = %d, 期望 1（密文模式）", enc)
	}
	if stored == plain {
		t.Error("库中 key_value 不应等于明文")
	}
	if strings.Contains(stored, plain) {
		t.Error("库中密文不应包含明文片段")
	}
	if hash != service.HashKey(plain) {
		t.Errorf("key_hash = %q, 期望 %q", hash, service.HashKey(plain))
	}
	// 列表响应不得泄露密文串。
	rr := c.do(http.MethodGet, "/api/v1/projects/"+itoa64(pid)+"/keys", nil)
	if strings.Contains(rr.Body.String(), stored) {
		t.Error("密钥列表不应包含密文串")
	}
}

// TestAuthenticateWithEncryptedKey 用创建时的明文调用 /authenticate → code=0。
func TestAuthenticateWithEncryptedKey(t *testing.T) {
	c := newEncTestClient(t)
	c.login()
	pid := c.createProject("svc-enc-auth")
	_, plain := c.createKeyReturn(pid, "生产", nil)

	rr := c.doAuthenticate(map[string]any{
		"project_name": "svc-enc-auth", "version": "1.0.0", "fingerprint": "fp-enc", "key": plain,
	})
	resp := parseAuth(t, rr)
	if resp.Code != CodeOK || !resp.Data.Authenticated {
		t.Fatalf("加密模式下认证应成功: code=%d body=%s", resp.Code, rr.Body.String())
	}
}

// TestAuthenticateWrongKeyStillKeyNotFound 错误密钥 → 10004（对外语义不变）。
func TestAuthenticateWrongKeyStillKeyNotFound(t *testing.T) {
	c := newEncTestClient(t)
	c.login()
	pid := c.createProject("svc-enc-wrong")
	c.createKeyReturn(pid, "k1", nil)

	rr := c.doAuthenticate(map[string]any{
		"project_name": "svc-enc-wrong", "version": "1.0.0", "fingerprint": "fp",
		"key": "WRONG-KEY-0000000000000000000000000000000",
	})
	resp := parseAuth(t, rr)
	if resp.Code != authCodeKeyNotFound {
		t.Errorf("错误密钥应 10004，实际 %d", resp.Code)
	}
}

// TestAuthenticateTamperedHashFails 「改库指路」攻击：把某行 key_hash 指向攻击者密钥，
// 提交攻击者密钥 → hash 命中该行但密文/AAD 不自洽 → 认证失败 10004 +
// 审计 reason=decrypt_failed（03 §2 缓解措施 / §7.2）。
func TestAuthenticateTamperedHashFails(t *testing.T) {
	c := newEncTestClient(t)
	c.login()
	pid := c.createProject("svc-enc-tamper")
	keyID, _ := c.createKeyReturn(pid, "k1", nil)

	const attackerKey = "ATTACKER-KEY-00000000000000000000000000000"
	if _, err := c.st.DB().Exec(`UPDATE api_key SET key_hash = ? WHERE id = ?`,
		service.HashKey(attackerKey), keyID); err != nil {
		t.Fatalf("篡改 key_hash 失败: %v", err)
	}
	rr := c.doAuthenticate(map[string]any{
		"project_name": "svc-enc-tamper", "version": "1.0.0", "fingerprint": "fp", "key": attackerKey,
	})
	if resp := parseAuth(t, rr); resp.Code != authCodeKeyNotFound {
		t.Fatalf("密文与哈希不自洽应 10004，实际 %d", resp.Code)
	}
	// 内部原因进审计 detail（03 §4.4）：KeyForAuth 会额外写一条 reason=decrypt_failed，
	// auth_service 随后按对外语义补写 key_not_found（两条都在）。
	if !c.hasAuditDetailLike(model.EventAuthAuthenticateFailed, "decrypt_failed") {
		t.Error("审计应含 reason=decrypt_failed（密文与哈希不自洽的内部原因）")
	}
	if !c.hasAuditDetailLike(model.EventAuthAuthenticateFailed, "key_not_found") {
		t.Error("审计应含对外语义 reason=key_not_found")
	}
}

// TestRotateWithEncryption 轮换后：新密钥落库为密文、新旧明文在宽限期内都可用。
func TestRotateWithEncryption(t *testing.T) {
	c := newEncTestClient(t)
	c.login()
	pid := c.createProject("svc-enc-rotate")
	keyID, oldPlain := c.createKeyReturn(pid, "k1", nil)

	rr := c.do(http.MethodPost, "/api/v1/keys/"+itoa64(keyID)+"/rotate", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("轮换失败: %d %s", rr.Code, rr.Body.String())
	}
	var rotated struct {
		Data struct {
			NewKey           map[string]any `json:"new_key"`
			OldKeyGraceUntil *string        `json:"old_key_grace_until"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	newPlain, _ := rotated.Data.NewKey["key_value"].(string)
	newKeyID, _ := rotated.Data.NewKey["id"].(float64)
	if len(newPlain) != 40 {
		t.Fatalf("新密钥应为 40 位明文: %q", newPlain)
	}
	if rotated.Data.OldKeyGraceUntil == nil {
		t.Error("轮换应返回 old_key_grace_until")
	}
	// 新密钥落库为密文且 hash 正确。
	_, enc, hash := c.keyRow(int64(newKeyID))
	if enc != model.KeyEncGCM || hash != service.HashKey(newPlain) {
		t.Errorf("轮换新密钥落库形态不正确: enc=%d hash=%s", enc, hash)
	}
	// 新旧明文都可用（旧密钥在宽限期内）。
	for _, kv := range []string{newPlain, oldPlain} {
		rr := c.doAuthenticate(map[string]any{
			"project_name": "svc-enc-rotate", "version": "1.0.0", "fingerprint": "fp", "key": kv,
		})
		if resp := parseAuth(t, rr); resp.Code != CodeOK {
			t.Errorf("密钥 %q 应可认证，实际 code=%d", kv, resp.Code)
		}
	}
}

// TestKeyHashBackfillJobCompletes 构造存量明文库（key_hash 为 NULL）→ 兼容分支可认证；
// 回填 job 跑完 → state=done、全部行有 hash、审计 mode=backfill_hash；再次运行幂等。
func TestKeyHashBackfillJobCompletes(t *testing.T) {
	c := newTestClient(t)
	c.login()
	pid := c.createProject("svc-backfill")
	_, plain := c.createKeyReturn(pid, "存量", nil)

	// 模拟 F-021 之前的存量库：key_hash 全空。
	c.clearHashes()
	if n := c.countNullHash(); n != 1 {
		t.Fatalf("构造存量库失败：key_hash 为空的行数 = %d, 期望 1", n)
	}

	// 回填未完成：认证走兼容路径（明文等值查询）仍成功。
	rr := c.doAuthenticate(map[string]any{
		"project_name": "svc-backfill", "version": "1.0.0", "fingerprint": "fp", "key": plain,
	})
	if resp := parseAuth(t, rr); resp.Code != CodeOK {
		t.Fatalf("回填未完成期认证应成功（兼容分支）: code=%d", resp.Code)
	}

	// 上一步认证触发了自愈式回填（异步补 hash），这里重新清空以驱动完整回填流程。
	c.clearHashes()

	c.runBackfill()
	ctx := context.Background()
	state, err := c.st.GetSetting(ctx, model.SettingKeyHashBackfillState)
	if err != nil {
		t.Fatal(err)
	}
	if state != model.BackfillDone {
		t.Errorf("回填后 state = %q, 期望 done", state)
	}
	if doneAt, _ := c.st.GetSetting(ctx, model.SettingKeyHashBackfillDoneAt); doneAt == "" {
		t.Error("回填完成应写 key_hash_backfill_done_at")
	}
	if n := c.countNullHash(); n != 0 {
		t.Errorf("回填后仍有 %d 行缺 key_hash", n)
	}
	if detail := c.lastAuditDetail(model.EventSystemKeyEncryptionMigrated); !strings.Contains(detail, "backfill_hash") {
		t.Errorf("审计 detail 应含 mode=backfill_hash: %s", detail)
	}

	// 幂等：再次运行不重复回填。
	res, err := c.maint.RunNow(ctx, "key_hash_backfill")
	if err != nil {
		t.Fatalf("重复运行回填失败: %v", err)
	}
	if res.Affected != 0 {
		t.Errorf("重复运行应回填 0 行，实际 %d", res.Affected)
	}
	if reason, _ := res.Detail["reason"].(string); reason != "already_done" {
		t.Errorf("重复运行应返回 already_done，实际 %q", reason)
	}
	// 回填后认证仍成功（双路径等价）。
	rr = c.doAuthenticate(map[string]any{
		"project_name": "svc-backfill", "version": "1.0.0", "fingerprint": "fp", "key": plain,
	})
	if resp := parseAuth(t, rr); resp.Code != CodeOK {
		t.Errorf("回填后认证应成功: code=%d", resp.Code)
	}
}

// TestAuthenticateDuringBackfillPending 回填未完成期：存量明文密钥认证成功，
// 且自愈式回填会把该行 key_hash 补上（03 §4.4）。
func TestAuthenticateDuringBackfillPending(t *testing.T) {
	c := newTestClient(t)
	c.login()
	pid := c.createProject("svc-selfheal")
	keyID, plain := c.createKeyReturn(pid, "k1", nil)
	c.clearHashes()

	rr := c.doAuthenticate(map[string]any{
		"project_name": "svc-selfheal", "version": "1.0.0", "fingerprint": "fp", "key": plain,
	})
	if resp := parseAuth(t, rr); resp.Code != CodeOK {
		t.Fatalf("兼容分支认证应成功: code=%d", resp.Code)
	}
	// 自愈回填是异步 goroutine：轮询等待（最多 2s）。
	for i := 0; i < 40; i++ {
		if _, _, hash := c.keyRow(keyID); hash == service.HashKey(plain) {
			return
		}
		sleepMs(50)
	}
	_, _, hash := c.keyRow(keyID)
	t.Errorf("自愈回填未生效：key_hash = %q, 期望 %q", hash, service.HashKey(plain))
}

// TestEnableEndpointFlow POST /enable → 全部行变密文 + 认证仍成功 +
// 审计 system.key_encryption_migrated（mode=enable）；重复启用 → 409/20202。
func TestEnableEndpointFlow(t *testing.T) {
	c := newEncTestClient(t)
	c.login()
	pid := c.createProject("svc-enable")
	// 造一条存量明文行（模拟启用前创建的密钥）。
	keyID, plain := c.createKeyReturn(pid, "存量", nil)
	if _, err := c.st.DB().Exec(
		`UPDATE api_key SET key_value = ?, key_value_enc = 0, key_hash = NULL WHERE id = ?`,
		plain, keyID); err != nil {
		t.Fatalf("构造存量明文行失败: %v", err)
	}
	c.apikeys.InvalidateBackfillCache()
	c.runBackfill() // 前置条件：hash 回填完成

	rr := c.do(http.MethodPost, "/api/v1/settings/key-encryption/enable", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("启用加密失败: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			EncryptedRows int64  `json:"encrypted_rows"`
			Mode          string `json:"mode"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.EncryptedRows != 1 || resp.Data.Mode != "encrypted" {
		t.Errorf("启用结果不正确: %+v", resp.Data)
	}
	// 落库为密文。
	stored, enc, hash := c.keyRow(keyID)
	if enc != model.KeyEncGCM || stored == plain || hash != service.HashKey(plain) {
		t.Errorf("启用后落库形态不正确: enc=%d stored=%q hash=%q", enc, stored, hash)
	}
	// settings 键已写入。
	ctx := context.Background()
	if v, _ := c.st.GetSetting(ctx, model.SettingKeyEncryptionEnabled); v != "1" {
		t.Errorf("key_encryption_enabled = %q, 期望 1", v)
	}
	if v, _ := c.st.GetSetting(ctx, model.SettingKeyEncryptionVersion); v != model.KeyEncVersion {
		t.Errorf("key_encryption_version = %q, 期望 %q", v, model.KeyEncVersion)
	}
	// 认证仍成功（对外行为零变化）。
	rr = c.doAuthenticate(map[string]any{
		"project_name": "svc-enable", "version": "1.0.0", "fingerprint": "fp", "key": plain,
	})
	if r := parseAuth(t, rr); r.Code != CodeOK {
		t.Errorf("启用后认证应成功: code=%d", r.Code)
	}
	if detail := c.lastAuditDetail(model.EventSystemKeyEncryptionMigrated); !strings.Contains(detail, `"mode":"enable"`) {
		t.Errorf("审计 detail 应含 mode=enable: %s", detail)
	}
	// 重复启用 → 409/20202。
	rr = c.do(http.MethodPost, "/api/v1/settings/key-encryption/enable", nil)
	if rr.Code != http.StatusConflict || bodyCode(t, rr) != CodeStateConflict {
		t.Errorf("重复启用应 409/20202: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

// TestEnableEndpointRequiresMasterKey 未配置主密钥 → 409/20202（不静默降级）。
func TestEnableEndpointRequiresMasterKey(t *testing.T) {
	c := newTestClient(t)
	c.login()
	rr := c.do(http.MethodPost, "/api/v1/settings/key-encryption/enable", nil)
	if rr.Code != http.StatusConflict || bodyCode(t, rr) != CodeStateConflict {
		t.Fatalf("未配置主密钥应 409/20202: status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "AUTHCENTER_KEY_ENC_KEY") {
		t.Errorf("错误信息应提示未配置主密钥: %s", rr.Body.String())
	}
}

// TestEnableEndpointBlockedByPendingHash 回填未完成时禁止启用（03 §4.6 前置条件）。
func TestEnableEndpointBlockedByPendingHash(t *testing.T) {
	c := newEncTestClient(t)
	c.login()
	pid := c.createProject("svc-pending")
	c.createKeyReturn(pid, "k1", nil)
	c.clearHashes()

	rr := c.do(http.MethodPost, "/api/v1/settings/key-encryption/enable", nil)
	if rr.Code != http.StatusConflict || bodyCode(t, rr) != CodeStateConflict {
		t.Fatalf("回填未完成应 409/20202: status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "key_hash") {
		t.Errorf("错误信息应说明 key_hash 回填未完成: %s", rr.Body.String())
	}
}

// TestSettingsExposesKeyEncryption GET /settings 暴露加密状态（仅布尔与计数）。
func TestSettingsExposesKeyEncryption(t *testing.T) {
	c := newEncTestClient(t)
	c.login()
	rr := c.do(http.MethodGet, "/api/v1/settings", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /settings 失败: %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`"key_encryption_enabled"`, `"key_encryption_version"`, `"key_encrypted_count"`,
		`"master_key_configured":true`, `"mode":"encrypted"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("响应应含 %s: %s", want, body)
		}
	}
}

// TestSecretNeverLeaked 全链路抓响应/审计：不含主密钥、不含密钥明文与密文（03 §7.2）。
func TestSecretNeverLeaked(t *testing.T) {
	c := newEncTestClient(t)
	c.login()
	pid := c.createProject("svc-leak")
	keyID, plain := c.createKeyReturn(pid, "生产", nil)
	stored, _, _ := c.keyRow(keyID)
	master := testKeyEncMasterKey()

	paths := []string{
		"/api/v1/projects/" + itoa64(pid) + "/keys",
		"/api/v1/keys/" + itoa64(keyID),
		"/api/v1/settings",
		"/api/v1/audit-logs?size=100",
	}
	for _, p := range paths {
		body := c.do(http.MethodGet, p, nil).Body.String()
		if strings.Contains(body, master) {
			t.Errorf("%s 响应泄露主密钥", p)
		}
		if strings.Contains(body, plain) {
			t.Errorf("%s 响应泄露密钥明文", p)
		}
		if strings.Contains(body, stored) {
			t.Errorf("%s 响应泄露密文串", p)
		}
	}
	// 审计库面：任何 detail 都不得含明文/主密钥。
	rows, err := c.st.DB().Query(`SELECT event_type, detail FROM audit_log`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var ev string
		var detail *string
		if err := rows.Scan(&ev, &detail); err != nil {
			t.Fatal(err)
		}
		if detail == nil {
			continue
		}
		if strings.Contains(*detail, plain) || strings.Contains(*detail, master) {
			t.Errorf("审计 %s 泄露密钥内容: %s", ev, *detail)
		}
	}
}

// TestKeyHashBackfillWithoutMasterKey 回填不需要主密钥（明文库 + 无 env 也能完成）。
func TestKeyHashBackfillWithoutMasterKey(t *testing.T) {
	c := newTestClient(t)
	c.login()
	pid := c.createProject("svc-nomaster")
	_, plain := c.createKeyReturn(pid, "k1", nil)
	c.clearHashes()

	c.runBackfill()
	if state, _ := c.st.GetSetting(context.Background(), model.SettingKeyHashBackfillState); state != model.BackfillDone {
		t.Errorf("无主密钥时回填也应完成: state=%q", state)
	}
	rr := c.doAuthenticate(map[string]any{
		"project_name": "svc-nomaster", "version": "1.0.0", "fingerprint": "fp", "key": plain,
	})
	if resp := parseAuth(t, rr); resp.Code != CodeOK {
		t.Errorf("回填后认证应成功: code=%d", resp.Code)
	}
}
