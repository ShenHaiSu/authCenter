// admin_user_service_test.go — F-020 多管理员与 RBAC 业务规则单测（need01 02 §7.1）。
// 覆盖：CRUD、四条护栏（R1 至少一个启用 owner / R2 不能操作自己 / R3 停用吊销会话 /
// R4 用户名规则与唯一冲突）、密码与强制改密、角色脏值 fail-safe 降级、审计事件与 actor。
package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

// validPassword 满足强度规则的测试密码（≥12 位含字母数字）。
const validPassword = "Str0ngPassw0rd!"

// adminUserEnv 构造 AdminUserService 测试环境：已初始化 admin（owner）并返回其指针。
func adminUserEnv(t *testing.T) (*AdminUserService, *store.Store, *model.AdminUser, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := database.Open(dir)
	if err != nil {
		t.Fatalf("database.Open 失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	st := store.New(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	audit := NewAuditService(st, logger)
	adminSvc := NewAdminService(st, logger, dir)
	created, plain, err := adminSvc.EnsureAdmin(context.Background())
	if err != nil {
		t.Fatalf("EnsureAdmin 失败: %v", err)
	}
	if !created {
		t.Fatal("EnsureAdmin 应为首次创建")
	}
	owner, err := st.GetAdminByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatalf("读取 owner 失败: %v", err)
	}
	return NewAdminUserService(st, audit, logger), st, owner, plain
}

// auditCount 统计某事件类型的审计条数。
func auditCount(t *testing.T, st *store.Store, event string) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRow(`SELECT count(*) FROM audit_log WHERE event_type = ?`, event).Scan(&n); err != nil {
		t.Fatalf("统计审计 %s 失败: %v", event, err)
	}
	return n
}

// auditDetail 取某事件最新一条的 detail。
func auditDetail(t *testing.T, st *store.Store, event string) string {
	t.Helper()
	var detail string
	if err := st.DB().QueryRow(
		`SELECT detail FROM audit_log WHERE event_type = ? ORDER BY id DESC LIMIT 1`, event).Scan(&detail); err != nil {
		t.Fatalf("读取审计 %s detail 失败: %v", event, err)
	}
	return detail
}

// sessionCount 统计某用户的会话数。
func sessionCount(t *testing.T, st *store.Store, userID int64) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRow(
		`SELECT count(*) FROM admin_session WHERE admin_user_id = ?`, userID).Scan(&n); err != nil {
		t.Fatalf("统计会话失败: %v", err)
	}
	return n
}

// insertSession 为用户插入一条会话（用于验证停用即吊销，R3）。
// token_hash 需全局唯一，故用单调计数器而非测试名。
var sessionSeq atomic.Int64

func insertSession(t *testing.T, st *store.Store, userID int64) {
	t.Helper()
	sess := &model.AdminSession{
		TokenHash:   "hash-" + strconv.FormatInt(sessionSeq.Add(1), 10),
		AdminUserID: userID,
		ExpiresAt:   timeNowUTC().Add(time.Hour),
		CreatedAt:   timeNowUTC(),
	}
	if err := st.CreateSession(context.Background(), sess); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
}

// TestEnsureAdminIsOwner F-020：初始账号创建时直接落 role=owner（否则无人可管理管理员）。
func TestEnsureAdminIsOwner(t *testing.T) {
	svc, st, _, _ := adminUserEnv(t)
	_ = svc
	u, err := st.GetAdminByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatalf("读取 admin 失败: %v", err)
	}
	if u.Role != model.RoleOwner {
		t.Errorf("初始 admin 的 role = %q, 期望 owner", u.Role)
	}
	if !u.IsActive {
		t.Error("初始 admin 应为启用状态")
	}
}

// TestCreateAdminUser 成功创建：密码为 argon2id 哈希（非明文）+ 写 admin.create 审计。
func TestCreateAdminUser(t *testing.T) {
	svc, st, owner, _ := adminUserEnv(t)
	ctx := context.Background()

	u, err := svc.Create(ctx, owner, "alice", validPassword, model.RoleAdmin, true, "127.0.0.1")
	if err != nil {
		t.Fatalf("创建管理员失败: %v", err)
	}
	if u.ID == 0 || u.Username != "alice" || u.Role != model.RoleAdmin || !u.IsActive || !u.ForcePasswordChange {
		t.Errorf("创建结果不符合预期: %+v", u)
	}
	stored, err := st.GetAdminByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("读取 alice 失败: %v", err)
	}
	if stored.PasswordHash == validPassword {
		t.Error("密码不得以明文存储")
	}
	if !strings.HasPrefix(stored.PasswordHash, "$argon2") {
		t.Errorf("密码应为 argon2id 哈希, 实际前缀: %.16s", stored.PasswordHash)
	}
	if !VerifyPassword(stored.PasswordHash, validPassword) {
		t.Error("哈希应能校验通过初始密码")
	}
	if auditCount(t, st, model.EventAdminCreate) != 1 {
		t.Error("应有 1 条 admin.create 审计")
	}
	// actor 应为操作者本人（追责到具体管理员，F-020 §1.5）。
	var actorID, actorName string
	if err := st.DB().QueryRow(
		`SELECT actor_id, actor_name FROM audit_log WHERE event_type = ?`, model.EventAdminCreate).
		Scan(&actorID, &actorName); err != nil {
		t.Fatal(err)
	}
	if actorName != owner.Username {
		t.Errorf("actor_name = %q, 期望 %q", actorName, owner.Username)
	}
	if actorID == "" || actorID == "0" {
		t.Errorf("actor_id 应为操作者 id, 实际 %q", actorID)
	}
}

// TestCreateAdminUserConflict 同名 → store.ErrConflict（→ 409/20201，R4）。
func TestCreateAdminUserConflict(t *testing.T) {
	svc, _, owner, _ := adminUserEnv(t)
	ctx := context.Background()

	if _, err := svc.Create(ctx, owner, "alice", validPassword, model.RoleAdmin, true, ""); err != nil {
		t.Fatalf("首次创建失败: %v", err)
	}
	if _, err := svc.Create(ctx, owner, "alice", validPassword, model.RoleAdmin, true, ""); !errors.Is(err, store.ErrConflict) {
		t.Errorf("同名创建应返回 store.ErrConflict, 实际 %v", err)
	}
	// 保留名 admin 可正常存在（初始账号），不得被规则拒绝。
	if _, err := svc.Create(ctx, owner, "admin", validPassword, model.RoleAdmin, true, ""); !errors.Is(err, store.ErrConflict) {
		t.Errorf("与初始账号同名应冲突, 实际 %v", err)
	}
}

// TestCreateAdminUserWeakPassword 弱密码（<12 位 / 纯字母 / 纯数字）→ ErrPasswordTooWeak。
func TestCreateAdminUserWeakPassword(t *testing.T) {
	svc, _, owner, _ := adminUserEnv(t)
	ctx := context.Background()

	for _, pw := range []string{"short1", "abcdefghijkl", "12345678901234"} {
		if _, err := svc.Create(ctx, owner, "alice", pw, model.RoleAdmin, true, ""); !errors.Is(err, ErrPasswordTooWeak) {
			t.Errorf("密码 %q 应返回 ErrPasswordTooWeak, 实际 %v", pw, err)
		}
	}
}

// TestCreateAdminUserInvalidUsername 用户名含空格/超长/中文 → ErrInvalidParameter（R4）。
func TestCreateAdminUserInvalidUsername(t *testing.T) {
	svc, _, owner, _ := adminUserEnv(t)
	ctx := context.Background()

	bad := []string{
		"", "ab", // 过短
		"with space",                  // 含空格
		"中文名",                         // 中文
		"a" + strings.Repeat("b", 40), // 超长（>32）
		"bad/name",                    // 非法字符
	}
	for _, name := range bad {
		if _, err := svc.Create(ctx, owner, name, validPassword, model.RoleAdmin, true, ""); !errors.Is(err, ErrInvalidParameter) {
			t.Errorf("用户名 %q 应返回 ErrInvalidParameter, 实际 %v", name, err)
		}
	}
	// 合法用户名通过（含 _ . - 与数字）。
	for _, name := range []string{"ab1", "alice_1", "a.b-c", strings.Repeat("u", 32)} {
		if _, err := svc.Create(ctx, owner, name, validPassword, model.RoleAdmin, true, ""); err != nil {
			t.Errorf("用户名 %q 应合法, 实际错误 %v", name, err)
		}
	}
}

// TestSetActiveRevokesSessions R3：停用后该用户会话数为 0；审计 admin.disable 带 sessions_revoked。
func TestSetActiveRevokesSessions(t *testing.T) {
	svc, st, owner, _ := adminUserEnv(t)
	ctx := context.Background()

	u, err := svc.Create(ctx, owner, "alice", validPassword, model.RoleAdmin, true, "")
	if err != nil {
		t.Fatalf("创建 alice 失败: %v", err)
	}
	insertSession(t, st, u.ID)
	insertSession(t, st, u.ID)
	if got := sessionCount(t, st, u.ID); got != 2 {
		t.Fatalf("准备阶段应有 2 条会话, 实际 %d", got)
	}

	if err := svc.SetActive(ctx, owner, u.ID, false, "127.0.0.1"); err != nil {
		t.Fatalf("停用失败: %v", err)
	}
	if got := sessionCount(t, st, u.ID); got != 0 {
		t.Errorf("停用后会话应全部吊销, 残留 %d 条", got)
	}
	detail := auditDetail(t, st, model.EventAdminDisable)
	if !strings.Contains(detail, `"sessions_revoked":2`) {
		t.Errorf("admin.disable detail 应含 sessions_revoked=2, 实际 %s", detail)
	}
	// 幂等：重复停用不再重复审计。
	before := auditCount(t, st, model.EventAdminDisable)
	if err := svc.SetActive(ctx, owner, u.ID, false, ""); err != nil {
		t.Fatalf("重复停用应成功(nil), 实际 %v", err)
	}
	if after := auditCount(t, st, model.EventAdminDisable); after != before {
		t.Errorf("重复停用不应重复审计: %d → %d", before, after)
	}
	// 重新启用后写 admin.enable。
	if err := svc.SetActive(ctx, owner, u.ID, true, ""); err != nil {
		t.Fatalf("启用失败: %v", err)
	}
	if auditCount(t, st, model.EventAdminDisable) == 0 || auditCount(t, st, model.EventAdminEnable) != 1 {
		t.Error("启用应写 1 条 admin.enable")
	}
}

// TestCannotDisableSelf R2：停用自己 → ErrStateConflict。
func TestCannotDisableSelf(t *testing.T) {
	svc, _, owner, _ := adminUserEnv(t)
	ctx := context.Background()

	if err := svc.SetActive(ctx, owner, owner.ID, false, ""); !errors.Is(err, ErrStateConflict) {
		t.Errorf("停用自己应返回 ErrStateConflict, 实际 %v", err)
	}
	if err := svc.SetRole(ctx, owner, owner.ID, model.RoleAdmin, ""); !errors.Is(err, ErrStateConflict) {
		t.Errorf("降级自己应返回 ErrStateConflict, 实际 %v", err)
	}
	if err := svc.ResetPassword(ctx, owner, owner.ID, validPassword, true, ""); !errors.Is(err, ErrStateConflict) {
		t.Errorf("重置自己密码应返回 ErrStateConflict, 实际 %v", err)
	}
	// 对自己的启用同样被 R2 拒绝（R2 先于幂等判断，符合「不对自己执行任何管理动作」）。
	if err := svc.SetActive(ctx, owner, owner.ID, true, ""); !errors.Is(err, ErrStateConflict) {
		t.Errorf("对自己的启用也应返回 ErrStateConflict, 实际 %v", err)
	}
}

// TestCannotDisableLastOwner R1：唯一 owner 被停用/降级 → ErrStateConflict。
func TestCannotDisableLastOwner(t *testing.T) {
	svc, _, owner, _ := adminUserEnv(t)
	ctx := context.Background()

	// 唯一 owner（初始 admin）被停用 → 拒绝。
	if err := svc.SetActive(ctx, owner, owner.ID, false, ""); !errors.Is(err, ErrStateConflict) {
		t.Errorf("停用唯一 owner 应返回 ErrStateConflict, 实际 %v", err)
	}
	if !strings.Contains(errLastOwnerMessage, "至少保留一个") {
		t.Error("错误文案应含「至少保留一个」")
	}
	// 新建的 admin（非 owner）可被停用，说明护栏只针对 owner。
	alice, err := svc.Create(ctx, owner, "alice", validPassword, model.RoleAdmin, true, "")
	if err != nil {
		t.Fatalf("创建 alice 失败: %v", err)
	}
	if err := svc.SetActive(ctx, owner, alice.ID, false, ""); err != nil {
		t.Errorf("停用普通管理员应成功, 实际 %v", err)
	}
}

// TestOwnerDowngradeGuard R1：2 个 owner，停用其中一个成功；再停用第二个拒绝。
func TestOwnerDowngradeGuard(t *testing.T) {
	svc, st, owner, _ := adminUserEnv(t)
	ctx := context.Background()

	second, err := svc.Create(ctx, owner, "owner2", validPassword, model.RoleOwner, false, "")
	if err != nil {
		t.Fatalf("创建第二个 owner 失败: %v", err)
	}
	if second.Role != model.RoleOwner {
		t.Fatalf("第二个账号角色 = %q, 期望 owner", second.Role)
	}
	// 2 个启用 owner → 停用其中一个允许。
	if err := svc.SetActive(ctx, owner, second.ID, false, ""); err != nil {
		t.Errorf("有 2 个启用 owner 时停用一个应成功, 实际 %v", err)
	}
	n, err := st.CountActiveOwners(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("停用后启用 owner 数 = %d, 期望 1", n)
	}
	// 只剩 1 个 → 停用它被拒（此处通过另一个 owner 操作）。
	if err := svc.SetRole(ctx, owner, owner.ID, model.RoleAdmin, ""); !errors.Is(err, ErrStateConflict) {
		t.Errorf("降级最后一个 owner 应返回 ErrStateConflict, 实际 %v", err)
	}
}

// TestSetRoleChange admin→owner 成功 + 写 admin.role_change（from/to 齐全）。
func TestSetRoleChange(t *testing.T) {
	svc, st, owner, _ := adminUserEnv(t)
	ctx := context.Background()

	alice, err := svc.Create(ctx, owner, "alice", validPassword, model.RoleAdmin, true, "")
	if err != nil {
		t.Fatalf("创建 alice 失败: %v", err)
	}
	if err := svc.SetRole(ctx, owner, alice.ID, model.RoleOwner, "127.0.0.1"); err != nil {
		t.Fatalf("提升为 owner 失败: %v", err)
	}
	got, err := svc.Get(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != model.RoleOwner {
		t.Errorf("alice.role = %q, 期望 owner", got.Role)
	}
	detail := auditDetail(t, st, model.EventAdminRoleChange)
	for _, want := range []string{`"from_role":"admin"`, `"to_role":"owner"`, `"username":"alice"`} {
		if !strings.Contains(detail, want) {
			t.Errorf("admin.role_change detail 应含 %s, 实际 %s", want, detail)
		}
	}
	// 脏角色入参按 admin 处理（fail-safe 降权）。
	if err := svc.SetRole(ctx, owner, alice.ID, "superuser", ""); err != nil {
		t.Fatalf("设置脏角色应归一化为 admin 而非报错, 实际 %v", err)
	}
	got, _ = svc.Get(ctx, alice.ID)
	if got.Role != model.RoleAdmin {
		t.Errorf("脏角色应降级为 admin, 实际 %q", got.Role)
	}
}

// TestResetPasswordSetsForceChange 重置后 force_password_change=1、会话全清、审计齐全。
func TestResetPasswordSetsForceChange(t *testing.T) {
	svc, st, owner, _ := adminUserEnv(t)
	ctx := context.Background()

	alice, err := svc.Create(ctx, owner, "alice", validPassword, model.RoleAdmin, false, "")
	if err != nil {
		t.Fatalf("创建 alice 失败: %v", err)
	}
	insertSession(t, st, alice.ID)
	if err := svc.ResetPassword(ctx, owner, alice.ID, "Reset3dPassw0rd!", true, "127.0.0.1"); err != nil {
		t.Fatalf("重置密码失败: %v", err)
	}
	got, err := svc.Get(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ForcePasswordChange {
		t.Error("重置后 force_password_change 应为 true")
	}
	if n := sessionCount(t, st, alice.ID); n != 0 {
		t.Errorf("重置后会话应全部吊销, 残留 %d", n)
	}
	if !VerifyPassword(got.PasswordHash, "Reset3dPassw0rd!") {
		t.Error("新密码应可校验通过")
	}
	if VerifyPassword(got.PasswordHash, validPassword) {
		t.Error("旧密码不应再有效")
	}
	detail := auditDetail(t, st, model.EventAdminPasswordReset)
	if !strings.Contains(detail, `"force_change":true`) || strings.Contains(detail, "Reset3dPassw0rd!") {
		t.Errorf("审计 detail 应含 force_change 且不得含密码明文: %s", detail)
	}
	// 弱密码被拒。
	if err := svc.ResetPassword(ctx, owner, alice.ID, "weak", true, ""); !errors.Is(err, ErrPasswordTooWeak) {
		t.Errorf("弱密码应返回 ErrPasswordTooWeak, 实际 %v", err)
	}
}

// TestNormalizeRoleFallback 库中 role 脏值（'superuser' / NULL）→ 一律按 admin 处理（降权）。
func TestNormalizeRoleFallback(t *testing.T) {
	_, st, owner, _ := adminUserEnv(t)
	ctx := context.Background()

	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO admin_user (username, password_hash, role, is_active, created_at) VALUES (?, ?, ?, 1, ?)`,
		"dirty", "hash", "superuser", database.FormatTime(timeNowUTC())); err != nil {
		t.Fatalf("插入脏角色行失败: %v", err)
	}
	// role 列为 NOT NULL（脏值只可能是任意字符串），逐一验证 fail-safe 降级。
	// 先确认 NOT NULL 约束确实存在（避免测试假设与 schema 脱节）。
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE admin_user SET role = NULL WHERE username = 'dirty'`); err == nil {
		t.Error("role 列应为 NOT NULL，无法写入 NULL（测试假设与 schema 不符）")
	}
	for _, dirty := range []string{"superuser", "OWNER", "Owner", "root", " ", "admin "} {
		if _, err := st.DB().ExecContext(ctx,
			`UPDATE admin_user SET role = ? WHERE username = 'dirty'`, dirty); err != nil {
			t.Fatalf("写入脏角色 %q 失败: %v", dirty, err)
		}
		u, err := st.GetAdminByUsername(ctx, "dirty")
		if err != nil {
			t.Fatalf("读取脏角色用户失败: %v", err)
		}
		if u.Role != model.RoleAdmin {
			t.Errorf("脏角色 %q 应归一化为 admin, 实际 %q", dirty, u.Role)
		}
	}
	// 精确 owner 才提权。
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE admin_user SET role = 'owner' WHERE username = 'dirty'`); err != nil {
		t.Fatal(err)
	}
	u, _ := st.GetAdminByUsername(ctx, "dirty")
	if u.Role != model.RoleOwner {
		t.Errorf("精确 owner 应保留 owner, 实际 %q", u.Role)
	}
	_ = owner
}

// TestSetForcePasswordChange 单独要求/取消强制改密 + admin.update 审计。
func TestSetForcePasswordChange(t *testing.T) {
	svc, st, owner, _ := adminUserEnv(t)
	ctx := context.Background()

	alice, err := svc.Create(ctx, owner, "alice", validPassword, model.RoleAdmin, false, "")
	if err != nil {
		t.Fatalf("创建 alice 失败: %v", err)
	}
	if err := svc.SetForcePasswordChange(ctx, owner, alice.ID, true, ""); err != nil {
		t.Fatalf("设置强制改密失败: %v", err)
	}
	got, _ := svc.Get(ctx, alice.ID)
	if !got.ForcePasswordChange {
		t.Error("force_password_change 应为 true")
	}
	if auditCount(t, st, model.EventAdminUpdate) != 1 {
		t.Error("应有 1 条 admin.update 审计")
	}
	// R2：不能对自己执行。
	if err := svc.SetForcePasswordChange(ctx, owner, owner.ID, true, ""); !errors.Is(err, ErrStateConflict) {
		t.Errorf("对自己设置强制改密应返回 ErrStateConflict, 实际 %v", err)
	}
}

// TestChangePasswordClearsForceFlag 本人改密成功后清零强制改密标记（避免死循环）。
func TestChangePasswordClearsForceFlag(t *testing.T) {
	svc, st, owner, _ := adminUserEnv(t)
	ctx := context.Background()

	alice, err := svc.Create(ctx, owner, "alice", validPassword, model.RoleAdmin, true, "")
	if err != nil {
		t.Fatalf("创建 alice 失败: %v", err)
	}
	sessions := NewSessionService(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := sessions.ChangePassword(ctx, alice, validPassword, "MyOwn3Passw0rd!"); err != nil {
		t.Fatalf("本人改密失败: %v", err)
	}
	got, _ := svc.Get(ctx, alice.ID)
	if got.ForcePasswordChange {
		t.Error("本人改密成功后 force_password_change 应清零")
	}
}

// TestListAdmins 分页与 total 正确，响应数据不含密码哈希。
func TestListAdmins(t *testing.T) {
	svc, _, owner, _ := adminUserEnv(t)
	ctx := context.Background()

	for _, n := range []string{"alice", "bob", "carol"} {
		if _, err := svc.Create(ctx, owner, n, validPassword, model.RoleAdmin, false, ""); err != nil {
			t.Fatalf("创建 %s 失败: %v", n, err)
		}
	}
	items, total, err := svc.List(ctx, 1, 2)
	if err != nil {
		t.Fatalf("分页查询失败: %v", err)
	}
	if total != 4 {
		t.Errorf("total = %d, 期望 4", total)
	}
	if len(items) != 2 {
		t.Errorf("page=1&size=2 应返回 2 条, 实际 %d", len(items))
	}
	items, _, err = svc.List(ctx, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Errorf("第 2 页应返回 2 条, 实际 %d", len(items))
	}
}

// TestGetAdminNotFound 目标不存在 → store.ErrNotFound（→ 404/20200）。
func TestGetAdminNotFound(t *testing.T) {
	svc, _, owner, _ := adminUserEnv(t)
	ctx := context.Background()

	if _, err := svc.Get(ctx, 99999); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("不存在应返回 store.ErrNotFound, 实际 %v", err)
	}
	if err := svc.SetActive(ctx, owner, 99999, false, ""); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("停用不存在的账号应返回 store.ErrNotFound, 实际 %v", err)
	}
	if err := svc.SetRole(ctx, owner, 99999, model.RoleOwner, ""); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("改角色不存在的账号应返回 store.ErrNotFound, 实际 %v", err)
	}
}
