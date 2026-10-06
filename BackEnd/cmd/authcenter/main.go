// Command authcenter 是 AuthCenter 中心认证服务入口（M1 骨架）。
//
// 启动流程（后端架构文档 02 §6）：
//  1. 解析配置（flag + env）
//  2. 初始化结构化日志（slog）
//  3. 打开 SQLite + PRAGMA + 迁移
//  4. 初始化 store
//  5. 写 system.startup 审计
//  6. 幂等初始化 admin（控制台打印 + auth.log 落盘）
//  7. 生成/读取 JWT secret（settings，env 可覆盖）
//  8. 装配路由与中间件，http.Server 监听 127.0.0.1:53779
//  9. 优雅关闭（SIGINT/SIGTERM）
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/authcenter/authcenter/internal/config"
	"github.com/authcenter/authcenter/internal/database"
	"github.com/authcenter/authcenter/internal/httpapi"
	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/service"
	"github.com/authcenter/authcenter/internal/store"
)

// version 构建期注入（build 脚本用 -ldflags "-X main.version=..."，文档 07 §4）。
var version = "dev-m1"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "authcenter 启动失败:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		return err
	}

	logger := newLogger(cfg)
	logger.Info("AuthCenter 启动", "version", version, "listen", cfg.Listen, "data_dir", cfg.DataDir)

	// 3. 数据库（打开 + PRAGMA + step 迁移；失败即退出，启动自检；need01 06 §3）。
	db, applied, err := database.OpenWithApplied(cfg.DataDir)
	if err != nil {
		return err
	}
	defer db.Close()
	curVer, _ := database.SchemaVersion(db)
	if len(applied) > 0 {
		names := make([]string, 0, len(applied))
		for _, a := range applied {
			names = append(names, a.Name)
		}
		logger.Info("schema 迁移完成", "to_version", curVer, "applied", names)
	} else {
		logger.Info("schema 无需迁移", "version", curVer)
	}
	if cfg.MigrateOnly {
		logger.Info("migrate-only 完成，仅迁移后退出", "version", curVer)
		return nil
	}

	// 4-5. store + system.startup 审计。
	st := store.New(db)
	auditCtx := context.Background()
	writeSystemAudit(st, &model.AuditLog{
		EventTime:  database.NowUTC(),
		EventType:  model.EventSystemStartup,
		ActorType:  model.ActorTypeSystem,
		ActorName:  "authcenter",
		TargetType: model.TargetTypeSystem,
		Result:     model.ResultSuccess,
		Detail:     fmt.Sprintf(`{"version":%q}`, version),
	})

	// 6. admin 幂等初始化（C3/D3）。
	adminSvc := service.NewAdminService(st, logger, cfg.DataDir)
	created, plainPassword, err := adminSvc.EnsureAdmin(auditCtx)
	if err != nil {
		return err
	}
	if created {
		// 控制台打印明文（D3 特殊通道之一）。
		fmt.Printf("\n========================================\n")
		fmt.Printf("  AuthCenter 初始管理员账号\n")
		fmt.Printf("  username: admin\n")
		fmt.Printf("  password: %s\n", plainPassword)
		fmt.Printf("  密码已写入: %s/auth.log\n", cfg.DataDir)
		fmt.Printf("  请立即保存，之后不再展示！\n")
		fmt.Printf("========================================\n\n")
		writeSystemAudit(st, &model.AuditLog{
			EventTime:  database.NowUTC(),
			EventType:  model.EventSystemAdminInitialized,
			ActorType:  model.ActorTypeSystem,
			ActorName:  "authcenter",
			TargetType: model.TargetTypeSystem,
			TargetName: "admin",
			Result:     model.ResultSuccess,
		})
	} else {
		logger.Info("admin 已存在，跳过初始化（幂等）")
	}

	// 7. JWT secret：env 覆盖优先，否则读取 settings，无则随机生成（32B base64，文档 06 §3.4）。
	if err := ensureJWTSecret(auditCtx, st, cfg.JWTSecret, logger); err != nil {
		return err
	}

	// 7.2 F-021 密钥存储加密装配：主密钥只来自 env AUTHCENTER_KEY_ENC_KEY（缺失即明文模式）。
	keyCipher, err := service.NewCipherFromEnv(cfg.KeyEncKey)
	if err != nil {
		// 主密钥长度非法：写自检失败审计后退出（绝不静默降级为明文模式）。
		writeSystemAudit(st, &model.AuditLog{
			EventTime: database.NowUTC(), EventType: model.EventSystemKeyEncryptionVerifyFailed,
			ActorType: model.ActorTypeSystem, ActorName: "authcenter",
			TargetType: model.TargetTypeSystem, Result: model.ResultFailure,
			Detail: `{"reason":"bad_key_length"}`,
		})
		return err
	}
	// 仅状态自检（不含数据回填；回填由后台 job 承担，need01 06 §4）。
	if err := ensureKeyEncryptionReady(auditCtx, st, keyCipher, logger); err != nil {
		return err
	}

	// 7.5 初始化 service 层（文档 02 §6 第 4 步：M2 会话/项目/密钥/审计；M3 令牌/认证；M4 统计）。
	auditSvc := service.NewAuditService(st, logger)
	sessionSvc := service.NewSessionService(st, logger)
	projectSvc := service.NewProjectService(st, auditSvc)
	graceDays := loadRotateGraceDays(auditCtx, st)
	apikeySvc := service.NewApiKeyService(st, auditSvc, projectSvc, graceDays, keyCipher)
	tokenSvc, err := service.NewTokenService(auditCtx, st)
	if err != nil {
		return err
	}
	authSvc := service.NewAuthService(auditCtx, st, auditSvc, tokenSvc, logger, apikeySvc)
	statsSvc := service.NewStatsService(st)
	// M7：审计保留策略后台任务（settings.audit_retention_days，默认 90 天，0=永久保留）。
	retentionSvc := service.NewAuditRetentionService(st, auditSvc, logger)
	retentionSvc.SyncInterval(auditCtx)
	settingsSvc := service.NewSettingsServiceWithCipher(st, auditSvc, logger, keyCipher)
	// F-021：key_hash 存量回填后台任务（Interval=0，启动后异步触发一次）。
	backfillSvc := service.NewKeyHashBackfillService(st, auditSvc, logger)
	backfillSvc.SetOnDone(apikeySvc.InvalidateBackfillCache)
	// M9：F-020 多管理员与 RBAC 的账号管理服务（owner 可增/停/启/改角色/重置密码）。
	// owner 回填不在此处调用——由迁移 step admin_user_role 承担（need01 02 §3.2/§4.7）。
	adminUserSvc := service.NewAdminUserService(st, auditSvc, logger)
	// 8. HTTP 服务（C2：仅 127.0.0.1:53779；超时参数见文档 02 §8）。
	//    前端资源：-web-dir 开发模式读磁盘（改文件即刷新），否则用 go:embed 内嵌（07 §2.3）。
	var webFS fs.FS
	if cfg.WebDir != "" {
		webFS = os.DirFS(cfg.WebDir)
		logger.Info("前端资源使用磁盘目录（开发模式）", "web_dir", cfg.WebDir)
	}
	// 优雅关闭上下文先建：MaintenanceRunner 随 ctx 停止（need01 01 §4.5）。
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	maint := service.NewMaintenanceRunner(st, auditSvc, logger)
	maint.Register(retentionSvc)
	maint.Register(backfillSvc)
	maint.Start(ctx)
	// F-021：异步触发一次 key_hash 回填，不阻塞 HTTP 启动（need01 03 §4.7）。
	go func() {
		if _, err := maint.RunNow(ctx, "key_hash_backfill"); err != nil && !errors.Is(err, service.ErrJobRunning) {
			logger.Error("key_hash 回填任务失败", "err", err)
		}
	}()
	defer maint.Stop()
	server := &http.Server{
		Addr: cfg.Listen,
		Handler: httpapi.New(httpapi.RouterDeps{
			Logger:    logger,
			Store:     st,
			Sessions:  sessionSvc,
			Projects:  projectSvc,
			Apikeys:   apikeySvc,
			Audits:    auditSvc,
			Auths:     authSvc,
			Stats:     statsSvc,
			Settings:  settingsSvc,
			Retention: retentionSvc,
			Admins:    adminUserSvc,
			Runner:    maint,
			WebFS:     webFS,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	// 优雅关闭（文档 04 §8）：SIGINT/SIGTERM → Shutdown(10s) → 关闭 db → system.shutdown 审计。
	errCh := make(chan error, 1)
	go func() {
		logger.Info("HTTP 服务已启动", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("HTTP 服务异常退出: %w", err)
	case <-ctx.Done():
		logger.Info("收到退出信号，开始优雅关闭", "signal", "SIGINT/SIGTERM")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("优雅关闭超时", "err", err)
		}
	}

	writeSystemAudit(st, &model.AuditLog{
		EventTime:  database.NowUTC(),
		EventType:  model.EventSystemShutdown,
		ActorType:  model.ActorTypeSystem,
		ActorName:  "authcenter",
		TargetType: model.TargetTypeSystem,
		Result:     model.ResultSuccess,
	})
	logger.Info("AuthCenter 已退出")
	return nil
}

// newLogger 按配置创建 slog 日志器（text/json，文档 02 §6 第 2 步）。
func newLogger(cfg *config.Config) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}

// ensureJWTSecret 读取/生成 JWT secret：env AUTHCENTER_JWT_SECRET 优先，
// 否则读 settings.jwt_secret；不存在则随机 32B base64 写入（幂等）。
func ensureJWTSecret(ctx context.Context, st *store.Store, envSecret string, logger *slog.Logger) error {
	if envSecret != "" {
		logger.Info("JWT secret 使用环境变量 AUTHCENTER_JWT_SECRET 覆盖")
		if err := st.SetSetting(ctx, model.SettingJWTSecret, envSecret); err != nil {
			return err
		}
		return nil
	}
	existing, err := st.GetSetting(ctx, model.SettingJWTSecret)
	if err != nil {
		return err
	}
	if existing != "" {
		return nil // 已存在：复用，保证重启后历史令牌仍可校验
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("生成 JWT secret 失败: %w", err)
	}
	if err := st.SetSetting(ctx, model.SettingJWTSecret, base64.RawStdEncoding.EncodeToString(buf)); err != nil {
		return err
	}
	logger.Info("已生成新的 JWT secret 并写入 settings")
	return nil
}

// loadRotateGraceDays 读取密钥轮换宽限期（settings.key_rotate_grace_days，默认 7 天，文档 04 §3.5）。
func loadRotateGraceDays(ctx context.Context, st *store.Store) int {
	v, err := st.GetSetting(ctx, model.SettingKeyRotateGraceDays)
	if err != nil || v == "" {
		return 7
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 7
	}
	return n
}

// writeSystemAudit 写一条系统审计；失败仅记日志不阻断（M1：system.* 事件）。
func writeSystemAudit(st *store.Store, e *model.AuditLog) {
	if err := st.InsertAudit(context.Background(), e); err != nil {
		slog.Error("写入系统审计失败", "err", err, "event_type", e.EventType)
	}
}

// ensureKeyEncryptionReady F-021 启动自检（全部幂等，不含数据回填；need01 03 §4.7）：
//  1. key_encryption_enabled=1 但未提供主密钥 → 报错退出（绝不带病启动）；
//  2. 库中存在密文行但未提供主密钥 → 报错退出（mixed_mode）；
//  3. 有密文时用主密钥自检密文验证其可用性；失败 → 写审计 + 报错退出；
//  4. 初始化 key_hash_backfill_state（缺失则写 pending；已完成过则保持 done）；
//  5. 全部通过 → 记 Info（只说条数与校验结论，绝不打任何密钥内容）。
func ensureKeyEncryptionReady(ctx context.Context, st *store.Store, c service.Cipher, logger *slog.Logger) error {
	writeVerifyFailed := func(reason string) {
		writeSystemAudit(st, &model.AuditLog{
			EventTime: database.NowUTC(), EventType: model.EventSystemKeyEncryptionVerifyFailed,
			ActorType: model.ActorTypeSystem, ActorName: "authcenter",
			TargetType: model.TargetTypeSystem, Result: model.ResultFailure,
			Detail: fmt.Sprintf(`{"reason":%q}`, reason),
		})
	}
	enabled, err := st.GetSetting(ctx, model.SettingKeyEncryptionEnabled)
	if err != nil {
		return err
	}
	encCount, err := st.CountEncrypted(ctx)
	if err != nil {
		return err
	}
	plainCount, err := st.CountPlain(ctx)
	if err != nil {
		return err
	}
	if enabled == "1" && !c.Enabled() {
		writeVerifyFailed("missing_master_key")
		return errors.New("已启用密钥加密但未提供 AUTHCENTER_KEY_ENC_KEY（拒绝以明文模式启动）")
	}
	if encCount > 0 && !c.Enabled() {
		writeVerifyFailed("mixed_mode")
		return fmt.Errorf("库中存在 %d 条密文密钥但未提供 AUTHCENTER_KEY_ENC_KEY，无法启动", encCount)
	}
	if c.Enabled() {
		// 自检密文同步 + 主密钥校验：
		//   库中已有密文（encCount>0）→ 必须解得开，否则 fail-fast；
		//   库中无密文 → 主密钥变更不算错误，按当前主密钥重写自检密文（自愈，不锁死服务）。
		if err := service.SyncKeyEncCheckBlob(ctx, st, c, encCount > 0); err != nil {
			if errors.Is(err, service.ErrCipherDecrypt) {
				writeVerifyFailed("decrypt_failed")
				return errors.New("主密钥校验失败：无法解开库中自检密文（AUTHCENTER_KEY_ENC_KEY 与库不匹配）")
			}
			return err
		}
	}
	// 初始化回填状态：缺失则 pending；已完成过则保持 done（幂等，重启不重复回填）。
	state, err := st.GetSetting(ctx, model.SettingKeyHashBackfillState)
	if err != nil {
		return err
	}
	if state == "" {
		if err := st.SetSetting(ctx, model.SettingKeyHashBackfillState, model.BackfillPending); err != nil {
			return err
		}
		state = model.BackfillPending
	}
	if encCount > 0 {
		logger.Info("主密钥已加载且校验通过", "encrypted_keys", encCount, "plaintext_keys", plainCount)
	} else if c.Enabled() {
		logger.Info("主密钥已加载，当前库中暂无密文密钥", "plaintext_keys", plainCount)
	} else {
		logger.Info("未配置主密钥，密钥以明文存储（可设置 AUTHCENTER_KEY_ENC_KEY 启用加密）",
			"plaintext_keys", plainCount)
	}
	return nil
}
