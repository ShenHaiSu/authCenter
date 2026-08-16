package service

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/authcenter/authcenter/internal/model"
	"github.com/authcenter/authcenter/internal/store"
)

func timeNowUTC() time.Time { return time.Now().UTC() }

// AdminPasswordLen admin 初始密码长度（文档 03 §3.1：30 位）。
const AdminPasswordLen = 30

// AuthLogFileName 初始密码落盘文件（文档 04 §3.1：data/auth.log）。
const AuthLogFileName = "auth.log"

// AdminService 管理员相关业务（M1：初始化）。
type AdminService struct {
	store    *store.Store
	logger   *slog.Logger
	dataDir  string
	authPath string
}

// NewAdminService 构造 AdminService。
func NewAdminService(st *store.Store, logger *slog.Logger, dataDir string) *AdminService {
	return &AdminService{
		store:    st,
		logger:   logger,
		dataDir:  dataDir,
		authPath: filepath.Join(dataDir, AuthLogFileName),
	}
}

// EnsureAdmin 幂等初始化 admin（文档 04 §3.1）：
//   - 已存在（username='admin'）→ 返回 created=false，什么都不做；
//   - 不存在 → crypto/rand 生成 30 位密码 → argon2id 哈希入库
//     → 明文落盘 data/auth.log（0600，仅首次）→ 返回明文供 main 打印控制台。
//
// 返回 (created, plainPassword, err)。
func (s *AdminService) EnsureAdmin(ctx context.Context) (created bool, plainPassword string, err error) {
	exists, err := s.store.AdminExists(ctx, "admin")
	if err != nil {
		return false, "", fmt.Errorf("检查 admin 是否已存在失败: %w", err)
	}
	if exists {
		return false, "", nil // 幂等：什么都不做
	}

	plain, err := RandomString(AdminPasswordLen)
	if err != nil {
		return false, "", fmt.Errorf("生成初始密码失败: %w", err)
	}
	hash, err := HashPassword(plain)
	if err != nil {
		return false, "", fmt.Errorf("哈希初始密码失败: %w", err)
	}

	admin := &model.AdminUser{
		Username:     "admin",
		PasswordHash: hash,
		CreatedAt:    timeNowUTC(),
	}
	if err := s.store.CreateAdmin(ctx, admin); err != nil {
		return false, "", err
	}

	// 落盘 data/auth.log（0600），D3 特殊通道，仅首次（幂等保证只出现一次）。
	if err := s.writeAuthLog(plain); err != nil {
		s.logger.Error("写入 auth.log 失败（初始密码仍需从控制台获取）", "err", err)
		return true, plain, nil // 落盘失败不阻断启动，控制台仍会打印
	}

	s.logger.Warn("admin 初始化完成，初始密码已打印控制台并写入 auth.log", "username", "admin")
	return true, plain, nil
}

// writeAuthLog 以 0600 权限追加写入初始密码。若文件已存在则跳过
// （幂等：即使 admin 恰好被并发创建，也不重复写入）。
func (s *AdminService) writeAuthLog(plain string) error {
	if _, err := os.Stat(s.authPath); err == nil {
		return nil // 已存在，不再写入（保证首次交付一次）
	}
	content := fmt.Sprintf("AuthCenter 初始管理员密码 (username=admin): %s\n生成时间: %s\n",
		plain, timeNowUTC().Format("2006-01-02 15:04:05 MST"))
	f, err := os.OpenFile(s.authPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("打开 %s 失败: %w", s.authPath, err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		return fmt.Errorf("写入 %s 失败: %w", s.authPath, err)
	}
	return f.Sync()
}
