// Package model 定义领域结构体（后端架构文档 04 §1）。
// M1：admin/settings/audit 基础结构体；M2：Project/APIKey 补全。
package model

import "time"

// 管理员角色常量（F-020：仅两级，细粒度权限列 P3；未知值一律按 admin 处理）。
const (
	RoleOwner = "owner" // 超级管理员：可管理管理员账号
	RoleAdmin = "admin" // 管理员：项目/密钥/审计/改自己密码
)

// AdminUser 管理员（表 admin_user，见数据库设计文档 03 §2.1）。
// F-020 新增 role / force_password_change / updated_at（迁移 step admin_user_role）。
type AdminUser struct {
	ID                  int64      `json:"id"`
	Username            string     `json:"username"`
	PasswordHash        string     `json:"-"` // 永不出现在任何响应
	Role                string     `json:"role"`
	IsActive            bool       `json:"is_active"`
	ForcePasswordChange bool       `json:"force_password_change"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           *time.Time `json:"updated_at,omitempty"`
	LastLoginAt         *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP         string     `json:"last_login_ip,omitempty"`
}

// IsOwner 判断是否为超级管理员（读路径统一走角色归一化后的 Role）。
func (u *AdminUser) IsOwner() bool { return u != nil && u.Role == RoleOwner }

// AdminSession 管理员会话（表 admin_session，见文档 03 §2.2）。
// 库中只存 token 的 SHA-256，不存明文。
type AdminSession struct {
	ID          int64     `json:"id"`
	TokenHash   string    `json:"-"`
	AdminUserID int64     `json:"admin_user_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	IP          string    `json:"ip,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Project 项目（表 project，见文档 03 §2.3）。
type Project struct {
	ID             int64     `json:"id"`
	Name           string    `json:"name"`            // 项目名（外部认证标识，UNIQUE）
	Description    string    `json:"description"`     //
	CurrentVersion string    `json:"current_version"` // 当前维护版本
	MinVersion     *string   `json:"min_version"`     // 可选最低版本，NULL=不限制
	IsActive       bool      `json:"is_active"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	KeyCount       int       `json:"key_count,omitempty"` // 列表查询附带，非表字段
}

// APIKey 项目密钥（表 api_key，见文档 03 §2.4）。
// KeyValue 永不出现在任何列表/详情响应（05 §4.3），仅创建/轮换响应返回一次明文。
type APIKey struct {
	ID          int64      `json:"id"`
	ProjectID   int64      `json:"project_id"`
	Name        string     `json:"name"`        // 备注/用途
	KeyValue    string     `json:"-"`           // 密钥明文，响应中永不输出
	Fingerprint *string    `json:"fingerprint"` // 绑定指纹，NULL=不绑定
	ExpiresAt   *time.Time `json:"expires_at"`  // NULL=永不过期
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP  string     `json:"last_used_ip,omitempty"`
	IsActive    bool       `json:"is_active"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Settings 系统设置项（表 settings，见文档 03 §2.6）。
type Settings struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// settings 键名常量（M1/M2 涉及的）。
const (
	SettingJWTSecret           = "jwt_secret"
	SettingTokenTTL            = "token_ttl_seconds"
	SettingRequireFp           = "require_fingerprint"
	SettingAuditRetDays        = "audit_retention_days"
	SettingKeyRotateGraceDays  = "key_rotate_grace_days"
	SettingRateLimitAuthPerMin = "rate_limit_auth_per_min"
	// F-019 审计保留策略 settings 键（need01 01 §9 步骤 1，键表见 05 §1）。
	SettingAuditCleanupIntervalHours = "audit_cleanup_interval_hours"
	SettingAuditMinKeepRows          = "audit_min_keep_rows"
	SettingAuditLastCleanupAt        = "audit_last_cleanup_at"
	SettingAuditLastCleanupRows      = "audit_last_cleanup_rows"
)

// AuditLog 审计日志（表 audit_log，见文档 03 §2.5）。
// M1 用于写 system.startup / system.admin_initialized / system.shutdown。
type AuditLog struct {
	ID         int64     `json:"id"`
	EventTime  time.Time `json:"event_time"`
	EventType  string    `json:"event_type"`
	ActorType  string    `json:"actor_type"`  // 'admin' | 'client' | 'system'
	ActorID    string    `json:"actor_id"`    // 管理员 id / 项目名
	ActorName  string    `json:"actor_name"`  //
	TargetType string    `json:"target_type"` // 'project' | 'api_key' | 'session' | 'system' | 'audit'
	TargetID   int64     `json:"target_id"`
	TargetName string    `json:"target_name"`
	Result     string    `json:"result"` // 'success' | 'failure'
	Detail     string    `json:"detail"` // JSON：失败原因、指纹等
	IP         string    `json:"ip"`
	RequestID  string    `json:"request_id"`
}

// 审计事件类型常量（文档 03 §5）。
const (
	EventSystemStartup          = "system.startup"
	EventSystemAdminInitialized = "system.admin_initialized"
	EventSystemShutdown         = "system.shutdown"

	EventAdminLogin          = "admin.login"
	EventAdminLogout         = "admin.logout"
	EventAdminLoginFailed    = "admin.login_failed"
	EventAdminPasswordChange = "admin.password_change"
	// F-020 多管理员与 RBAC 事件（need01 02 §4.6 / 05 §2）。
	EventAdminCreate        = "admin.create"
	EventAdminUpdate        = "admin.update"
	EventAdminEnable        = "admin.enable"
	EventAdminDisable       = "admin.disable"
	EventAdminRoleChange    = "admin.role_change"
	EventAdminPasswordReset = "admin.password_reset"

	EventProjectCreate  = "project.create"
	EventProjectUpdate  = "project.update"
	EventProjectDelete  = "project.delete"
	EventProjectDisable = "project.disable"
	EventProjectEnable  = "project.enable"

	EventKeyCreate  = "key.create"
	EventKeyUpdate  = "key.update"
	EventKeyDisable = "key.disable"
	EventKeyEnable  = "key.enable"
	EventKeyRotate  = "key.rotate"
	EventKeyDelete  = "key.delete"

	EventAuthAuthenticate       = "auth.authenticate"
	EventAuthAuthenticateFailed = "auth.authenticate_failed"
	// F-019 审计保留策略事件（need01 01 §9 步骤 1，事件表见 05 §2）。
	EventSystemAuditCleanup = "system.audit_cleanup"
	EventSettingsUpdate     = "settings.update"
	// 基础设施：schema 迁移事件（need01 06 §9 步骤 5）。
	EventSystemSchemaMigrated = "system.schema_migrated"
)

// 审计结果常量。
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// Actor 类型常量。
const (
	ActorTypeAdmin  = "admin"
	ActorTypeClient = "client"
	ActorTypeSystem = "system"
)

// Target 类型常量。
const (
	TargetTypeSystem  = "system"
	TargetTypeSession = "session"
	TargetTypeProject = "project"
	TargetTypeAPIKey  = "api_key"
	TargetTypeAudit   = "audit"
	TargetTypeAdmin   = "admin" // F-020：管理员账号作为审计目标
)
