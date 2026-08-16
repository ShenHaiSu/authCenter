// Package model 定义领域结构体（后端架构文档 04 §1）。
// M1 阶段仅需要 admin 与会话、settings 相关结构体；
// project/api_key/audit_log 的结构体随 M2/M3 逐步补齐。
package model

import "time"

// AdminUser 管理员（表 admin_user，见数据库设计文档 03 §2.1）。
type AdminUser struct {
	ID           int64      `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"-"` // 永不出现在任何响应
	IsActive     bool       `json:"is_active"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP  string     `json:"last_login_ip,omitempty"`
}

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

// Settings 系统设置项（表 settings，见文档 03 §2.6）。
type Settings struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// settings 键名常量（M1 涉及的）。
const (
	SettingJWTSecret    = "jwt_secret"
	SettingTokenTTL     = "token_ttl_seconds"
	SettingRequireFp    = "require_fingerprint"
	SettingAuditRetDays = "audit_retention_days"
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
	TargetTypeSystem = "system"
)
