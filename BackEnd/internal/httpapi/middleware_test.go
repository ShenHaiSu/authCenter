package httpapi

import (
	"net/http/httptest"
	"testing"
)

// TestClientIP_XForwardedFor 验证 X-Forwarded-For 优先解析规则。
func TestClientIP_XForwardedFor(t *testing.T) {
	tests := []struct {
		name string
		xff  string
		want string
	}{
		{"IPv4", "203.0.113.7", "203.0.113.7"},
		{"IPv6", "2001:db8::1", "2001:db8::1"},
		{"IPv6带方括号", "[2001:db8::1]", "2001:db8::1"},
		{"带端口", "203.0.113.7:8888", "203.0.113.7"},
		{"多级代理取最左", "203.0.113.7, 10.0.0.1", "203.0.113.7"},
		{"多级代理含空格", " 203.0.113.7 , 10.0.0.1 ", "203.0.113.7"},
		{"左侧非法跳过", "not-an-ip, 8.8.8.8", "8.8.8.8"},
		{"前级代理IPv6", "2001:db8::1, 10.0.0.1", "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = "127.0.0.1:53779"
			r.Header.Set("X-Forwarded-For", tt.xff)
			if got := clientIP(r); got != tt.want {
				t.Errorf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestClientIP_Fallback 验证 XFF 缺失或非法时回落 RemoteAddr。
func TestClientIP_Fallback(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		remoteAddr string
		want       string
	}{
		{"无XFF回落RemoteAddr", "", "127.0.0.1:53779", "127.0.0.1"},
		{"XFF为空回落", "  ", "127.0.0.1:53779", "127.0.0.1"},
		{"XFF全非法回落", "not-an-ip", "127.0.0.1:53779", "127.0.0.1"},
		{"XFF全非法多段回落", "bad1, bad2", "127.0.0.1:53779", "127.0.0.1"},
		{"RemoteAddr无端口IPv4", "", "127.0.0.1", "127.0.0.1"},
		{"RemoteAddr带方括号IPv6", "", "[::1]:53779", "::1"},
		{"RemoteAddr裸IPv6", "", "::1", "::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if got := clientIP(r); got != tt.want {
				t.Errorf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
