package config

import (
	"os"
	"strings"
)

// LoadTrustedProxies 加载可信代理列表
func LoadTrustedProxies() []string {
	proxiesEnv := os.Getenv("TRUSTED_PROXIES")
	if proxiesEnv == "" {
		// 默认：只信任本地回环地址
		return []string{"127.0.0.1"}
	}
	// 多个代理用逗号分隔
	proxies := strings.Split(proxiesEnv, ",")
	return proxies
}
