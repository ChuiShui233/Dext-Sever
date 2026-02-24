package config

import (
	"os"
	"strings"
)

// GetAnonIDMode returns the anonymous ID generation mode.
// Supported values: off | normal | strict
// Default: normal
func GetAnonIDMode() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("ANON_ID_MODE")))
	if mode == "off" || mode == "strict" || mode == "normal" {
		return mode
	}
	return "normal"
}

// AnonIncludePort controls whether to include the source port in strict mode.
// Default: false
func AnonIncludePort() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("ANON_INCLUDE_PORT")))
	return v == "1" || v == "true" || v == "yes"
}

// TrustProxy indicates whether to trust reverse proxy headers like X-Forwarded-For.
// Default: true
func TrustProxy() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("TRUST_PROXY")))
	if v == "" {
		return true
	}
	return v == "1" || v == "true" || v == "yes"
}

// GetAnonIDSalt returns an optional salt to strengthen the anonymity hash.
// Default: empty string
func GetAnonIDSalt() string {
	return os.Getenv("ANON_ID_SALT")
}
