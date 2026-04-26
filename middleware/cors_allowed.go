package middleware

import (
	"log"
	"os"
	"strings"
	"sync"
)

type corsAllowlistCache struct {
	mu  sync.RWMutex
	raw string
	set map[string]struct{}
}

var corsAllowlist corsAllowlistCache

func getAllowedOriginSet() map[string]struct{} {
	raw := strings.TrimSpace(os.Getenv("CORS_ALLOWED_ORIGINS"))

	corsAllowlist.mu.RLock()
	if corsAllowlist.set != nil && corsAllowlist.raw == raw {
		set := corsAllowlist.set
		corsAllowlist.mu.RUnlock()
		return set
	}
	corsAllowlist.mu.RUnlock()

	// Build a new immutable set
	newSet := map[string]struct{}{}
	if raw != "" {
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			newSet[item] = struct{}{}
		}
	} else {
		// Backward-compatible defaults
		for _, item := range []string{
			"https://qs.chuishui.top",
			"http://localhost:8001",
			"http://127.0.0.1:8001",
			"http://192.168.1.4:8001",
		} {
			newSet[item] = struct{}{}
		}
	}

	corsAllowlist.mu.Lock()
	corsAllowlist.raw = raw
	corsAllowlist.set = newSet
	corsAllowlist.mu.Unlock()

	if os.Getenv("ENV") == "production" && raw == "" {
		log.Println("[SECURITY] ENV=production but CORS_ALLOWED_ORIGINS is empty; using built-in defaults")
	}

	return newSet
}

func isDevEnv() bool {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("ENV")))
	return env == "" || env == "dev" || env == "development"
}

func IsOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	}

	if _, ok := getAllowedOriginSet()[origin]; ok {
		return true
	}

	// Dev-only convenience: allow localhost/LAN dynamic ports
	if isDevEnv() {
		isLocalDynamic := strings.HasPrefix(origin, "http://localhost:") ||
			strings.HasPrefix(origin, "http://127.0.0.1:") ||
			strings.HasPrefix(origin, "https://localhost:") ||
			strings.HasPrefix(origin, "https://127.0.0.1:")
		isLAN := strings.HasPrefix(origin, "http://192.168.") ||
			strings.HasPrefix(origin, "http://10.") ||
			strings.HasPrefix(origin, "http://172.") ||
			strings.HasPrefix(origin, "https://192.168.") ||
			strings.HasPrefix(origin, "https://10.") ||
			strings.HasPrefix(origin, "https://172.")
		return isLocalDynamic || isLAN
	}

	return false
}
