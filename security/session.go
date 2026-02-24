package security

import (
	"fmt"
	"sync"
	"time"
)

// SessionManager 会话管理器
type SessionManager struct {
	sessions map[string]*SessionData
	mutex    sync.RWMutex
}

// SessionData 会话数据
type SessionData struct {
	SessionKey *SessionKey
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// 全局会话管理器
var globalSessionManager = &SessionManager{
	sessions: make(map[string]*SessionData),
}

// StoreSessionKey 存储用户的会话密钥（按用户名，兼容旧逻辑）
func StoreSessionKey(username string, sessionKey *SessionKey) error {
	globalSessionManager.mutex.Lock()
	defer globalSessionManager.mutex.Unlock()

	now := time.Now()
	expiresAt := now.Add(24 * time.Hour) // 会话密钥24小时过期

	globalSessionManager.sessions[username] = &SessionData{
		SessionKey: sessionKey,
		CreatedAt:  now,
		ExpiresAt:  expiresAt,
	}

	return nil
}

// GetUserSessionKey 获取用户的会话密钥（按用户名，兼容旧逻辑）
func GetUserSessionKey(username string) (*SessionKey, error) {
	globalSessionManager.mutex.RLock()
	defer globalSessionManager.mutex.RUnlock()

	sessionData, exists := globalSessionManager.sessions[username]
	if !exists {
		return nil, fmt.Errorf("用户 %s 的会话密钥不存在", username)
	}

	// 检查会话是否过期
	if time.Now().After(sessionData.ExpiresAt) {
		// 清理过期会话
		delete(globalSessionManager.sessions, username)
		return nil, fmt.Errorf("用户 %s 的会话密钥已过期", username)
	}

	return sessionData.SessionKey, nil
}

// StoreSessionKeyForSession 存储会话密钥（按会话ID/JTI）
func StoreSessionKeyForSession(sessionID string, sessionKey *SessionKey) error {
	globalSessionManager.mutex.Lock()
	defer globalSessionManager.mutex.Unlock()

	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)

	globalSessionManager.sessions[sessionID] = &SessionData{
		SessionKey: sessionKey,
		CreatedAt:  now,
		ExpiresAt:  expiresAt,
	}

	return nil
}

// GetSessionKeyBySessionID 按会话ID/JTI获取会话密钥
func GetSessionKeyBySessionID(sessionID string) (*SessionKey, error) {
	globalSessionManager.mutex.RLock()
	defer globalSessionManager.mutex.RUnlock()

	sessionData, exists := globalSessionManager.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("会话 %s 的会话密钥不存在", sessionID)
	}

	if time.Now().After(sessionData.ExpiresAt) {
		delete(globalSessionManager.sessions, sessionID)
		return nil, fmt.Errorf("会话 %s 的会话密钥已过期", sessionID)
	}

	return sessionData.SessionKey, nil
}

// RemoveSessionKey 移除用户的会话密钥
func RemoveSessionKey(username string) {
	globalSessionManager.mutex.Lock()
	defer globalSessionManager.mutex.Unlock()

	delete(globalSessionManager.sessions, username)
}

// CleanExpiredSessions 清理过期的会话
func CleanExpiredSessions() {
	globalSessionManager.mutex.Lock()
	defer globalSessionManager.mutex.Unlock()

	now := time.Now()
	for username, sessionData := range globalSessionManager.sessions {
		if now.After(sessionData.ExpiresAt) {
			delete(globalSessionManager.sessions, username)
		}
	}
}

// GetActiveSessionCount 获取活跃会话数量
func GetActiveSessionCount() int {
	globalSessionManager.mutex.RLock()
	defer globalSessionManager.mutex.RUnlock()

	// 先清理过期会话
	now := time.Now()
	count := 0
	for _, sessionData := range globalSessionManager.sessions {
		if now.Before(sessionData.ExpiresAt) {
			count++
		}
	}

	return count
}

// 定期清理过期会话的后台任务
func StartSessionCleanup() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour) // 每小时清理一次
		defer ticker.Stop()

		for range ticker.C {
			CleanExpiredSessions()
		}
	}()
}
