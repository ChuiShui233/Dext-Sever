package session

import (
	"Dext-Server/security"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"time"
)

type SessionManager struct {
	db *sql.DB
}

type Session struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	TokenHash    string    `json:"token_hash"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	LastAccessed time.Time `json:"last_accessed"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	IsActive     bool      `json:"is_active"`
}

func NewSessionManager(database *sql.DB) *SessionManager {
	return &SessionManager{db: database}
}

// CreateSession 创建新会话
func (sm *SessionManager) CreateSession(userID, token, ipAddress, userAgent string, expiresAt time.Time) (*Session, error) {
	sessionID := generateSessionID()
	tokenHash := hashToken(token)
	
	session := &Session{
		ID:           sessionID,
		UserID:       userID,
		TokenHash:    tokenHash,
		ExpiresAt:    expiresAt,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		IsActive:     true,
	}
	
	_, err := sm.db.Exec(`
		INSERT INTO user_sessions (id, user_id, token_hash, expires_at, ip_address, user_agent, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, session.ID, session.UserID, session.TokenHash, session.ExpiresAt, 
	   session.IPAddress, session.UserAgent, session.IsActive)
	
	if err != nil {
		return nil, fmt.Errorf("创建会话失败: %v", err)
	}
	
	log.Printf("为用户 %s 创建新会话: %s", userID, sessionID)
	return session, nil
}

// ValidateSession 验证会话有效性
func (sm *SessionManager) ValidateSession(token string) (*Session, error) {
	// 先尝试直接验证JWT令牌
	if claims, err := security.ParseTokenClaims(token); err == nil {
		// JWT有效，检查用户是否存在
		var userID, username string
		err := sm.db.QueryRow("SELECT id, username FROM users WHERE id = ?", claims.Subject).Scan(&userID, &username)
		if err != nil {
			return nil, fmt.Errorf("用户不存在: %v", err)
		}
		
		// 返回虚拟会话对象
		return &Session{
			ID:           fmt.Sprintf("jwt_%s", claims.Subject),
			UserID:       userID,
			TokenHash:    hashToken(token),
			ExpiresAt:    claims.ExpiresAt.Time,
			CreatedAt:    claims.IssuedAt.Time,
			LastAccessed: time.Now(),
			IsActive:     true,
		}, nil
	}
	
	// JWT验证失败，尝试会话表验证
	tokenHash := hashToken(token)
	
	var session Session
	err := sm.db.QueryRow(`
		SELECT id, user_id, token_hash, expires_at, created_at, last_accessed, 
		       ip_address, user_agent, is_active
		FROM user_sessions 
		WHERE token_hash = ? AND is_active = TRUE AND expires_at > NOW()
	`, tokenHash).Scan(
		&session.ID, &session.UserID, &session.TokenHash, &session.ExpiresAt,
		&session.CreatedAt, &session.LastAccessed, &session.IPAddress,
		&session.UserAgent, &session.IsActive,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("会话无效或已过期")
		}
		return nil, fmt.Errorf("验证会话失败: %v", err)
	}
	
	// 更新最后访问时间
	sm.UpdateLastAccessed(session.ID)
	
	return &session, nil
}

// UpdateLastAccessed 更新会话最后访问时间
func (sm *SessionManager) UpdateLastAccessed(sessionID string) error {
	_, err := sm.db.Exec(`
		UPDATE user_sessions 
		SET last_accessed = NOW() 
		WHERE id = ?
	`, sessionID)
	
	return err
}

// RevokeSession 撤销单个会话
func (sm *SessionManager) RevokeSession(sessionID string) error {
	_, err := sm.db.Exec(`
		UPDATE user_sessions 
		SET is_active = FALSE 
		WHERE id = ?
	`, sessionID)
	
	if err != nil {
		return fmt.Errorf("撤销会话失败: %v", err)
	}
	
	log.Printf("会话已撤销: %s", sessionID)
	return nil
}

// RevokeUserSessions 撤销用户的所有会话
func (sm *SessionManager) RevokeUserSessions(userID string) error {
	result, err := sm.db.Exec(`
		UPDATE user_sessions 
		SET is_active = FALSE 
		WHERE user_id = ? AND is_active = TRUE
	`, userID)
	
	if err != nil {
		return fmt.Errorf("撤销用户会话失败: %v", err)
	}
	
	affected, _ := result.RowsAffected()
	log.Printf("已撤销用户 %s 的 %d 个会话", userID, affected)
	return nil
}

// CleanupExpiredSessions 清理过期会话
func (sm *SessionManager) CleanupExpiredSessions() error {
	result, err := sm.db.Exec(`
		DELETE FROM user_sessions 
		WHERE expires_at < NOW() OR is_active = FALSE
	`)
	
	if err != nil {
		return fmt.Errorf("清理过期会话失败: %v", err)
	}
	
	affected, _ := result.RowsAffected()
	if affected > 0 {
		log.Printf("已清理 %d 个过期会话", affected)
	}
	
	return nil
}

// LimitUserSessions 限制用户活跃会话数量
func (sm *SessionManager) LimitUserSessions(userID string, maxSessions int) error {
	_, err := sm.db.Exec(`
		UPDATE user_sessions s1
		INNER JOIN (
			SELECT id, ROW_NUMBER() OVER (ORDER BY last_accessed DESC) as rn
			FROM user_sessions 
			WHERE user_id = ? AND is_active = TRUE AND expires_at > NOW()
		) s2 ON s1.id = s2.id
		SET s1.is_active = FALSE
		WHERE s2.rn > ?
	`, userID, maxSessions)
	
	return err
}

// GetUserSessions 获取用户的活跃会话
func (sm *SessionManager) GetUserSessions(userID string) ([]Session, error) {
	rows, err := sm.db.Query(`
		SELECT id, user_id, token_hash, expires_at, created_at, last_accessed,
		       ip_address, user_agent, is_active
		FROM user_sessions 
		WHERE user_id = ? AND is_active = TRUE AND expires_at > NOW()
		ORDER BY last_accessed DESC
	`, userID)
	
	if err != nil {
		return nil, fmt.Errorf("查询用户会话失败: %v", err)
	}
	defer rows.Close()
	
	var sessions []Session
	for rows.Next() {
		var session Session
		err := rows.Scan(
			&session.ID, &session.UserID, &session.TokenHash, &session.ExpiresAt,
			&session.CreatedAt, &session.LastAccessed, &session.IPAddress,
			&session.UserAgent, &session.IsActive,
		)
		if err != nil {
			continue
		}
		sessions = append(sessions, session)
	}
	
	return sessions, nil
}

// BlacklistToken 将令牌加入黑名单
func (sm *SessionManager) BlacklistToken(token, userID, reason string, expiresAt time.Time) error {
	tokenHash := hashToken(token)
	
	_, err := sm.db.Exec(`
		INSERT INTO jwt_blacklist (token_hash, user_id, expires_at, reason)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE revoked_at = NOW(), reason = VALUES(reason)
	`, tokenHash, userID, expiresAt, reason)
	
	if err != nil {
		return fmt.Errorf("令牌加入黑名单失败: %v", err)
	}
	
	log.Printf("令牌已加入黑名单: 用户=%s, 原因=%s", userID, reason)
	return nil
}

// IsTokenBlacklisted 检查令牌是否在黑名单中
func (sm *SessionManager) IsTokenBlacklisted(token string) bool {
	tokenHash := hashToken(token)
	
	var count int
	err := sm.db.QueryRow(`
		SELECT COUNT(*) FROM jwt_blacklist 
		WHERE token_hash = ? AND expires_at > NOW()
	`, tokenHash).Scan(&count)
	
	return err == nil && count > 0
}

// 生成会话ID
func generateSessionID() string {
	return fmt.Sprintf("sess_%d_%s", time.Now().UnixNano(), 
		hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))[:8])
}

// 哈希令牌
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// StartCleanupRoutine 启动定期清理协程
func (sm *SessionManager) StartCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour) // 每小时清理一次
		defer ticker.Stop()
		
		for range ticker.C {
			if err := sm.CleanupExpiredSessions(); err != nil {
				log.Printf("定期清理会话失败: %v", err)
			}
		}
	}()
	
	log.Println("会话清理服务已启动")
}
