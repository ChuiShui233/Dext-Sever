package session

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// SessionHandlers 会话管理处理器
type SessionHandlers struct {
	sessionManager *SessionManager
}

func NewSessionHandlers(sm *SessionManager) *SessionHandlers {
	return &SessionHandlers{sessionManager: sm}
}

// GetUserSessions 获取用户的所有活跃会话
func (h *SessionHandlers) GetUserSessions(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未授权访问"})
		return
	}

	sessions, err := h.sessionManager.GetUserSessions(userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取会话列表失败"})
		return
	}

	// 隐藏敏感信息
	for i := range sessions {
		sessions[i].TokenHash = "***"
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": sessions,
		"total":    len(sessions),
	})
}

// RevokeSession 撤销指定会话
func (h *SessionHandlers) RevokeSession(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未授权访问"})
		return
	}

	sessionID := c.Param("session_id")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少会话ID"})
		return
	}

	// 验证会话属于当前用户
	sessions, err := h.sessionManager.GetUserSessions(userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "验证会话失败"})
		return
	}

	found := false
	for _, session := range sessions {
		if session.ID == sessionID {
			found = true
			break
		}
	}

	if !found {
		c.JSON(http.StatusForbidden, gin.H{"error": "无权撤销此会话"})
		return
	}

	err = h.sessionManager.RevokeSession(sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "撤销会话失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "会话已撤销"})
}

// RevokeAllSessions 撤销用户的所有会话（除当前会话外）
func (h *SessionHandlers) RevokeAllSessions(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未授权访问"})
		return
	}

	currentSessionID, _ := c.Get("session_id")

	// 获取所有会话
	sessions, err := h.sessionManager.GetUserSessions(userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取会话列表失败"})
		return
	}

	revokedCount := 0
	for _, session := range sessions {
		if session.ID != currentSessionID {
			if err := h.sessionManager.RevokeSession(session.ID); err == nil {
				revokedCount++
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       "其他会话已撤销",
		"revoked_count": revokedCount,
	})
}

// LogoutCurrentSession 注销当前会话
func (h *SessionHandlers) LogoutCurrentSession(c *gin.Context) {
	sessionID, exists := c.Get("session_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到会话"})
		return
	}

	err := h.sessionManager.RevokeSession(sessionID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "注销失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "已成功注销"})
}

// GetSessionStats 获取会话统计信息（管理员功能）
func (h *SessionHandlers) GetSessionStats(c *gin.Context) {
	// 这里应该添加管理员权限检查
	userRole, exists := c.Get("user_role")
	if !exists || userRole != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "需要管理员权限"})
		return
	}

	// 获取统计信息的SQL查询
	stats := make(map[string]interface{})

	// 总活跃会话数
	var activeSessions int
	h.sessionManager.db.QueryRow("SELECT COUNT(*) FROM user_sessions WHERE is_active = TRUE AND expires_at > NOW()").Scan(&activeSessions)
	stats["active_sessions"] = activeSessions

	// 今日新建会话数
	var todaySessions int
	h.sessionManager.db.QueryRow("SELECT COUNT(*) FROM user_sessions WHERE DATE(created_at) = CURDATE()").Scan(&todaySessions)
	stats["today_sessions"] = todaySessions

	// 黑名单令牌数
	var blacklistedTokens int
	h.sessionManager.db.QueryRow("SELECT COUNT(*) FROM jwt_blacklist WHERE expires_at > NOW()").Scan(&blacklistedTokens)
	stats["blacklisted_tokens"] = blacklistedTokens

	c.JSON(http.StatusOK, stats)
}

// CleanupSessions 手动触发会话清理（管理员功能）
func (h *SessionHandlers) CleanupSessions(c *gin.Context) {
	userRole, exists := c.Get("user_role")
	if !exists || userRole != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "需要管理员权限"})
		return
	}

	err := h.sessionManager.CleanupExpiredSessions()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "清理失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "会话清理完成"})
}

// LimitUserSessions 限制用户会话数量
func (h *SessionHandlers) LimitUserSessions(c *gin.Context) {
	var req struct {
		MaxSessions int `json:"max_sessions" binding:"required,min=1,max=20"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未授权访问"})
		return
	}

	err := h.sessionManager.LimitUserSessions(userID.(string), req.MaxSessions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "限制会话失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "会话数量已限制",
		"max_sessions": req.MaxSessions,
	})
}
