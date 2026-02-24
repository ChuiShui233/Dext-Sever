package session

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// JWTMiddleware JWT令牌验证中间件（集成会话管理）
func JWTMiddleware(sm *SessionManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从请求头获取令牌
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "缺少授权令牌"})
			c.Abort()
			return
		}

		// 检查Bearer格式
		tokenParts := strings.SplitN(authHeader, " ", 2)
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "令牌格式错误"})
			c.Abort()
			return
		}

		token := tokenParts[1]

		// 检查令牌是否在黑名单中
		if sm.IsTokenBlacklisted(token) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "令牌已失效"})
			c.Abort()
			return
		}

		// 验证会话
		session, err := sm.ValidateSession(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "会话无效或已过期"})
			c.Abort()
			return
		}

		// 获取用户信息
		var username string
		err = sm.db.QueryRow("SELECT username FROM users WHERE id = ?", session.UserID).Scan(&username)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "用户信息获取失败"})
			c.Abort()
			return
		}

		// 将用户信息和会话信息存储到上下文
		c.Set("user_id", session.UserID)
		c.Set("username", username)
		c.Set("session_id", session.ID)
		c.Set("session", session)

		c.Next()
	}
}

// OptionalJWTMiddleware 可选的JWT验证中间件
func OptionalJWTMiddleware(sm *SessionManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			tokenParts := strings.SplitN(authHeader, " ", 2)
			if len(tokenParts) == 2 && tokenParts[0] == "Bearer" {
				token := tokenParts[1]
				
				if !sm.IsTokenBlacklisted(token) {
					if session, err := sm.ValidateSession(token); err == nil {
						// 获取用户信息
						var username string
						if err := sm.db.QueryRow("SELECT username FROM users WHERE id = ?", session.UserID).Scan(&username); err == nil {
							c.Set("user_id", session.UserID)
							c.Set("username", username)
							c.Set("session_id", session.ID)
							c.Set("session", session)
						}
					}
				}
			}
		}
		c.Next()
	}
}
