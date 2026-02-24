package user

import (
	"Dext-Server/config"
	"Dext-Server/model"
	"Dext-Server/security"
	"Dext-Server/utils"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// 统一设置认证Cookie（支持Domain/SameSite，区分dev/prod）
func setAuthCookie(c *gin.Context, token string, expires time.Time) {
	maxAge := int(time.Until(expires).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}
	secure := os.Getenv("ENV") == "production"
	domain := os.Getenv("COOKIE_DOMAIN") //（可空）

	// SameSite 策略：生产用 None；开发用 Lax
	if secure {
		c.SetSameSite(http.SameSiteNoneMode)
	} else {
		c.SetSameSite(http.SameSiteLaxMode)
	}

	c.SetCookie("access_token", token, maxAge, "/", domain, secure, true)
}

// --- Refresh token helpers ---
func issueAndStoreRefreshToken(db *sql.DB, userID string, userAgent string, ip string) (string, time.Time, error) {
	// generate 32 bytes random token and encode as hex
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	token := hex.EncodeToString(b)
	hash := sha256Hex(token)
	expires := time.Now().Add(30 * 24 * time.Hour)
	_, err := db.Exec(`INSERT INTO refresh_tokens (user_id, token_hash, issued_at, expires_at, user_agent, ip_address, is_revoked) VALUES (?, ?, NOW(), ?, ?, ?, 0)`,
		userID, hash, expires, truncate(userAgent, 255), truncate(ip, 64))
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// 根据用户ID获取公开的用户信息（供公开路由使用）
func GetUserProfileHandler(c *gin.Context) {
	db := config.DB
	userID := c.Param("id")

	var username string
	var avatarURL sql.NullString

	err := db.QueryRow(`SELECT username, avatar_url FROM users WHERE id = ?`, userID).Scan(&username, &avatarURL)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("拒绝连接: 访问不存在的用户 %s", userID)
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		utils.SendError(c, http.StatusInternalServerError, "数据库错误")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":    userID,
		"username":   username,
		"avatar_url": avatarURL.String,
	})
}

// 生成自定义过期时间的JWT令牌（受保护路由）
func GenerateCustomTokenHandler(c *gin.Context) {
	username := c.MustGet("username").(string)

	var req struct {
		Expiration string `json:"expiration" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的请求格式")
		return
	}

	expiration, err := time.ParseDuration(req.Expiration)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的过期时间格式，请使用如：1h, 2h30m, 24h, 7d等格式")
		return
	}
	if expiration < 5*time.Minute {
		utils.SendError(c, http.StatusBadRequest, "过期时间不能少于5分钟")
		return
	}
	if expiration > 30*24*time.Hour {
		utils.SendError(c, http.StatusBadRequest, "过期时间不能超过30天")
		return
	}

	tokenString, expires, err := security.GenerateTokenWithExpiration(username, expiration)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "生成令牌失败")
		return
	}

	c.JSON(http.StatusOK, model.AuthResponse{
		Token:   tokenString,
		Expires: expires,
	})
}

// 用户信息处理函数
func GetCurrentUserHandler(c *gin.Context) {
	db := config.DB
	username := c.MustGet("username").(string)

	var user model.User
	var email sql.NullString
	err := db.QueryRow(`
		SELECT id, username, user_role, created_at, updated_at, avatar_url, email
		FROM users
		WHERE username = ?`, username).
		Scan(&user.ID, &user.Username, &user.UserRole, &user.CreatedAt, &user.UpdatedAt, &user.AvatarURL, &email)

	// 处理可能为NULL的email字段
	if email.Valid {
		user.Email = email.String
	}
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "获取用户信息失败", err)
		return
	}

	// 查询OAuth绑定状态
	oauthBindings := make(map[string]interface{})
	rows, err := db.Query(`
		SELECT provider, provider_username, provider_name, provider_avatar, is_primary, created_at
		FROM oauth_bindings 
		WHERE user_id = ?
	`, user.ID)

	if err == nil {
		defer rows.Close()
		bindings := make([]map[string]interface{}, 0)

		for rows.Next() {
			var provider, providerUsername, providerName sql.NullString
			var providerAvatar sql.NullString
			var isPrimary bool
			var createdAt string

			err := rows.Scan(&provider, &providerUsername, &providerName, &providerAvatar, &isPrimary, &createdAt)
			if err == nil {
				binding := map[string]interface{}{
					"provider":   provider.String,
					"is_primary": isPrimary,
					"created_at": createdAt,
				}
				if providerUsername.Valid {
					binding["provider_username"] = providerUsername.String
				}
				if providerName.Valid {
					binding["provider_name"] = providerName.String
				}
				if providerAvatar.Valid {
					binding["provider_avatar"] = providerAvatar.String
				}
				bindings = append(bindings, binding)
			}
		}

		oauthBindings["bindings"] = bindings
		oauthBindings["count"] = len(bindings)

		// 设置各提供商的绑定状态
		providers := []string{"google", "github", "microsoft"}
		for _, provider := range providers {
			bound := false
			for _, binding := range bindings {
				if binding["provider"] == provider {
					bound = true
					break
				}
			}
			oauthBindings[provider+"_bound"] = bound
		}
	}

	// 添加OAuth绑定信息到用户数据
	response := map[string]interface{}{
		"id":             user.ID,
		"username":       user.Username,
		"email":          user.Email,
		"userRole":       user.UserRole,
		"createdAt":      user.CreatedAt,
		"updatedAt":      user.UpdatedAt,
		"avatarUrl":      user.AvatarURL,
		"oauth_bindings": oauthBindings,
	}

	c.JSON(http.StatusOK, response)
}

// 注册处理器
func RegisterHandler(c *gin.Context) {
	db := config.DB
	var req model.UserRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的请求格式", err)
		return
	}
	if !utils.Verify(req.CaptchaId, req.CaptchaValue) {
		utils.SendError(c, http.StatusBadRequest, "验证码错误", nil)
		return
	}

	if len(req.Password) < 8 || len(req.Password) > 64 {
		utils.SendError(c, http.StatusBadRequest, "密码长度必须在8-64位之间", nil)
		return
	}
	if len(req.Username) < 3 || len(req.Username) > 12 {
		utils.SendError(c, http.StatusBadRequest, "用户名长度必须在3-12位之间", nil)
		return
	}

	if !isValidUsername(req.Username) {
		utils.SendError(c, http.StatusBadRequest, "用户名只能包含字母和数字", nil)
		return
	}

	// 验证邮箱格式（如果提供）
	if req.Email != "" && !isValidEmail(req.Email) {
		utils.SendError(c, http.StatusBadRequest, "邮箱格式不正确", nil)
		return
	}

	// 检查用户名是否已存在
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", req.Username).Scan(&count)
	if err != nil {
		utils.LogError("检查用户名失败", err)
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}
	if count > 0 {
		utils.SendError(c, http.StatusBadRequest, "用户名已被使用", nil)
		return
	}

	// 检查邮箱是否已存在（如果提供）
	if req.Email != "" {
		err = db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", req.Email).Scan(&count)
		if err != nil {
			utils.LogError("检查邮箱失败", err)
			utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
			return
		}
		if count > 0 {
			utils.SendError(c, http.StatusBadRequest, "邮箱已被使用", nil)
			return
		}
	}

	// 使用Argon2id哈希密码
	pepper := security.GetPepper()
	hashedPassword, err := security.HashPassword(req.Password, pepper)
	if err != nil {
		utils.LogError("密码哈希失败", err)
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}

	userID := utils.GenerateCustomUserID() // 生成自定义格式的 UserID

	// 如果提供了邮箱，需要验证邮箱验证码
	var emailVerified bool
	if req.Email != "" {
		// 验证邮箱验证码
		var verified bool
		var expiresAt time.Time
		err = db.QueryRow(`
			SELECT verified, expires_at FROM email_verifications
			WHERE email = ? AND code = ? AND purpose = 'register'
			ORDER BY created_at DESC LIMIT 1
		`, req.Email, req.EmailCode).Scan(&verified, &expiresAt)

		if err != nil {
			if err == sql.ErrNoRows {
				utils.SendError(c, http.StatusBadRequest, "邮箱验证码不存在或已过期", nil)
				return
			}
			utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
			return
		}

		if verified {
			utils.SendError(c, http.StatusBadRequest, "验证码已使用", nil)
			return
		}

		if time.Now().After(expiresAt) {
			utils.SendError(c, http.StatusBadRequest, "验证码已过期", nil)
			return
		}

		emailVerified = true
	}

	// 开启事务
	tx, err := db.Begin()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}
	defer tx.Rollback()

	// 插入用户
	var stmt *sql.Stmt
	if req.Email != "" {
		stmt, err = tx.Prepare("INSERT INTO users (id, username, password_hash, email, email_verified, email_verified_at) VALUES (?, ?, ?, ?, ?, NOW())")
		if err != nil {
			utils.LogError("预处理语句创建失败", err)
			utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
			return
		}
		defer stmt.Close()
		_, err = stmt.Exec(userID, req.Username, hashedPassword, req.Email, emailVerified)
	} else {
		stmt, err = tx.Prepare("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)")
		if err != nil {
			utils.LogError("预处理语句创建失败", err)
			utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
			return
		}
		defer stmt.Close()
		_, err = stmt.Exec(userID, req.Username, hashedPassword)
	}

	if err != nil {
		utils.LogError("数据库写入失败", err)
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}

	// 如果有邮箱验证码，标记为已使用
	if req.Email != "" && req.EmailCode != "" {
		_, err = tx.Exec(`
			UPDATE email_verifications 
			SET verified = TRUE, verified_at = NOW()
			WHERE email = ? AND code = ? AND purpose = 'register'
		`, req.Email, req.EmailCode)

		if err != nil {
			utils.LogError("更新验证状态失败", err)
			utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
			return
		}
	}

	// 提交事务
	if err = tx.Commit(); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "注册失败", err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "用户注册成功", "userId": userID})
}

func isValidUsername(username string) bool {
	for _, c := range username {
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func isValidEmail(email string) bool {
	// 简单的邮箱格式验证
	if len(email) < 3 || len(email) > 255 {
		return false
	}
	atIndex := strings.Index(email, "@")
	if atIndex <= 0 || atIndex == len(email)-1 {
		return false
	}
	dotIndex := strings.LastIndex(email, ".")
	if dotIndex <= atIndex+1 || dotIndex == len(email)-1 {
		return false
	}
	return true
}

// 登录处理器
func LoginHandler(c *gin.Context) {
	db := config.DB

	var req struct {
		Username     string `json:"username" binding:"required"`
		Password     string `json:"password" binding:"required"`
		CaptchaId    string `json:"captchaId"`
		CaptchaValue string `json:"captchaValue"`
		Expiration   string `json:"expiration"`
		SessionKey   string `json:"sessionKey"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效请求格式", err)
		return
	}
	if !utils.Verify(req.CaptchaId, req.CaptchaValue) {
		utils.SendError(c, http.StatusBadRequest, "验证码错误", nil)
		return
	}

	var storedUser struct {
		ID             string
		PasswordHash   string
		FailedAttempts int
		LockedUntil    *time.Time
	}

	stmt, err := db.Prepare("SELECT id, password_hash, failed_attempts, locked_until FROM users WHERE username = ?")
	if err != nil {
		utils.LogError("预处理语句创建失败", err)
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}
	defer stmt.Close()

	err = stmt.QueryRow(req.Username).Scan(&storedUser.ID, &storedUser.PasswordHash, &storedUser.FailedAttempts, &storedUser.LockedUntil)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// 防止时序攻击
			pepper := security.GetPepper()
			security.VerifyPassword(req.Password, pepper, "$argon2id$v=19$m=65536,t=1,p=4$fakeSaltForTiming$fakeHashForTiming")
			utils.SendError(c, http.StatusUnauthorized, "认证失败", nil)
			return
		}
		utils.LogError("数据库查询失败", err)
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}

	// 检查账户是否被锁定
	if storedUser.LockedUntil != nil && storedUser.LockedUntil.After(time.Now()) {
		remaining := time.Until(*storedUser.LockedUntil).Round(time.Minute)
		utils.SendError(c, http.StatusTooManyRequests,
			fmt.Sprintf("账户已锁定，请%d分钟后再试", int(remaining.Minutes())), nil)
		return
	}

	pepper := security.GetPepper()
	var passwordValid bool
	var passwordErr error

	if security.IsArgon2Hash(storedUser.PasswordHash) {
		passwordValid, passwordErr = security.VerifyPassword(req.Password, pepper, storedUser.PasswordHash)
	} else {
		passwordErr = fmt.Errorf("不支持的密码哈希格式")
		passwordValid = false
	}

	if passwordErr != nil || !passwordValid {
		tx, err := db.Begin()
		if err != nil {
			utils.LogError("事务开启失败", err)
			utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
			return
		}

		var currentAttempts int
		var currentLockedUntil *time.Time
		err = tx.QueryRow("SELECT failed_attempts, locked_until FROM users WHERE id = ? FOR UPDATE", storedUser.ID).
			Scan(&currentAttempts, &currentLockedUntil)
		if err != nil {
			tx.Rollback()
			utils.LogError("获取锁定状态失败", err)
			utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
			return
		}

		if currentLockedUntil != nil && currentLockedUntil.After(time.Now()) {
			tx.Rollback()
			remaining := time.Until(*currentLockedUntil).Round(time.Minute)
			utils.SendError(c, http.StatusTooManyRequests,
				fmt.Sprintf("账户已锁定，请%d分钟后再试", int(remaining.Minutes())), nil)
			return
		}

		newAttempts := currentAttempts + 1
		var updateErr error
		if newAttempts >= 5 {
			lockTime := time.Now().Add(10 * time.Minute)
			_, updateErr = tx.Exec("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
				newAttempts, lockTime, storedUser.ID)
		} else {
			_, updateErr = tx.Exec("UPDATE users SET failed_attempts = ? WHERE id = ?",
				newAttempts, storedUser.ID)
		}

		if updateErr != nil {
			tx.Rollback()
			utils.LogError("更新尝试次数失败", updateErr)
			utils.SendError(c, http.StatusInternalServerError, "系统错误", updateErr)
			return
		}

		if err := tx.Commit(); err != nil {
			utils.LogError("提交事务失败", err)
			utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
			return
		}

		if newAttempts >= 5 {
			utils.SendError(c, http.StatusTooManyRequests, "账户已锁定，请10分钟后再试", nil)
		} else {
			utils.SendError(c, http.StatusUnauthorized,
				fmt.Sprintf("认证失败，剩余尝试次数：%d", 5-newAttempts), nil)
		}
		return
	}

	// 登录成功，重置尝试次数
	if _, err := db.Exec("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
		storedUser.ID); err != nil {
		utils.LogError("重置登录尝试失败", err)
	}

	// 处理自定义过期时间
	var expiration time.Duration
	if req.Expiration != "" {
		if customExpiration, err := time.ParseDuration(req.Expiration); err == nil {
			if customExpiration >= 5*time.Minute && customExpiration <= 30*24*time.Hour {
				expiration = customExpiration
			} else {
				utils.SendError(c, http.StatusBadRequest, "过期时间必须在5分钟到30天之间", nil)
				return
			}
		} else {
			utils.SendError(c, http.StatusBadRequest, "无效的过期时间格式，请使用如：1h, 2h30m, 24h, 7d等格式", nil)
			return
		}
	} else {
		expiration = security.GetTokenExpiration()
	}

	// 生成JWT令牌（以用户ID作为Subject，避免改名导致旧令牌失效）
	tokenString, expires, err := security.GenerateTokenWithExpiration(storedUser.ID, expiration)
	if err != nil {
		utils.LogError("令牌生成失败", err)
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}

	// 处理会话密钥（如果提供）
	var sessionKeyData string
	if req.SessionKey != "" {
		// 解密客户端发送的会话密钥
		sessionKeyBytes, err := security.DecryptSessionKey(req.SessionKey)
		if err != nil {
			utils.LogError("解密会话密钥失败", err)
			utils.SendError(c, http.StatusBadRequest, "会话密钥解密失败", err)
			return
		}
		sessionKeyData = string(sessionKeyBytes)

		// 解析并存储会话密钥
		sessionKey, err := security.SessionKeyFromBase64(sessionKeyData)
		if err != nil {
			utils.LogError("解析会话密钥失败", err)
			utils.SendError(c, http.StatusBadRequest, "会话密钥格式错误", err)
			return
		}

		// 存储用户的会话密钥
		err = security.StoreSessionKey(req.Username, sessionKey)
		if err != nil {
			utils.LogError("存储会话密钥失败", err)
			utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
			return
		}

		// 额外：按会话ID(JTI)存储，便于用户名变更后仍可解密
		// 解析当前签发的JWT以获取JTI
		secrets, err := security.LoadSecrets()
		if err == nil && len(secrets) > 0 {
			tokenOnly := tokenString
			for _, secret := range secrets {
				claims := &jwt.RegisteredClaims{}
				if t, e := jwt.ParseWithClaims(tokenOnly, claims, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("不支持的签名算法: %v", token.Header["alg"])
					}
					return []byte(secret.Secret), nil
				}); e == nil && t.Valid {
					if claims.ID != "" {
						_ = security.StoreSessionKeyForSession(claims.ID, sessionKey)
					}
					break
				}
			}
		}
	}

	// 生成刷新令牌并持久化（默认30天）
	refreshToken, refreshExpires, err := issueAndStoreRefreshToken(db, storedUser.ID, c.Request.UserAgent(), c.ClientIP())
	if err != nil {
		utils.LogError("生成刷新令牌失败", err)
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}

	response := model.AuthResponse{
		Token:          tokenString,
		Expires:        expires,
		RefreshToken:   refreshToken,
		RefreshExpires: refreshExpires,
	}

	// 在Cookie中设置HttpOnly的access_token（按环境设置 SameSite/Domain）
	setAuthCookie(c, tokenString, expires)

	// 检查请求是否使用 XChaCha 加密
	requestEncryptionType := c.GetHeader("X-Encrypted")

	// 如果请求使用 XChaCha 加密，让响应加密中间件处理
	if requestEncryptionType == "xchacha" {
		// 返回未加密的 JSON 响应，让响应加密中间件处理
		c.JSON(http.StatusOK, response)
		return
	}

	// 如果有会话密钥且请求使用 AES 加密，使用AES加密响应
	if sessionKeyData != "" && requestEncryptionType == "aes" {
		sessionKey, err := security.SessionKeyFromBase64(sessionKeyData)
		if err != nil {
			utils.LogError("解析会话密钥失败", err)
			utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
			return
		}

		// 将响应序列化为JSON
		responseBytes, err := json.Marshal(response)
		if err != nil {
			utils.LogError("序列化响应失败", err)
			utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
			return
		}

		// 使用会话密钥加密响应
		encryptedResponse, err := security.EncryptWithSessionKeyGCM(responseBytes, sessionKey)
		if err != nil {
			utils.LogError("加密响应失败", err)
			utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
			return
		}

		// 返回加密的响应
		c.Header("X-Encrypted", "aes")
		c.Data(http.StatusOK, "application/octet-stream", encryptedResponse)
	} else {
		// 返回未加密的响应（向后兼容）
		c.JSON(http.StatusOK, response)
	}
}

// 刷新令牌处理函数
func RefreshHandler(c *gin.Context) {
	db := config.DB

	// 接收刷新令牌
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的请求格式", err)
		return
	}

	// 校验刷新令牌（查库）
	hash := sha256Hex(req.RefreshToken)
	var userID string
	var expiresAt time.Time
	var revoked int
	err := db.QueryRow(`SELECT user_id, expires_at, is_revoked FROM refresh_tokens WHERE token_hash = ?`, hash).Scan(&userID, &expiresAt, &revoked)
	if err != nil {
		if err == sql.ErrNoRows {
			utils.SendError(c, http.StatusUnauthorized, "刷新令牌无效", nil)
			return
		}
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}
	if revoked == 1 || time.Now().After(expiresAt) {
		utils.SendError(c, http.StatusUnauthorized, "刷新令牌已失效", nil)
		return
	}

	// 生成新的访问令牌
	newAccess, accessExpires, err := security.GenerateToken(userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "令牌生成失败", err)
		return
	}

	// 令牌轮换：撤销旧刷新令牌并签发新的刷新令牌（滑动续期）
	if _, e := db.Exec(`UPDATE refresh_tokens SET is_revoked = 1, last_used_at = NOW() WHERE token_hash = ?`, hash); e != nil {
		utils.LogError("撤销旧刷新令牌失败", e)
	}
	newRefresh, refreshExpires, err := issueAndStoreRefreshToken(db, userID, c.Request.UserAgent(), c.ClientIP())
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "生成刷新令牌失败", err)
		return
	}

	// 设置新的访问令牌到Cookie
	setAuthCookie(c, newAccess, accessExpires)

	c.JSON(http.StatusOK, model.AuthResponse{
		Token:          newAccess,
		Expires:        accessExpires,
		RefreshToken:   newRefresh,
		RefreshExpires: refreshExpires,
	})
}

// 注销接口
func LogoutHandler(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	// 兼容从Cookie读取
	if cookieToken, err := c.Cookie("access_token"); (tokenString == "" || tokenString == "Bearer ") && err == nil {
		tokenString = "Bearer " + cookieToken
	}
	if tokenString == "" {
		utils.SendError(c, http.StatusBadRequest, "缺少令牌", nil)
		return
	}

	// 从令牌中提取用户名和会话ID
	username, _ := c.Get("username")

	// 1. 将令牌添加到Redis黑名单
	err := config.AddToBlacklist(tokenString)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "无法注销令牌", err)
		return
	}

	// 2. 清除用户的会话密钥（重要安全措施）
	if username != nil {
		if usernameStr, ok := username.(string); ok {
			security.RemoveSessionKey(usernameStr)
		}
	}

	// 2.1 撤销该用户的所有刷新令牌
	if uid, ok := c.Get("user_id"); ok {
		if userID, ok2 := uid.(string); ok2 && userID != "" {
			_, _ = config.DB.Exec("UPDATE refresh_tokens SET is_revoked = 1 WHERE user_id = ?", userID)
		}
	}

	// 3. 尝试从JWT中提取JTI并清除对应的会话密钥
	if jti, exists := c.Get("jti"); exists {
		if jtiStr, ok := jti.(string); ok {
			security.RemoveSessionKey(jtiStr)
		}
	} else {
		// 如果没有JTI，尝试从令牌中解析
		parts := strings.Split(tokenString, " ")
		if len(parts) == 2 {
			token, err := jwt.ParseWithClaims(parts[1], &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
				secrets, err := security.LoadSecrets()
				if err != nil || len(secrets) == 0 {
					return nil, fmt.Errorf("无法加载JWT密钥")
				}
				return []byte(secrets[0].Secret), nil
			})

			if err == nil && token.Valid {
				if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && claims.ID != "" {
					security.RemoveSessionKey(claims.ID)
				}
			}
		}
	}

	// 4. 清除Cookie（保持同域同SameSite策略）
	secure := os.Getenv("ENV") == "production"
	domain := os.Getenv("COOKIE_DOMAIN")
	if secure {
		c.SetSameSite(http.SameSiteNoneMode)
	} else {
		c.SetSameSite(http.SameSiteLaxMode)
	}
	c.SetCookie("access_token", "", -1, "/", domain, secure, true)

	c.JSON(http.StatusOK, gin.H{"message": "注销成功"})
}

// ResetPasswordWithEmailHandler 通过邮箱验证码重置密码
func ResetPasswordWithEmailHandler(c *gin.Context) {
	db := config.DB

	var req struct {
		Email       string `json:"email" binding:"required,email"`
		Code        string `json:"code" binding:"required,len=6"`
		NewPassword string `json:"newPassword" binding:"required,min=8,max=64"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的请求格式", err)
		return
	}

	// 标准化邮箱地址
	email := strings.ToLower(strings.TrimSpace(req.Email))

	// 验证邮箱验证码
	var verified bool
	var expiresAt time.Time
	err := db.QueryRow(`
		SELECT verified, expires_at FROM email_verifications
		WHERE email = ? AND code = ? AND purpose = 'reset_password'
		ORDER BY created_at DESC LIMIT 1
	`, email, req.Code).Scan(&verified, &expiresAt)

	if err != nil {
		if err == sql.ErrNoRows {
			utils.SendError(c, http.StatusBadRequest, "验证码不存在或已过期", nil)
			return
		}
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}

	if verified {
		utils.SendError(c, http.StatusBadRequest, "验证码已使用", nil)
		return
	}

	if time.Now().After(expiresAt) {
		utils.SendError(c, http.StatusBadRequest, "验证码已过期", nil)
		return
	}

	// 获取用户ID
	var userID string
	err = db.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("拒绝连接: 邮箱 %s 对应的用户不存在", email)
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}

	// 使用Argon2id哈希新密码
	pepper := security.GetPepper()
	hashedPassword, err := security.HashPassword(req.NewPassword, pepper)
	if err != nil {
		utils.LogError("密码哈希失败", err)
		utils.SendError(c, http.StatusInternalServerError, "密码加密失败", err)
		return
	}

	// 开启事务
	tx, err := db.Begin()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}
	defer tx.Rollback()

	// 更新密码
	_, err = tx.Exec(`
		UPDATE users 
		SET password_hash = ?, updated_at = CURRENT_TIMESTAMP 
		WHERE id = ?
	`, hashedPassword, userID)

	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "密码更新失败", err)
		return
	}

	// 标记验证码为已使用
	_, err = tx.Exec(`
		UPDATE email_verifications 
		SET verified = TRUE, verified_at = NOW()
		WHERE email = ? AND code = ? AND purpose = 'reset_password'
	`, email, req.Code)

	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "更新验证状态失败", err)
		return
	}

	// 提交事务
	if err = tx.Commit(); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "操作失败", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "密码重置成功",
	})
}

// ChangeEmailHandler 更换邮箱（需要登录、密码验证和邮箱验证码）
func ChangeEmailHandler(c *gin.Context) {
	db := config.DB

	// 获取当前用户
	userID, exists := c.Get("user_id")
	if !exists {
		utils.SendError(c, http.StatusUnauthorized, "请先登录", nil)
		return
	}

	var req struct {
		NewEmail string `json:"newEmail" binding:"required,email"`
		Password string `json:"password" binding:"required"`
		Code     string `json:"code" binding:"required,len=6"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的请求格式", err)
		return
	}

	// 验证用户密码
	var passwordHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&passwordHash)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}

	// 使用Argon2id验证密码
	pepper := security.GetPepper()
	valid, err := security.VerifyPassword(req.Password, pepper, passwordHash)
	if err != nil || !valid {
		utils.SendError(c, http.StatusUnauthorized, "密码错误", nil)
		return
	}

	// 标准化邮箱地址
	newEmail := strings.ToLower(strings.TrimSpace(req.NewEmail))

	// 验证邮箱验证码
	var verified bool
	var expiresAt time.Time
	err = db.QueryRow(`
		SELECT verified, expires_at FROM email_verifications
		WHERE email = ? AND code = ? AND purpose = 'change_email'
		ORDER BY created_at DESC LIMIT 1
	`, newEmail, req.Code).Scan(&verified, &expiresAt)

	if err != nil {
		if err == sql.ErrNoRows {
			utils.SendError(c, http.StatusBadRequest, "验证码不存在或已过期", nil)
			return
		}
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}

	if verified {
		utils.SendError(c, http.StatusBadRequest, "验证码已使用", nil)
		return
	}

	if time.Now().After(expiresAt) {
		utils.SendError(c, http.StatusBadRequest, "验证码已过期", nil)
		return
	}

	// 检查新邮箱是否已被使用
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ? AND id != ?", newEmail, userID).Scan(&count)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}
	if count > 0 {
		utils.SendError(c, http.StatusBadRequest, "该邮箱已被使用", nil)
		return
	}

	// 开启事务
	tx, err := db.Begin()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}
	defer tx.Rollback()

	// 更新邮箱
	_, err = tx.Exec(`
		UPDATE users 
		SET email = ?, email_verified = TRUE, email_verified_at = NOW(), updated_at = CURRENT_TIMESTAMP 
		WHERE id = ?
	`, newEmail, userID)

	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "邮箱更新失败", err)
		return
	}

	// 标记验证码为已使用
	_, err = tx.Exec(`
		UPDATE email_verifications 
		SET verified = TRUE, verified_at = NOW()
		WHERE email = ? AND code = ? AND purpose = 'change_email'
	`, newEmail, req.Code)

	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "更新验证状态失败", err)
		return
	}

	// 提交事务
	if err = tx.Commit(); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "操作失败", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "邮箱更换成功",
		"email":   newEmail,
	})
}

// ChangePasswordHandler 修改密码（需要登录和旧密码验证）
func ChangePasswordHandler(c *gin.Context) {
	db := config.DB

	// 获取当前用户
	userID, exists := c.Get("user_id")
	if !exists {
		utils.SendError(c, http.StatusUnauthorized, "请先登录", nil)
		return
	}

	var req struct {
		OldPassword string `json:"oldPassword" binding:"required"`
		NewPassword string `json:"newPassword" binding:"required,min=8,max=64"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的请求格式", err)
		return
	}

	// 验证旧密码
	var passwordHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE id = ?", userID).Scan(&passwordHash)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}

	// 使用Argon2id验证旧密码
	pepper := security.GetPepper()
	valid, err := security.VerifyPassword(req.OldPassword, pepper, passwordHash)
	if err != nil || !valid {
		utils.SendError(c, http.StatusUnauthorized, "旧密码错误", nil)
		return
	}

	// 使用Argon2id生成新密码哈希
	newPasswordHash, err := security.HashPassword(req.NewPassword, pepper)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "密码加密失败", err)
		return
	}

	// 更新密码
	_, err = db.Exec(`
		UPDATE users 
		SET password_hash = ?, updated_at = CURRENT_TIMESTAMP 
		WHERE id = ?
	`, newPasswordHash, userID)

	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "密码更新失败", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "密码修改成功",
	})
}

// 更新用户名处理器
func UpdateUsernameHandler(c *gin.Context) {
	db := config.DB
	currentUsername := c.MustGet("username").(string)
	userID := c.MustGet("user_id").(string)

	var req model.UserUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的请求格式", err)
		return
	}

	// 验证新用户名格式
	if !isValidUsername(req.NewUsername) {
		utils.SendError(c, http.StatusBadRequest, "用户名只能包含字母和数字", nil)
		return
	}

	// 检查新用户名是否已被使用
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ? AND id != ?",
		req.NewUsername, userID).Scan(&count)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}
	if count > 0 {
		utils.SendError(c, http.StatusBadRequest, "用户名已被使用", nil)
		return
	}

	// 开启事务进行用户名更新
	tx, err := db.Begin()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}
	defer tx.Rollback()

	// 更新users表
	_, err = tx.Exec("UPDATE users SET username = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		req.NewUsername, userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "更新用户名失败", err)
		return
	}

	// 更新projects表中的create_by和update_by字段
	_, err = tx.Exec("UPDATE projects SET create_by = ? WHERE create_by = ?",
		req.NewUsername, currentUsername)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "更新项目关联失败", err)
		return
	}

	_, err = tx.Exec("UPDATE projects SET update_by = ? WHERE update_by = ?",
		req.NewUsername, currentUsername)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "更新项目关联失败", err)
		return
	}

	// 更新survey_backgrounds表中的created_by字段
	_, err = tx.Exec("UPDATE survey_backgrounds SET created_by = ? WHERE created_by = ?",
		req.NewUsername, currentUsername)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "更新问卷背景关联失败", err)
		return
	}

	// 更新survey_assets_files表中的username字段
	_, err = tx.Exec("UPDATE survey_assets_files SET username = ? WHERE username = ?",
		req.NewUsername, currentUsername)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "更新问卷资源关联失败", err)
		return
	}

	// 更新user_images表中的owner字段
	_, err = tx.Exec("UPDATE user_images SET owner = ? WHERE owner = ?",
		req.NewUsername, currentUsername)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "更新用户图片关联失败", err)
		return
	}

	// 提交事务
	if err = tx.Commit(); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "更新失败", err)
		return
	}

	// 读取旧token以便黑名单吊销与会话密钥迁移
	oldAuthHeader := c.GetHeader("Authorization")
	if oldAuthHeader == "" {
		if cookieToken, err := c.Cookie("access_token"); err == nil && cookieToken != "" {
			oldAuthHeader = "Bearer " + cookieToken
		}
	}

	// 生成新的JWT令牌（以用户ID作为Subject，改名不影响会话）
	newToken, expires, err := security.GenerateToken(userID)
	if err != nil {
		utils.LogError("生成新令牌失败", err)
		utils.SendError(c, http.StatusInternalServerError, "生成新令牌失败", err)
		return
	}

	// 会话密钥迁移：将旧JTI下的AES会话密钥复制到新JTI
	func() {
		// 解析旧token与新token的JTI
		secrets, e := security.LoadSecrets()
		if e != nil || len(secrets) == 0 {
			return
		}
		// 解析旧JTI
		var oldJTI string
		if strings.HasPrefix(oldAuthHeader, "Bearer ") {
			raw := strings.TrimPrefix(oldAuthHeader, "Bearer ")
			claims := &jwt.RegisteredClaims{}
			for _, s := range secrets {
				if t, pe := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("alg")
					}
					return []byte(s.Secret), nil
				}); pe == nil && t.Valid {
					oldJTI = claims.ID
					break
				}
			}
		}
		// 解析新JTI
		var newJTI string
		{
			claims := &jwt.RegisteredClaims{}
			for _, s := range secrets {
				if t, pe := jwt.ParseWithClaims(newToken, claims, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("alg")
					}
					return []byte(s.Secret), nil
				}); pe == nil && t.Valid {
					newJTI = claims.ID
					break
				}
			}
		}
		if oldJTI != "" && newJTI != "" {
			if sk, ge := security.GetSessionKeyBySessionID(oldJTI); ge == nil && sk != nil {
				_ = security.StoreSessionKeyForSession(newJTI, sk)
			}
		}
	}()

	// 将旧token加入黑名单，强制旧令牌立刻失效
	if oldAuthHeader != "" {
		_ = config.AddToBlacklist(oldAuthHeader)
	}

	// 同步更新Cookie中的token
	setAuthCookie(c, newToken, expires)

	c.JSON(http.StatusOK, gin.H{
		"message":     "用户名更新成功",
		"newUsername": req.NewUsername,
		"token":       newToken,
		"expires":     expires,
	})
}

// ChangePasswordWithEmailHandler 使用邮箱验证码修改密码（需要登录）
func ChangePasswordWithEmailHandler(c *gin.Context) {
	// 获取当前用户ID
	userID, exists := c.Get("user_id")
	if !exists {
		utils.SendError(c, http.StatusUnauthorized, "未授权", nil)
		return
	}

	var req struct {
		Code        string `json:"code" binding:"required"`
		NewPassword string `json:"newPassword" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "请求参数错误", err)
		return
	}

	// 验证新密码长度
	if len(req.NewPassword) < 8 || len(req.NewPassword) > 64 {
		utils.SendError(c, http.StatusBadRequest, "密码长度必须在8-64个字符之间", nil)
		return
	}

	// 获取用户邮箱
	var email string
	err := config.DB.QueryRow("SELECT email FROM users WHERE id = ?", userID).Scan(&email)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("拒绝连接: 用户 %s 不存在", userID)
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}

	if email == "" {
		utils.SendError(c, http.StatusBadRequest, "用户未绑定邮箱", nil)
		return
	}

	// 验证邮箱验证码
	var verified bool
	var expiresAt time.Time
	err = config.DB.QueryRow(`
		SELECT verified, expires_at FROM email_verifications
		WHERE email = ? AND code = ? AND purpose = 'reset_password'
		ORDER BY created_at DESC LIMIT 1
	`, email, req.Code).Scan(&verified, &expiresAt)

	if err != nil {
		if err == sql.ErrNoRows {
			utils.SendError(c, http.StatusBadRequest, "验证码不存在或已过期", nil)
			return
		}
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}

	if verified {
		utils.SendError(c, http.StatusBadRequest, "验证码已使用", nil)
		return
	}

	if time.Now().After(expiresAt) {
		utils.SendError(c, http.StatusBadRequest, "验证码已过期", nil)
		return
	}

	// 使用Argon2id哈希新密码
	pepper := security.GetPepper()
	hashedPassword, err := security.HashPassword(req.NewPassword, pepper)
	if err != nil {
		utils.LogError("密码哈希失败", err)
		utils.SendError(c, http.StatusInternalServerError, "密码加密失败", err)
		return
	}

	// 开启事务
	tx, err := config.DB.Begin()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}
	defer tx.Rollback()

	// 更新密码
	_, err = tx.Exec(`
		UPDATE users 
		SET password_hash = ?, updated_at = CURRENT_TIMESTAMP 
		WHERE id = ?
	`, hashedPassword, userID)

	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "密码更新失败", err)
		return
	}

	// 标记验证码为已使用
	_, err = tx.Exec(`
		UPDATE email_verifications 
		SET verified = TRUE, verified_at = NOW()
		WHERE email = ? AND code = ? AND purpose = 'reset_password'
	`, email, req.Code)

	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "更新验证状态失败", err)
		return
	}

	// 提交事务
	if err = tx.Commit(); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}

	log.Printf("用户 %s 使用邮箱验证码成功修改密码", userID)

	c.JSON(http.StatusOK, gin.H{
		"message": "密码修改成功",
	})
}
