package oauth

import (
	"Dext-Server/model"
	"Dext-Server/module/session"
	"Dext-Server/security"
	"Dext-Server/utils"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var db *sql.DB
var oauthConfig *Config
var sessionManager *session.SessionManager

// 初始化OAuth模块
func InitOAuth(database *sql.DB) {
	db = database
	oauthConfig = LoadConfig()
	sessionManager = session.NewSessionManager(database)

	if !oauthConfig.IsValid() {
		log.Println("警告: OAuth配置不完整，某些OAuth提供商可能无法使用")
	}
}

// OAuth认证请求结构
type OAuthRequest struct {
	Provider  string                 `json:"provider"`
	OAuthData map[string]interface{} `json:"oauth_data"`
}

// OAuth用户信息结构
type OAuthUserInfo struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Picture  string `json:"picture"`
	Username string `json:"username,omitempty"`
	Provider string `json:"provider"`
}

// OAuth认证处理器
func OAuthHandler(c *gin.Context) {
	var req OAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求格式"})
		return
	}

	// 验证提供商
	if !isValidProvider(req.Provider) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不支持的OAuth提供商"})
		return
	}

	var userInfo *OAuthUserInfo
	var accessToken string

	// 检查是否提供了授权码（Web端流程）
	if authCode, ok := req.OAuthData["authorization_code"].(string); ok && authCode != "" {
		redirectUri := getString(req.OAuthData, "redirect_uri")

		// 使用授权码交换访问令牌并获取用户信息
		var err error
		userInfo, accessToken, err = exchangeCodeForToken(req.Provider, authCode, redirectUri)
		if err != nil {
			log.Printf("授权码交换失败: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "授权码验证失败"})
			return
		}
	} else {
		// 原生端流程：直接使用访问令牌
		userInfoData, ok := req.OAuthData["user_info"].(map[string]interface{})
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "缺少用户信息"})
			return
		}

		userInfo = &OAuthUserInfo{
			ID:       getString(userInfoData, "id"),
			Email:    getString(userInfoData, "email"),
			Name:     getString(userInfoData, "name"),
			Picture:  getString(userInfoData, "picture"),
			Username: getString(userInfoData, "username"),
			Provider: req.Provider,
		}

		var tokenOk bool
		accessToken, tokenOk = req.OAuthData["access_token"].(string)
		if !tokenOk || accessToken == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "缺少访问令牌"})
			return
		}

		// 验证令牌有效性
		if !verifyOAuthToken(req.Provider, accessToken, userInfo) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "OAuth令牌验证失败"})
			return
		}
	}

	// 验证必要字段
	if userInfo.ID == "" || userInfo.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少必要的用户信息"})
		return
	}

	// 查找或创建用户
	user, err := findOrCreateOAuthUser(userInfo)
	if err != nil {
		log.Printf("OAuth用户处理失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "用户处理失败"})
		return
	}

	// 生成JWT令牌
	token, expires, err := security.GenerateJWT(user.ID, user.Username)
	if err != nil {
		log.Printf("JWT生成失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "令牌生成失败"})
		return
	}

	// 创建会话记录
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	_, err = sessionManager.CreateSession(user.ID, token, clientIP, userAgent, expires)
	if err != nil {
		log.Printf("创建会话失败: %v", err)
		// 不阻塞登录流程，仅记录错误
	}

	c.JSON(http.StatusOK, gin.H{
		"token":   token,
		"expires": expires.Format(time.RFC3339),
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
		},
	})
}

// 验证OAuth提供商
func isValidProvider(provider string) bool {
	validProviders := []string{"google", "github", "microsoft"}
	for _, p := range validProviders {
		if p == provider {
			return true
		}
	}
	return false
}

// 从map中安全获取字符串值
func getString(data map[string]interface{}, key string) string {
	if val, ok := data[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// 验证OAuth令牌
func verifyOAuthToken(provider, accessToken string, userInfo *OAuthUserInfo) bool {
	switch provider {
	case "google":
		return verifyGoogleToken(accessToken, userInfo)
	case "github":
		return verifyGitHubToken(accessToken, userInfo)
	case "microsoft":
		return verifyMicrosoftToken(accessToken, userInfo)
	default:
		return false
	}
}

// 验证Google令牌
func verifyGoogleToken(accessToken string, userInfo *OAuthUserInfo) bool {
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		log.Printf("创建Google请求失败: %v", err)
		return false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Google令牌验证请求失败: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Google令牌验证失败，状态码: %d", resp.StatusCode)
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("读取Google响应失败: %v", err)
		return false
	}

	var googleUser map[string]interface{}
	if err := json.Unmarshal(body, &googleUser); err != nil {
		log.Printf("解析Google响应失败: %v", err)
		return false
	}

	// 验证用户ID匹配
	if getString(googleUser, "id") != userInfo.ID {
		log.Printf("Google用户ID不匹配")
		return false
	}

	return true
}

// 验证GitHub令牌
func verifyGitHubToken(accessToken string, userInfo *OAuthUserInfo) bool {
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		log.Printf("创建GitHub请求失败: %v", err)
		return false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("GitHub令牌验证请求失败: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("GitHub令牌验证失败，状态码: %d", resp.StatusCode)
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("读取GitHub响应失败: %v", err)
		return false
	}

	var githubUser map[string]interface{}
	if err := json.Unmarshal(body, &githubUser); err != nil {
		log.Printf("解析GitHub响应失败: %v", err)
		return false
	}

	// 验证用户ID匹配
	githubID := fmt.Sprintf("%.0f", githubUser["id"])
	if githubID != userInfo.ID {
		log.Printf("GitHub用户ID不匹配")
		return false
	}

	return true
}

// 验证Microsoft令牌
func verifyMicrosoftToken(accessToken string, userInfo *OAuthUserInfo) bool {
	req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		log.Printf("创建Microsoft请求失败: %v", err)
		return false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Microsoft令牌验证请求失败: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Microsoft令牌验证失败，状态码: %d", resp.StatusCode)
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("读取Microsoft响应失败: %v", err)
		return false
	}

	var msUser map[string]interface{}
	if err := json.Unmarshal(body, &msUser); err != nil {
		log.Printf("解析Microsoft响应失败: %v", err)
		return false
	}

	// 验证用户ID匹配
	if getString(msUser, "id") != userInfo.ID {
		log.Printf("Microsoft用户ID不匹配")
		return false
	}

	return true
}

// 查找或创建OAuth用户
func findOrCreateOAuthUser(userInfo *OAuthUserInfo) (*model.User, error) {
	// 首先检查是否已有该provider的绑定记录
	var existingUser model.User
	err := db.QueryRow(`
		SELECT u.id, u.username, u.email, u.password_hash, u.created_at, u.updated_at 
		FROM users u
		JOIN oauth_bindings ob ON u.id = ob.user_id
		WHERE ob.provider = ? AND ob.provider_user_id = ? AND u.is_delete = 0
	`, userInfo.Provider, userInfo.ID).Scan(
		&existingUser.ID, &existingUser.Username, &existingUser.Email,
		&existingUser.Password, &existingUser.CreatedAt, &existingUser.UpdatedAt,
	)

	if err == nil {
		// 已有绑定记录，检查邮箱是否发生变更
		var oldEmail string
		err = db.QueryRow(`
			SELECT provider_email FROM oauth_bindings 
			WHERE user_id = ? AND provider = ?
		`, existingUser.ID, userInfo.Provider).Scan(&oldEmail)

		if err == nil && oldEmail != userInfo.Email {
			log.Printf("检测到OAuth邮箱变更: %s -> %s (用户: %s, 提供商: %s)",
				oldEmail, userInfo.Email, existingUser.ID, userInfo.Provider)

			// 检查新邮箱是否被其他用户占用
			var conflictUserID string
			conflictErr := db.QueryRow(`
				SELECT id FROM users WHERE email = ? AND id != ?
			`, userInfo.Email, existingUser.ID).Scan(&conflictUserID)

			if conflictErr == nil {
				// 存在邮箱冲突，记录但允许登录（采用最安全的策略）
				log.Printf("邮箱冲突警告: OAuth邮箱 %s 已被用户 %s 占用，但允许登录",
					userInfo.Email, conflictUserID)

				// 记录冲突事件
				_, logErr := db.Exec(`
					INSERT INTO oauth_email_conflicts (
						user_id, provider, old_email, new_email, 
						conflict_user_id, conflict_type, resolution_status, 
						resolution_method, notes
					) VALUES (?, ?, ?, ?, ?, 'email_occupied', 'resolved', 
						'allow_with_warning', '检测到邮箱冲突但允许登录，不更新主账号邮箱')
				`, existingUser.ID, userInfo.Provider, oldEmail, userInfo.Email, conflictUserID)

				if logErr != nil {
					log.Printf("记录邮箱冲突失败: %v", logErr)
				}
			}
		}

		// 更新绑定信息
		_, updateErr := db.Exec(`
			UPDATE oauth_bindings 
			SET provider_email = ?, provider_username = ?, provider_name = ?, provider_avatar = ?, updated_at = NOW()
			WHERE user_id = ? AND provider = ?
		`, userInfo.Email, userInfo.Username, userInfo.Name, userInfo.Picture, existingUser.ID, userInfo.Provider)

		if updateErr != nil {
			log.Printf("更新OAuth绑定记录失败: %v", updateErr)
		}

		// 更新用户最后登录时间
		_, updateErr = db.Exec(`
			UPDATE users SET updated_at = NOW() WHERE id = ?
		`, existingUser.ID)
		if updateErr != nil {
			log.Printf("更新用户登录时间失败: %v", updateErr)
		}

		return &existingUser, nil
	}

	// 没有现有绑定，先通过真实邮箱查找主账号
	// 策略：先查oauth_bindings.provider_email，再查users.email
	// 这解决了Google账号的users.email是随机OAuth邮箱的问题
	var user model.User

	// 第一步：检查是否有其他OAuth账号使用相同的provider_email
	// 这意味着用户用相同邮箱注册了其他OAuth（如GitHub/Microsoft）
	err = db.QueryRow(`
		SELECT DISTINCT u.id, u.username, u.email, u.password_hash, u.created_at, u.updated_at
		FROM users u
		JOIN oauth_bindings ob ON u.id = ob.user_id
		WHERE ob.provider_email = ? AND ob.provider != ? AND u.is_delete = 0
		LIMIT 1
	`, userInfo.Email, userInfo.Provider).Scan(
		&user.ID, &user.Username, &user.Email,
		&user.Password, &user.CreatedAt, &user.UpdatedAt,
	)

	if err == nil {
		// 找到了使用相同邮箱的其他OAuth账号，这就是主账号
		log.Printf("通过provider_email %s 找到主账号 %s，准备绑定OAuth", userInfo.Email, user.ID)

		// 检查是否已有该provider的绑定
		var existingBindingCount int
		bindingCheckErr := db.QueryRow(`
			SELECT COUNT(*) FROM oauth_bindings 
			WHERE user_id = ? AND provider = ?
		`, user.ID, userInfo.Provider).Scan(&existingBindingCount)

		if bindingCheckErr == nil && existingBindingCount == 0 {
			// 没有绑定，创建新绑定
			log.Printf("主账号 %s 没有%s绑定，自动绑定", user.ID, userInfo.Provider)

			_, bindErr := db.Exec(`
				INSERT INTO oauth_bindings (user_id, provider, provider_user_id, provider_email, provider_username, provider_name, is_primary) 
				VALUES (?, ?, ?, ?, ?, ?, FALSE)
			`, user.ID, userInfo.Provider, userInfo.ID, userInfo.Email, userInfo.Username, userInfo.Name)

			if bindErr == nil {
				log.Printf("OAuth账号成功绑定到主账号 %s", user.ID)
			} else {
				log.Printf("绑定失败: %v", bindErr)
			}
		}

		return &user, nil
	}

	// 第二步：通过users.email查找（常规邮箱注册的用户）
	err = db.QueryRow(`
		SELECT id, username, email, password_hash, created_at, updated_at 
		FROM users 
		WHERE email = ? AND is_delete = 0
	`, userInfo.Email).Scan(
		&user.ID, &user.Username, &user.Email,
		&user.Password, &user.CreatedAt, &user.UpdatedAt,
	)

	if err == nil {
		// 邮箱匹配的用户存在，检查是否已有该provider的绑定
		var existingBindingCount int
		bindingCheckErr := db.QueryRow(`
			SELECT COUNT(*) FROM oauth_bindings 
			WHERE user_id = ? AND provider = ?
		`, user.ID, userInfo.Provider).Scan(&existingBindingCount)

		if bindingCheckErr != nil {
			log.Printf("检查OAuth绑定失败: %v", bindingCheckErr)
			// 如果检查失败，为安全起见创建新账号
			return createOAuthUser(userInfo)
		}

		if existingBindingCount > 0 {
			// 该用户已经绑定了这个provider，这可能是账号劫持尝试
			log.Printf("安全警告: 用户 %s 已绑定 %s，拒绝重复绑定", user.ID, userInfo.Provider)

			// 记录潜在的账号劫持尝试
			_, logErr := db.Exec(`
				INSERT INTO oauth_email_conflicts (
					user_id, provider, new_email, conflict_user_id, 
					conflict_type, resolution_status, notes
				) VALUES (?, ?, ?, ?, 'binding_conflict', 'pending', 
					'OAuth登录尝试绑定到已有绑定的用户，已拒绝以防账号劫持')
			`, "oauth_"+userInfo.Provider+"_"+userInfo.ID, userInfo.Provider, userInfo.Email, user.ID)

			if logErr != nil {
				log.Printf("记录账号劫持尝试失败: %v", logErr)
			}

			return createOAuthUser(userInfo)
		}

		// 用户存在且没有该provider的绑定，可以安全绑定
		log.Printf("OAuth邮箱 %s 匹配现有用户 %s，自动绑定OAuth账号", userInfo.Email, user.ID)

		// 创建OAuth绑定记录
		_, bindErr := db.Exec(`
			INSERT INTO oauth_bindings (user_id, provider, provider_user_id, provider_email, provider_username, provider_name, is_primary) 
			VALUES (?, ?, ?, ?, ?, ?, FALSE)
		`, user.ID, userInfo.Provider, userInfo.ID, userInfo.Email, userInfo.Username, userInfo.Name)

		if bindErr != nil {
			log.Printf("创建OAuth绑定记录失败: %v", bindErr)
			// 绑定失败，创建新账号
			return createOAuthUser(userInfo)
		}

		// 更新用户最后登录时间
		_, updateErr := db.Exec(`
			UPDATE users SET updated_at = NOW() WHERE id = ?
		`, user.ID)
		if updateErr != nil {
			log.Printf("更新用户登录时间失败: %v", updateErr)
		}

		log.Printf("OAuth账号成功绑定到现有用户 %s", user.ID)
		return &user, nil
	}

	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("查询用户失败: %v", err)
	}

	// 通过真实邮箱找不到用户，检查是否存在该provider的OAuth账号
	// 这解决了解绑后重新绑定的问题
	oauthEmail := generateUniqueOAuthEmail(userInfo)
	var oauthUser model.User
	oauthErr := db.QueryRow(`
		SELECT id, username, email, password_hash, created_at, updated_at 
		FROM users 
		WHERE email = ? AND is_delete = 0
	`, oauthEmail).Scan(
		&oauthUser.ID, &oauthUser.Username, &oauthUser.Email,
		&oauthUser.Password, &oauthUser.CreatedAt, &oauthUser.UpdatedAt,
	)

	if oauthErr == nil {
		// 找到OAuth账号，检查是否已有绑定
		var bindingCount int
		db.QueryRow(`
			SELECT COUNT(*) FROM oauth_bindings 
			WHERE user_id = ? AND provider = ? AND provider_user_id = ?
		`, oauthUser.ID, userInfo.Provider, userInfo.ID).Scan(&bindingCount)

		if bindingCount == 0 {
			// 绑定记录丢失（可能被解绑），重新创建绑定
			log.Printf("OAuth账号 %s 已存在但缺少绑定记录，重新创建: provider=%s, provider_email=%s",
				oauthUser.ID, userInfo.Provider, userInfo.Email)

			_, bindErr := db.Exec(`
				INSERT INTO oauth_bindings (user_id, provider, provider_user_id, provider_email, provider_username, provider_name, is_primary) 
				VALUES (?, ?, ?, ?, ?, ?, TRUE)
			`, oauthUser.ID, userInfo.Provider, userInfo.ID, userInfo.Email, userInfo.Username, userInfo.Name)

			if bindErr != nil {
				log.Printf("重新创建OAuth绑定失败: %v", bindErr)
			}
		}

		log.Printf("返回现有OAuth账号: %s (%s)", oauthUser.ID, oauthUser.Email)
		return &oauthUser, nil
	}

	// 用户不存在，创建新用户
	return createOAuthUser(userInfo)
}

// 创建OAuth用户
func createOAuthUser(userInfo *OAuthUserInfo) (*model.User, error) {
	// 生成唯一的用户名
	username := generateUniqueUsername(userInfo)

	// 为OAuth用户生成唯一邮箱，避免与现有用户冲突
	uniqueEmail := generateUniqueOAuthEmail(userInfo)

	// 生成随机密码哈希（OAuth用户不使用密码登录）
	randomPassword := security.GenerateRandomString(32)
	pepper := os.Getenv("PASSWORD_PEPPER")
	if pepper == "" {
		pepper = "default_pepper_change_in_production"
	}
	hashedPassword, err := security.HashPassword(randomPassword, pepper)
	if err != nil {
		return nil, fmt.Errorf("生成密码哈希失败: %v", err)
	}

	// 生成自定义用户ID
	customUserID := utils.GenerateCustomUserID()

	// 插入新用户
	_, err = db.Exec(`
		INSERT INTO users (id, username, email, password_hash, created_at, updated_at) 
		VALUES (?, ?, ?, ?, NOW(), NOW())
	`, customUserID, username, uniqueEmail, hashedPassword)

	if err != nil {
		// 检查是否是邮箱重复错误
		if strings.Contains(err.Error(), "Duplicate entry") && strings.Contains(err.Error(), "email") {
			log.Printf("OAuth邮箱 %s 已存在，尝试查找现有用户", uniqueEmail)

			// 通过OAuth邮箱查找现有用户
			var existingUser model.User
			findErr := db.QueryRow(`
				SELECT id, username, email, password_hash, created_at, updated_at 
				FROM users WHERE email = ? AND is_delete = 0
			`, uniqueEmail).Scan(
				&existingUser.ID, &existingUser.Username, &existingUser.Email,
				&existingUser.Password, &existingUser.CreatedAt, &existingUser.UpdatedAt,
			)

			if findErr == nil {
				log.Printf("找到现有OAuth用户: %s (%s)", existingUser.ID, existingUser.Email)

				// 检查是否已有OAuth绑定
				var bindingCount int
				db.QueryRow(`
					SELECT COUNT(*) FROM oauth_bindings 
					WHERE user_id = ? AND provider = ? AND provider_user_id = ?
				`, existingUser.ID, userInfo.Provider, userInfo.ID).Scan(&bindingCount)

				if bindingCount == 0 {
					// 绑定记录丢失，重新创建
					log.Printf("OAuth绑定记录丢失，重新创建: 用户=%s, provider=%s", existingUser.ID, userInfo.Provider)
					db.Exec(`
						INSERT INTO oauth_bindings (user_id, provider, provider_user_id, provider_email, provider_username, provider_name, is_primary) 
						VALUES (?, ?, ?, ?, ?, ?, TRUE)
					`, existingUser.ID, userInfo.Provider, userInfo.ID, userInfo.Email, userInfo.Username, userInfo.Name)
				}

				return &existingUser, nil
			}
		}

		return nil, fmt.Errorf("创建用户失败: %v", err)
	}

	// 创建OAuth绑定记录
	_, err = db.Exec(`
		INSERT INTO oauth_bindings (user_id, provider, provider_user_id, provider_email, provider_username, provider_name, is_primary) 
		VALUES (?, ?, ?, ?, ?, ?, TRUE)
	`, customUserID, userInfo.Provider, userInfo.ID, userInfo.Email, userInfo.Username, userInfo.Name)

	if err != nil {
		log.Printf("创建OAuth绑定记录失败: %v", err)
		// 不阻塞用户创建流程
	}

	// 查询并返回创建的用户
	var user model.User
	err = db.QueryRow(`
		SELECT id, username, email, password_hash, created_at, updated_at 
		FROM users 
		WHERE id = ? AND is_delete = 0
	`, customUserID).Scan(
		&user.ID, &user.Username, &user.Email,
		&user.Password, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("查询新创建用户失败: %v", err)
	}

	log.Printf("OAuth用户创建成功: %s (%s)", user.Username, user.Email)
	return &user, nil
}

// 生成唯一用户名
func generateUniqueUsername(userInfo *OAuthUserInfo) string {
	// 基础用户名：优先使用username，否则使用name，最后使用email前缀
	var baseUsername string
	if userInfo.Username != "" {
		baseUsername = userInfo.Username
	} else if userInfo.Name != "" {
		baseUsername = strings.ReplaceAll(userInfo.Name, " ", "")
	} else {
		parts := strings.Split(userInfo.Email, "@")
		baseUsername = parts[0]
	}

	// 清理用户名，只保留字母数字和下划线
	baseUsername = strings.ToLower(baseUsername)
	var cleanUsername strings.Builder
	for _, r := range baseUsername {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			cleanUsername.WriteRune(r)
		}
	}

	username := cleanUsername.String()
	if len(username) == 0 {
		username = "user"
	}

	// 限制长度
	if len(username) > 8 {
		username = username[:8]
	}

	// 检查用户名是否已存在，如果存在则添加数字后缀
	originalUsername := username
	counter := 1

	for {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
		if err != nil {
			log.Printf("检查用户名唯一性失败: %v", err)
			break
		}

		if count == 0 {
			break
		}

		username = fmt.Sprintf("%s%d", originalUsername, counter)
		counter++

		// 防止无限循环
		if counter > 9999 {
			username = fmt.Sprintf("%s%d", originalUsername, time.Now().Unix()%10000)
			break
		}
	}

	return username
}

// 使用授权码交换访问令牌并获取用户信息
func exchangeCodeForToken(provider, authCode, redirectUri string) (*OAuthUserInfo, string, error) {
	switch provider {
	case "google":
		return exchangeGoogleCode(authCode, redirectUri)
	case "github":
		return exchangeGitHubCode(authCode)
	case "microsoft":
		return exchangeMicrosoftCode(authCode, redirectUri)
	default:
		return nil, "", fmt.Errorf("不支持的提供商: %s", provider)
	}
}

// Google授权码交换
func exchangeGoogleCode(authCode, redirectUri string) (*OAuthUserInfo, string, error) {
	// 交换访问令牌
	tokenResp, err := http.PostForm("https://oauth2.googleapis.com/token", map[string][]string{
		"client_id":     {oauthConfig.GoogleClientID},
		"client_secret": {oauthConfig.GoogleClientSecret},
		"code":          {authCode},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirectUri},
	})
	if err != nil {
		return nil, "", fmt.Errorf("令牌交换请求失败: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("令牌交换失败，状态码: %d", tokenResp.StatusCode)
	}

	tokenBody, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("读取令牌响应失败: %v", err)
	}

	var tokenData map[string]interface{}
	if err := json.Unmarshal(tokenBody, &tokenData); err != nil {
		return nil, "", fmt.Errorf("解析令牌响应失败: %v", err)
	}

	accessToken := getString(tokenData, "access_token")
	if accessToken == "" {
		return nil, "", fmt.Errorf("未获取到访问令牌")
	}

	// 获取用户信息
	userResp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + accessToken)
	if err != nil {
		return nil, "", fmt.Errorf("获取用户信息失败: %v", err)
	}
	defer userResp.Body.Close()

	if userResp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("获取用户信息失败，状态码: %d", userResp.StatusCode)
	}

	userBody, err := io.ReadAll(userResp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("读取用户信息失败: %v", err)
	}

	var userData map[string]interface{}
	if err := json.Unmarshal(userBody, &userData); err != nil {
		return nil, "", fmt.Errorf("解析用户信息失败: %v", err)
	}

	userInfo := &OAuthUserInfo{
		ID:       getString(userData, "id"),
		Email:    getString(userData, "email"),
		Name:     getString(userData, "name"),
		Picture:  getString(userData, "picture"),
		Provider: "google",
	}

	return userInfo, accessToken, nil
}

// GitHub授权码交换
func exchangeGitHubCode(authCode string) (*OAuthUserInfo, string, error) {
	// 交换访问令牌
	tokenResp, err := http.PostForm("https://github.com/login/oauth/access_token", map[string][]string{
		"client_id":     {oauthConfig.GitHubClientID},
		"client_secret": {oauthConfig.GitHubClientSecret},
		"code":          {authCode},
	})
	if err != nil {
		return nil, "", fmt.Errorf("令牌交换请求失败: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("令牌交换失败，状态码: %d", tokenResp.StatusCode)
	}

	tokenBody, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("读取令牌响应失败: %v", err)
	}

	// GitHub返回的是URL编码格式
	tokenStr := string(tokenBody)
	accessToken := ""
	for _, part := range strings.Split(tokenStr, "&") {
		if strings.HasPrefix(part, "access_token=") {
			accessToken = strings.TrimPrefix(part, "access_token=")
			break
		}
	}

	if accessToken == "" {
		return nil, "", fmt.Errorf("未获取到访问令牌")
	}

	// 获取用户信息
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, "", fmt.Errorf("创建用户信息请求失败: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	userResp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("获取用户信息失败: %v", err)
	}
	defer userResp.Body.Close()

	if userResp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("获取用户信息失败，状态码: %d", userResp.StatusCode)
	}

	userBody, err := io.ReadAll(userResp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("读取用户信息失败: %v", err)
	}

	var userData map[string]interface{}
	if err := json.Unmarshal(userBody, &userData); err != nil {
		return nil, "", fmt.Errorf("解析用户信息失败: %v", err)
	}

	// 获取用户邮箱
	email := getString(userData, "email")
	if email == "" {
		emailReq, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
		if err == nil {
			emailReq.Header.Set("Authorization", "Bearer "+accessToken)
			emailResp, err := client.Do(emailReq)
			if err == nil && emailResp.StatusCode == http.StatusOK {
				defer emailResp.Body.Close()
				emailBody, err := io.ReadAll(emailResp.Body)
				if err == nil {
					var emails []map[string]interface{}
					if json.Unmarshal(emailBody, &emails) == nil {
						for _, e := range emails {
							if primary, ok := e["primary"].(bool); ok && primary {
								email = getString(e, "email")
								break
							}
						}
						if email == "" && len(emails) > 0 {
							email = getString(emails[0], "email")
						}
					}
				}
			}
		}
	}

	userInfo := &OAuthUserInfo{
		ID:       fmt.Sprintf("%.0f", userData["id"]),
		Email:    email,
		Name:     getString(userData, "name"),
		Picture:  getString(userData, "avatar_url"),
		Username: getString(userData, "login"),
		Provider: "github",
	}

	if userInfo.Name == "" {
		userInfo.Name = userInfo.Username
	}

	return userInfo, accessToken, nil
}

// Microsoft授权码交换
func exchangeMicrosoftCode(authCode, redirectUri string) (*OAuthUserInfo, string, error) {
	// 交换访问令牌
	tokenResp, err := http.PostForm("https://login.microsoftonline.com/consumers/oauth2/v2.0/token", map[string][]string{
		"client_id":     {oauthConfig.MicrosoftClientID},
		"client_secret": {oauthConfig.MicrosoftClientSecret},
		"code":          {authCode},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirectUri},
	})
	if err != nil {
		return nil, "", fmt.Errorf("令牌交换请求失败: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("令牌交换失败，状态码: %d", tokenResp.StatusCode)
	}

	tokenBody, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("读取令牌响应失败: %v", err)
	}

	var tokenData map[string]interface{}
	if err := json.Unmarshal(tokenBody, &tokenData); err != nil {
		return nil, "", fmt.Errorf("解析令牌响应失败: %v", err)
	}

	accessToken := getString(tokenData, "access_token")
	if accessToken == "" {
		return nil, "", fmt.Errorf("未获取到访问令牌")
	}

	// 获取用户信息
	req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		return nil, "", fmt.Errorf("创建用户信息请求失败: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	userResp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("获取用户信息失败: %v", err)
	}
	defer userResp.Body.Close()

	if userResp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("获取用户信息失败，状态码: %d", userResp.StatusCode)
	}

	userBody, err := io.ReadAll(userResp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("读取用户信息失败: %v", err)
	}

	var userData map[string]interface{}
	if err := json.Unmarshal(userBody, &userData); err != nil {
		return nil, "", fmt.Errorf("解析用户信息失败: %v", err)
	}

	email := getString(userData, "mail")
	if email == "" {
		email = getString(userData, "userPrincipalName")
	}

	userInfo := &OAuthUserInfo{
		ID:       getString(userData, "id"),
		Email:    email,
		Name:     getString(userData, "displayName"),
		Picture:  "",
		Provider: "microsoft",
	}

	return userInfo, accessToken, nil
}

// 获取OAuth授权URL处理器
func GetOAuthURLHandler(c *gin.Context) {
	provider := c.Param("provider")

	if !isValidProvider(provider) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不支持的OAuth提供商"})
		return
	}

	redirectUri := c.Query("redirect_uri")
	if redirectUri == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少redirect_uri参数"})
		return
	}

	state := c.Query("state")
	if state == "" {
		state = fmt.Sprintf("%d", time.Now().UnixNano())
	}

	var authURL string
	var err error

	switch provider {
	case "google":
		authURL, err = buildGoogleAuthURL(redirectUri, state)
	case "github":
		authURL, err = buildGitHubAuthURL(redirectUri, state)
	case "microsoft":
		authURL, err = buildMicrosoftAuthURL(redirectUri, state)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "不支持的提供商"})
		return
	}

	if err != nil {
		log.Printf("构建授权URL失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "构建授权URL失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"auth_url": authURL,
		"state":    state,
	})
}

// 构建Google授权URL
func buildGoogleAuthURL(redirectUri, state string) (string, error) {
	baseURL := "https://accounts.google.com/o/oauth2/v2/auth"
	params := map[string]string{
		"client_id":     oauthConfig.GoogleClientID,
		"response_type": "code",
		"redirect_uri":  redirectUri,
		"scope":         "openid profile email",
		"state":         state,
	}
	return buildAuthURL(baseURL, params), nil
}

// 构建GitHub授权URL
func buildGitHubAuthURL(redirectUri, state string) (string, error) {
	baseURL := "https://github.com/login/oauth/authorize"
	params := map[string]string{
		"client_id":    oauthConfig.GitHubClientID,
		"redirect_uri": redirectUri,
		"scope":        "user:email",
		"state":        state,
	}
	return buildAuthURL(baseURL, params), nil
}

// 构建Microsoft授权URL
func buildMicrosoftAuthURL(redirectUri, state string) (string, error) {
	baseURL := "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"
	params := map[string]string{
		"client_id":     oauthConfig.MicrosoftClientID,
		"response_type": "code",
		"redirect_uri":  redirectUri,
		"scope":         "openid profile email User.Read",
		"response_mode": "query",
		"state":         state,
	}
	return buildAuthURL(baseURL, params), nil
}

// 构建授权URL辅助函数
func buildAuthURL(baseURL string, params map[string]string) string {
	u, _ := http.NewRequest("GET", baseURL, nil)
	q := u.URL.Query()
	for key, value := range params {
		q.Add(key, value)
	}
	u.URL.RawQuery = q.Encode()
	return u.URL.String()
}

// BindOAuthHandler 绑定OAuth账号
func BindOAuthHandler(c *gin.Context) {
	provider := c.Param("provider")
	if !isValidProvider(provider) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不支持的OAuth提供商"})
		return
	}

	// 获取当前用户信息
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未授权"})
		return
	}

	// 解析请求体
	var bindRequest struct {
		AccessToken string `json:"access_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&bindRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
		return
	}

	// 验证OAuth令牌并获取用户信息
	var userInfo *OAuthUserInfo
	var err error

	switch provider {
	case "google":
		userInfo = &OAuthUserInfo{Provider: "google"}
		if !verifyGoogleToken(bindRequest.AccessToken, userInfo) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Google令牌验证失败"})
			return
		}
	case "github":
		userInfo = &OAuthUserInfo{Provider: "github"}
		if !verifyGitHubToken(bindRequest.AccessToken, userInfo) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "GitHub令牌验证失败"})
			return
		}
	case "microsoft":
		userInfo = &OAuthUserInfo{Provider: "microsoft"}
		if !verifyMicrosoftToken(bindRequest.AccessToken, userInfo) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Microsoft令牌验证失败"})
			return
		}
	}

	// 检查是否已经绑定
	var existingBinding int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM oauth_bindings 
		WHERE user_id = ? AND provider = ?
	`, userID, provider).Scan(&existingBinding)

	if err != nil {
		log.Printf("检查OAuth绑定失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器内部错误"})
		return
	}

	if existingBinding > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "该OAuth账号已经绑定"})
		return
	}

	// 检查该OAuth账号是否已被其他用户绑定
	var otherUserBinding int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM oauth_bindings 
		WHERE provider = ? AND provider_user_id = ? AND user_id != ?
	`, provider, userInfo.ID, userID).Scan(&otherUserBinding)

	if err != nil {
		log.Printf("检查OAuth账号冲突失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器内部错误"})
		return
	}

	if otherUserBinding > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "该OAuth账号已被其他用户绑定"})
		return
	}

	// 创建绑定记录
	_, err = db.Exec(`
		INSERT INTO oauth_bindings (user_id, provider, provider_user_id, provider_email, provider_username, provider_name, provider_avatar, is_primary, binding_method) 
		VALUES (?, ?, ?, ?, ?, ?, ?, FALSE, 'manual')
	`, userID, provider, userInfo.ID, userInfo.Email, userInfo.Username, userInfo.Name, userInfo.Picture)

	if err != nil {
		log.Printf("创建OAuth绑定失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "绑定失败"})
		return
	}

	log.Printf("用户 %s 成功绑定 %s OAuth账号", userID, provider)
	c.JSON(http.StatusOK, gin.H{
		"message":  "OAuth账号绑定成功",
		"provider": provider,
		"username": userInfo.Username,
	})
}

// UnbindOAuthHandler 解绑OAuth账号
func UnbindOAuthHandler(c *gin.Context) {
	provider := c.Param("provider")
	if !isValidProvider(provider) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不支持的OAuth提供商"})
		return
	}

	// 获取当前用户信息
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未授权"})
		return
	}

	// 检查绑定是否存在
	var bindingExists int
	var isPrimary bool
	err := db.QueryRow(`
		SELECT COUNT(*), COALESCE(MAX(is_primary), FALSE) FROM oauth_bindings 
		WHERE user_id = ? AND provider = ?
	`, userID, provider).Scan(&bindingExists, &isPrimary)

	if err != nil {
		log.Printf("检查OAuth绑定失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器内部错误"})
		return
	}

	if bindingExists == 0 {
		log.Printf("拒绝连接: 用户 %s 尝试解绑不存在的 %s OAuth绑定", userID, provider)
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	// 检查是否为主要绑定且用户没有设置密码
	if isPrimary {
		var hasPassword bool
		err = db.QueryRow(`
			SELECT CASE WHEN password_hash IS NOT NULL AND password_hash != '' THEN TRUE ELSE FALSE END 
			FROM users WHERE id = ?
		`, userID).Scan(&hasPassword)

		if err != nil {
			log.Printf("检查用户密码失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器内部错误"})
			return
		}

		if !hasPassword {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无法解绑主要OAuth账号，请先设置密码或绑定其他OAuth账号"})
			return
		}
	}

	// 删除绑定记录
	_, err = db.Exec(`
		DELETE FROM oauth_bindings 
		WHERE user_id = ? AND provider = ?
	`, userID, provider)

	if err != nil {
		log.Printf("删除OAuth绑定失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "解绑失败"})
		return
	}

	log.Printf("用户 %s 成功解绑 %s OAuth账号", userID, provider)
	c.JSON(http.StatusOK, gin.H{
		"message":  "OAuth账号解绑成功",
		"provider": provider,
	})
}

// generateUniqueOAuthEmail 为OAuth用户生成唯一邮箱地址
func generateUniqueOAuthEmail(userInfo *OAuthUserInfo) string {
	// 使用provider和provider_user_id生成唯一邮箱
	// 格式: oauth.{provider}.{provider_user_id}@dext.oauth
	return fmt.Sprintf("oauth.%s.%s@dext.oauth", userInfo.Provider, userInfo.ID)
}
