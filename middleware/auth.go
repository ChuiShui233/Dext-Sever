package middleware

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"Dext-Server/config"
	"Dext-Server/security"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func DecryptMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// OPTIONS 预检请求直接放行
		if c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		path := c.Request.URL.Path

		// 对 /api/* 的 GET/HEAD 请求强制要求密文通道
		if c.Request.Method == "GET" || c.Request.Method == "HEAD" {
			if strings.HasPrefix(path, "/api/") &&
				!(strings.Contains(path, "/media") || strings.Contains(path, "/upload") ||
					strings.HasPrefix(path, "/openassets/files/") || strings.HasPrefix(path, "/uploads/") ||
					path == "/api/getCaptcha" || path == "/api/verifyCaptcha" ||
					path == "/api/auth/refresh" || path == "/api/crypto/public-key" ||
					strings.HasPrefix(path, "/api/auth/oauth/callback")) {
				encryptionType := c.GetHeader("X-Encrypted")
				allowLegacy := strings.ToLower(os.Getenv("ALLOW_LEGACY_ENCRYPTION")) == "true"
				if encryptionType == "" {
					log.Printf("未加密的%s请求被拒绝: %s", c.Request.Method, c.Request.URL.Path)
					sendError(c, http.StatusBadRequest, "请求缺少加密头信息")
					c.Abort()
					return
				}
				if encryptionType != "xchacha" && !(allowLegacy && (encryptionType == "aes" || encryptionType == "rsa" || encryptionType == "hybrid")) {
					log.Printf("不支持的加密类型: %s, 路径: %s", encryptionType, c.Request.URL.Path)
					sendError(c, http.StatusBadRequest, "不支持的加密类型")
					c.Abort()
					return
				}
				if encryptionType == "xchacha" {
					hdr := c.Request.Header.Get("X-Client-Ephemeral-Key")
					if hdr == "" {
						log.Printf("缺少客户端临时公钥: %s", c.Request.URL.Path)
						sendError(c, http.StatusBadRequest, "缺少客户端临时公钥")
						c.Abort()
						return
					}
					decoded, err := base64.StdEncoding.DecodeString(hdr)
					if err != nil || len(decoded) == 0 {
						log.Printf("无效的 X-Client-Ephemeral-Key: %v", err)
						sendError(c, http.StatusBadRequest, "无效的客户端临时公钥")
						c.Abort()
						return
					}
					c.Set("clientEphemeralKey", decoded)
				}
			}
			c.Next()
			return
		}

		// 仅对需要读取请求体并可能携带加密数据的方法进行解密
		// 覆盖 POST/PUT/DELETE 以及 PATCH（预留）
		if c.Request.Method != "POST" && c.Request.Method != "PUT" && c.Request.Method != "DELETE" && c.Request.Method != "PATCH" {
			c.Next()
			return
		}

		// 允许无需加密的白名单路径（上传/媒体/验证码/刷新令牌/获取公钥/OAuth回调）
		if strings.Contains(path, "/media") || strings.Contains(path, "/upload") ||
			path == "/api/getCaptcha" || path == "/api/verifyCaptcha" ||
			path == "/api/auth/refresh" || path == "/api/crypto/public-key" || strings.HasPrefix(path, "/api/auth/oauth/callback") {
			c.Next()
			return
		}

		// 提前读取请求体，用于判断是否需要解密（例如无请求体的DELETE应直接放行）
		body, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			log.Printf("读取请求体失败: %v", err)
			sendError(c, http.StatusBadRequest, "请求体读取失败")
			c.Abort()
			return
		}
		if len(body) == 0 {
			// 无请求体：对 /api/* 强制要求密文通道（例如无Body的 DELETE 请求）
			if strings.HasPrefix(path, "/api/") {
				encryptionType := c.GetHeader("X-Encrypted")
				allowLegacy := strings.ToLower(os.Getenv("ALLOW_LEGACY_ENCRYPTION")) == "true"
				if encryptionType == "" {
					log.Printf("未加密的%s请求被拒绝: %s", c.Request.Method, c.Request.URL.Path)
					sendError(c, http.StatusBadRequest, "请求缺少加密头信息")
					c.Abort()
					return
				}
				if encryptionType != "xchacha" && !(allowLegacy && (encryptionType == "aes" || encryptionType == "rsa" || encryptionType == "hybrid")) {
					log.Printf("不支持的加密类型: %s, 路径: %s", encryptionType, c.Request.URL.Path)
					sendError(c, http.StatusBadRequest, "不支持的加密类型")
					c.Abort()
					return
				}
				if encryptionType == "xchacha" {
					if hdr := c.Request.Header.Get("X-Client-Ephemeral-Key"); hdr != "" {
						if decoded, err := base64.StdEncoding.DecodeString(hdr); err == nil && len(decoded) > 0 {
							c.Set("clientEphemeralKey", decoded)
						} else {
							log.Printf("无效的 X-Client-Ephemeral-Key: %v", err)
						}
					}
			}
			}
			c.Request.Body = ioutil.NopCloser(bytes.NewReader(body))
			c.Next()
			return
		}

		encryptionType := c.GetHeader("X-Encrypted")
		// 默认仅接受 xchacha；仅当 ALLOW_LEGACY_ENCRYPTION=true 时兼容 aes/rsa/hybrid
		allowLegacy := strings.ToLower(os.Getenv("ALLOW_LEGACY_ENCRYPTION")) == "true"
		if encryptionType == "" {
			log.Printf("未加密的%s请求被拒绝: %s", c.Request.Method, c.Request.URL.Path)
			// 明确返回 400，避免出现 200 的错误感知
			sendError(c, http.StatusBadRequest, "请求缺少加密头信息")
			c.Abort()
			return
		}
		if encryptionType != "xchacha" && !(allowLegacy && (encryptionType == "aes" || encryptionType == "rsa" || encryptionType == "hybrid")) {
			log.Printf("不支持的加密类型: %s, 路径: %s", encryptionType, c.Request.URL.Path)
			sendError(c, http.StatusBadRequest, "不支持的加密类型")
			c.Abort()
			return
		}

		var decryptedData []byte

		switch encryptionType {
		case "rsa", "hybrid":
			// RSA解密流程
			// 第一次Base64解码
			firstDecoded, err := base64.StdEncoding.DecodeString(string(body))
			if err != nil {

				c.Abort()
				return
			}

			// 第二次Base64解码
			encryptedData, err := base64.StdEncoding.DecodeString(string(firstDecoded))
			if err != nil {

				c.Abort()
				return
			}

			decryptedData, err = security.DecryptData(encryptedData)
			if err != nil {

				c.Abort()
				return
			}

		case "aes":
			// AES解密流程 - 需要从JWT中获取用户信息和会话密钥
			authHeader := c.GetHeader("Authorization")
			// 兼容从Cookie读取token
			if authHeader == "" {
				if cookieToken, err := c.Cookie("access_token"); err == nil && cookieToken != "" {
					authHeader = "Bearer " + cookieToken
				}
			}
			if authHeader == "" {
				log.Println("AES解密请求缺少认证信息")
				sendError(c, http.StatusUnauthorized, "缺少认证信息")
				c.Abort()
				return
			}

			// 解析JWT，优先提取JTI（会话ID），其次提取用户名
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				log.Printf("无效的Authorization头格式: %s", authHeader)
				sendError(c, http.StatusUnauthorized, "无效的认证格式")
				c.Abort()
				return
			}
			tokenString := parts[1]
			claims := &jwt.RegisteredClaims{}
			// 尝试用所有密钥解析（与AuthMiddleware一致）
			secrets, err := security.LoadSecrets()
			if err != nil || len(secrets) == 0 {
				log.Printf("加载JWT密钥失败: %v", err)
				sendError(c, http.StatusInternalServerError, "系统错误")
				c.Abort()
				return
			}
			var parsed bool
			for _, secret := range secrets {
				if t, e := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("不支持的签名算法: %v", token.Header["alg"])
					}
					return []byte(secret.Secret), nil
				}); e == nil && t.Valid {
					parsed = true
					break
				}
			}
			if !parsed || claims.ExpiresAt == nil || claims.ExpiresAt.Before(time.Now()) || claims.Subject == "" {
				log.Printf("JWT解析失败或无效")
				sendError(c, http.StatusUnauthorized, "无效的认证信息")
				c.Abort()
				return
			}

			// 仅按JTI获取会话密钥（取消用户名兼容存取）
			var sessionKey *security.SessionKey
			if claims.ID != "" {
				if sk, e := security.GetSessionKeyBySessionID(claims.ID); e == nil {
					sessionKey = sk
				}
			}
			// 如果没有会话密钥，返回401，避免将密文传递给后续JSON解析
			if sessionKey == nil {
				log.Printf("会话密钥不存在，拒绝AES解密请求: JTI=%s, user=%s", claims.ID, claims.Subject)
				sendError(c, http.StatusUnauthorized, "缺少认证信息")
				c.Abort()
				return
			} else {
				// AES解密（仅在有会话密钥时进行）
				decryptedData, err = security.DecryptWithSessionKeyGCM(body, sessionKey)
				if err != nil {
					log.Printf("AES解密失败: %v", err)
					sendError(c, http.StatusBadRequest, "数据解密失败")
					c.Abort()
					return
				}
			}

		case "xchacha":
			// XChaCha 解密流程
			// 解析 JSON 请求体
			var encryptedPayload map[string]interface{}
			if err := json.Unmarshal(body, &encryptedPayload); err != nil {
				log.Printf("解析 XChaCha 加密请求体失败: %v", err)
				sendError(c, http.StatusBadRequest, "请求格式错误")
				c.Abort()
				return
			}

			var clientEphemeralKey []byte
			decryptedData, clientEphemeralKey, err = security.DecryptXChaChaRequest(encryptedPayload)
			if err != nil {
				log.Printf("XChaCha 解密失败: %v", err)
				sendError(c, http.StatusBadRequest, "数据解密失败")
				c.Abort()
				return
			}

			// 将客户端临时公钥存储到 context 中，用于响应加密
			c.Set("clientEphemeralKey", clientEphemeralKey)
		}

		c.Request.Body = ioutil.NopCloser(bytes.NewReader(decryptedData))
		c.Next()
	}
}

// EncryptResponseMiddleware 响应加密中间件
func EncryptResponseMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 检查请求是否使用 XChaCha 加密
		encryptionType := c.Request.Header.Get("X-Encrypted")
		if encryptionType != "xchacha" {
			c.Next()
			return
		}

		// 获取原始响应写入器
		originalWriter := c.Writer

		// 创建自定义响应写入器
		responseWriter := &encryptResponseWriter{
			ResponseWriter: originalWriter,
			body:          &bytes.Buffer{},
			encryptionType: encryptionType,
		}

		// 替换响应写入器
		c.Writer = responseWriter

		// 继续处理请求
		c.Next()

		// 如果响应体不为空且状态码为成功，进行加密
		statusCode := responseWriter.Status()
		if responseWriter.body.Len() > 0 && statusCode >= 200 && statusCode < 300 {
			// 获取客户端临时公钥：优先从解密中间件写入的 context，其次从请求头 X-Client-Ephemeral-Key 读取
			var clientKeyBytes []byte
			if v, exists := c.Get("clientEphemeralKey"); exists {
				if kb, ok := v.([]byte); ok && len(kb) > 0 {
					clientKeyBytes = kb
				}
			}
			if len(clientKeyBytes) == 0 {
				if hdr := c.Request.Header.Get("X-Client-Ephemeral-Key"); hdr != "" {
					if decoded, err := base64.StdEncoding.DecodeString(hdr); err == nil {
						clientKeyBytes = decoded
					} else {
						log.Printf("无效的 X-Client-Ephemeral-Key: %v", err)
					}
				}
			}
			if len(clientKeyBytes) == 0 {
				// 如果没有客户端临时公钥，返回原始响应
				originalWriter.WriteHeader(statusCode)
				originalWriter.Write(responseWriter.body.Bytes())
				return
			}

			// 加密响应
			encryptedResponse, err := security.EncryptXChaChaResponse(
				responseWriter.body.Bytes(),
				clientKeyBytes,
			)
			if err != nil {
				log.Printf("响应加密失败: %v", err)
				// 如果加密失败，返回原始响应
				originalWriter.WriteHeader(statusCode)
				originalWriter.Write(responseWriter.body.Bytes())
				return
			}

			// 在清除前缓存 CORS 相关头，避免被清空导致浏览器 CORS 失败
			corsHeaderKeys := []string{
				"Access-Control-Allow-Origin",
				"Access-Control-Allow-Credentials",
				"Access-Control-Allow-Methods",
				"Access-Control-Allow-Headers",
				"Access-Control-Expose-Headers",
				"Access-Control-Max-Age",
				"Vary",
			}
			cachedCORS := make(map[string]string, len(corsHeaderKeys))
			for _, hk := range corsHeaderKeys {
				cachedCORS[hk] = originalWriter.Header().Get(hk)
			}

			// 清除原始响应头，设置新的响应头
			for k := range originalWriter.Header() {
				originalWriter.Header().Del(k)
			}
			// 恢复必要的 CORS 头
			for k, v := range cachedCORS {
				if v != "" {
					originalWriter.Header().Set(k, v)
				}
			}
			originalWriter.Header().Set("X-Encrypted", "xchacha")
			originalWriter.Header().Set("Content-Type", "application/json")
			originalWriter.WriteHeader(statusCode)

			// 写入加密后的响应
			encryptedJSON, _ := json.Marshal(encryptedResponse)
			originalWriter.Write(encryptedJSON)
		} else if responseWriter.body.Len() > 0 {
			// 如果响应体不为空但不是成功状态，直接写入
			originalWriter.WriteHeader(statusCode)
			originalWriter.Write(responseWriter.body.Bytes())
		}
	}
}

// encryptResponseWriter 自定义响应写入器
type encryptResponseWriter struct {
	gin.ResponseWriter
	body          *bytes.Buffer
	encryptionType string
	statusCode    int
}

func (w *encryptResponseWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

func (w *encryptResponseWriter) WriteString(s string) (int, error) {
	return w.body.WriteString(s)
}

func (w *encryptResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *encryptResponseWriter) Status() int {
	if w.statusCode == 0 {
		return 200 // 默认状态码
	}
	return w.statusCode
}

// JWT认证中间件
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var authHeader string
		if cookieToken, err := c.Cookie("access_token"); err == nil && cookieToken != "" {
			authHeader = "Bearer " + cookieToken
		} else {
			authHeader = c.GetHeader("Authorization")
		}
		if authHeader == "" {
			log.Println("请求缺少认证信息")
			sendError(c, http.StatusUnauthorized, "缺少认证信息")
			return
		}

		// 验证Authorization头格式
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Printf("无效的Authorization头格式: %s", authHeader)
			sendError(c, http.StatusUnauthorized, "无效的认证格式")
			return
		}

		tokenString := parts[1]
		if len(tokenString) < 10 { // 简单长度检查
			log.Printf("令牌长度不足: %d", len(tokenString))
			sendError(c, http.StatusUnauthorized, "无效的令牌")
			return
		}

		// 加载所有有效密钥
		secrets, err := security.LoadSecrets()
		if err != nil {
			log.Printf("加载JWT密钥失败: %v", err)
			sendError(c, http.StatusInternalServerError, "系统错误")
			return
		}

		if len(secrets) == 0 {
			log.Println("没有可用的JWT密钥")
			sendError(c, http.StatusInternalServerError, "系统错误")
			return
		}

		var lastErr error
		for _, secret := range secrets {
			claims := &jwt.RegisteredClaims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("不支持的签名算法: %v", token.Header["alg"])
				}
				return []byte(secret.Secret), nil
			})

			if err == nil && token.Valid {
				// log.Printf("令牌验证成功，使用密钥 #%d", i+1)
				if claims.ExpiresAt.Before(time.Now()) {
					log.Println("令牌已过期")
					sendError(c, http.StatusUnauthorized, "令牌已过期")
					return
				}
				if claims.Subject == "" {
					log.Println("令牌缺少Subject声明")
					sendError(c, http.StatusUnauthorized, "无效的令牌声明")
					return
				}

				// 取消旧兼容：Subject 仅为用户ID
				var userID, dbUsername string
				err := config.DB.QueryRow("SELECT id, username FROM users WHERE id = ?", claims.Subject).Scan(&userID, &dbUsername)
				if err != nil {
					log.Println("令牌用户不存在或已被删除")
					sendError(c, http.StatusUnauthorized, "用户不存在或已被删除")
					return
				}

				c.Set("username", dbUsername)
				c.Set("user_id", userID)
				c.Next()
				return
			}
			lastErr = err
		}

		if lastErr != nil {
			switch lastErr {
			case jwt.ErrSignatureInvalid:
				log.Println("令牌签名无效")
				sendError(c, http.StatusUnauthorized, "无效的令牌签名")
			case jwt.ErrTokenExpired:
				log.Println("令牌已过期")
				sendError(c, http.StatusUnauthorized, "令牌已过期")
			default:
				log.Printf("令牌验证失败: %v", lastErr)
				sendError(c, http.StatusUnauthorized, "无效的令牌")
			}
		} else {
			log.Println("令牌验证失败")
			sendError(c, http.StatusUnauthorized, "无效的令牌")
		}
	}
}

// 可选认证中间件 - 如果有token就解析，没有就跳过
func OptionalAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var authHeader string
		if cookieToken, err := c.Cookie("access_token"); err == nil && cookieToken != "" {
			authHeader = "Bearer " + cookieToken
		} else {
			authHeader = c.GetHeader("Authorization")
		}
		
		// 如果没有认证信息，直接跳过
		if authHeader == "" {
			c.Next()
			return
		}

		// 验证Authorization头格式
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.Next()
			return
		}

		tokenString := parts[1]
		if len(tokenString) < 10 {
			c.Next()
			return
		}

		// 加载所有有效密钥
		secrets, err := security.LoadSecrets()
		if err != nil || len(secrets) == 0 {
			c.Next()
			return
		}

		// 尝试解析token
		for _, secret := range secrets {
			claims := &jwt.RegisteredClaims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("不支持的签名算法: %v", token.Header["alg"])
				}
				return []byte(secret.Secret), nil
			})

			if err == nil && token.Valid {
				// token有效且未过期
				if claims.ExpiresAt != nil && !claims.ExpiresAt.Before(time.Now()) && claims.Subject != "" {
					// 查询用户信息
					var userID, dbUsername string
					err := config.DB.QueryRow("SELECT id, username FROM users WHERE id = ?", claims.Subject).Scan(&userID, &dbUsername)
					if err == nil {
						// 设置用户信息到context
						c.Set("username", dbUsername)
						c.Set("user_id", userID)
						c.Next()
						return
					}
				}
			}
		}

		// token无效或解析失败，继续执行但不设置用户信息
		c.Next()
	}
}

func sendError(c *gin.Context, code int, _ string) {
	// 不返回任何错误信息，只返回固定响应码
	c.AbortWithStatus(code)
}

func CorsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		// 根据不同 Origin 进行缓存区分
		c.Writer.Header().Add("Vary", "Origin")

		// 允许的域名列表
		allowedOrigins := []string{
			"https://wucode.xyz",
			"https://www.wucode.xyz",
			"https://dext.wucode.xyz",
			"http://localhost:8001",
			"http://127.0.0.1:8001",
			"http://192.168.1.4:8001",
		}

		// 检查是否为pages.dev域名
		isPagesDev := strings.HasSuffix(origin, ".pages.dev")

		// 检查是否为wucode.xyz的子域名
		isWucodeSubdomain := strings.HasSuffix(origin, ".wucode.xyz") || origin == "https://wucode.xyz"

		// 检查是否在允许列表中
		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin {
				allowed = true
				break
			}
		}

		// 开发环境放宽：允许本机与私网 IP 的任意端口
		env := strings.ToLower(os.Getenv("ENV"))
		isDev := env == "" || env == "dev" || env == "development"
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
		if !allowed && isDev && origin != "" && (isLocalDynamic || isLAN) {
			allowed = true
		}

		if allowed || isPagesDev || isWucodeSubdomain {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Encrypted, X-Client-Ephemeral-Key, X-Requested-With, Accept")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "X-Encrypted, Content-Type")
		c.Writer.Header().Set("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 基本安全头部
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		c.Writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// 内容安全策略 - 添加媒体支持
		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline'; " +
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
			"img-src 'self' data: blob:; " +
			"font-src 'self' https://fonts.gstatic.com; " +
			"media-src 'self' blob: data:; " +
			"connect-src 'self'; " +
			"frame-ancestors 'none'; " +
			"form-action 'self'; " +
			"worker-src 'self' blob:;"
		c.Writer.Header().Set("Content-Security-Policy", csp)

		// HSTS - 在生产环境启用
		if os.Getenv("ENV") == "production" {
			c.Writer.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		}

		// 防止MIME类型嗅探
		c.Writer.Header().Set("X-Download-Options", "noopen")
		c.Writer.Header().Set("X-Permitted-Cross-Domain-Policies", "none")

		c.Next()
	}
}
