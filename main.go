package main

import (
	"Dext-Server/config"
	"Dext-Server/middleware"
	"Dext-Server/module/analytics"
	"Dext-Server/module/answer"
	"Dext-Server/module/assets"
	"Dext-Server/module/email"
	"Dext-Server/module/oauth"
	"Dext-Server/module/project"
	"Dext-Server/module/session"
	"Dext-Server/module/survey"
	"Dext-Server/module/survey/media"
	"Dext-Server/module/survey/question"
	"Dext-Server/module/user"
	"Dext-Server/security"
	"Dext-Server/utils"
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"github.com/robfig/cron/v3"
)

var db *sql.DB

var openAssetsService *assets.Service

func main() {

	gin.SetMode(gin.ReleaseMode)

	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// 初始化私钥
	if err := security.InitPrivateKey(); err != nil {
		log.Fatal("初始化私钥失败:", err)
	}

	// 初始化 XChaCha 服务器密钥对
	if err := security.InitServerKeyPair(); err != nil {
		log.Fatal("初始化 XChaCha 服务器密钥对失败:", err)
	}
	log.Println("XChaCha 服务器密钥对已初始化")

	// 初始化JWT密钥
	log.Println("开始初始化JWT密钥...")
	if _, err := security.LoadSecrets(); err != nil {
		log.Printf("初始化JWT密钥失败: %v, 尝试重新生成...", err)
		if _, err = security.InitializeSecretFile(); err != nil {
			log.Fatalf("重新初始化JWT密钥失败: %v", err)
		}
	}
	log.Println("JWT密钥已准备就绪")

	// 启动密钥轮换服务
	security.StartSecretRotation()
	log.Println("JWT密钥轮换服务已启动")

	// 启动会话清理服务
	security.StartSessionCleanup()
	log.Println("会话清理服务已启动")

	// 使用config模块初始化数据库
	config.InitDB()
	db = config.DB
	defer db.Close()

	// 初始化 Redis 客户端
	if err := config.InitRedis(); err != nil {
		log.Fatalf("无法连接到 Redis: %v", err)
	}

	// 启动问卷到期自动完结计划任务
	startSurveyExpiryScheduler()

	// 初始化 answer 服务模块
	answer.InitService()
	log.Println("答案服务已初始化")

	// 启动回收站定时清理任务
	startRecycleBinCleanupScheduler()

	// 初始化会话管理器
	sessionManager := session.NewSessionManager(db)
	sessionManager.StartCleanupRoutine()
	log.Println("会话管理服务已启动")

	// 初始化 OAuth 模块
	oauth.InitOAuth(db)
	log.Println("OAuth服务已初始化")

	// 初始化邮件服务
	email.InitEmailService(db)
	log.Println("邮件服务已初始化")

	// 初始化 OpenAssets 服务模块
	port := os.Getenv("PORT")
	if port == "" {
		port = "11222"
	}
	hostURL := os.Getenv("HOST_URL")
	httpsEnabled := os.Getenv("HTTPS_ENABLED") == "true"
	httpsPort := os.Getenv("HTTPS_PORT")
	if hostURL == "" && httpsEnabled {
		hostURL = fmt.Sprintf("https://127.0.0.1:%s", httpsPort)
	} else if hostURL == "" {
		hostURL = fmt.Sprintf("http://127.0.0.1:%s", port)
	}

	oaConfig := &assets.Config{
		BaseURL:        hostURL,
		StoragePath:    "assets_storage",
		MaxFileSize:    100 * 1024 * 1024,  // 100MB
		MaxUserStorage: 1024 * 1024 * 1024, // 1GB
		AuthRequired:   true,
		AllowedTypes: map[string]bool{
			"image/jpeg": true, "image/jpg": true, "image/png": true, "image/gif": true, "image/webp": true, "image/bmp": true, "image/tiff": true, "image/svg+xml": true, "image/ico": true, "image/heic": true, "image/heif": true, "image/avif": true, "image/jxl": true,
			"video/mp4": true, "video/webm": true, "video/avi": true, "video/mov": true, "video/wmv": true, "video/flv": true, "video/mkv": true, "video/3gp": true,
			"audio/mpeg": true, "audio/wav": true, "audio/ogg": true, "audio/mp3": true, "audio/aac": true, "audio/flac": true, "audio/wma": true,
			"application/pdf": true, "text/plain": true, "application/json": true, "application/xml": true, "text/html": true, "text/css": true, "text/javascript": true, "application/javascript": true,
		},
	}

	oaService, err := assets.NewService(oaConfig, db)
	if err != nil {
		log.Fatalf("初始化 OpenAssets 服务失败: %v", err)
	}
	openAssetsService = oaService

	// 设置 media 模块的 OpenAssets 服务实例
	media.SetOpenAssetsService(openAssetsService)

	// 主应用 Gin 路由器
	router := gin.Default()

	// 设置可信代理
	trusted := config.LoadTrustedProxies()
	if err := router.SetTrustedProxies(trusted); err != nil {
		log.Fatalf("设置可信代理失败: %v", err)
	}

	router.MaxMultipartMemory = 100 << 20
	router.Use(gin.Recovery())

	router.Use(
		middleware.CorsMiddleware(),
		middleware.RateLimitMiddleware(),
		middleware.SecurityHeadersMiddleware(),
		middleware.DecryptMiddleware(),
		middleware.EncryptResponseMiddleware(),
	)

	// ===================================================================
	// 主应用 API 路由
	// ===================================================================
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})

	// 提供 XChaCha 公钥的 API 端点
	router.GET("/api/crypto/public-key", func(c *gin.Context) {
		publicKey := security.GetServerPublicKey()
		if publicKey == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器公钥未初始化"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"publicKey": publicKey})
	})

	authGroup := router.Group("/api/auth")
	{
		authGroup.POST("/register", user.RegisterHandler)
		authGroup.POST("/login", user.LoginHandler)
		authGroup.POST("/refresh", user.RefreshHandler)
		authGroup.POST("/logout", user.LogoutHandler)
		authGroup.POST("/oauth", oauth.OAuthHandler)
		authGroup.GET("/oauth/:provider/url", oauth.GetOAuthURLHandler)

		// OAuth回调代理路由（支持多平台）
		authGroup.GET("/oauth/callback/:platform", oauth.OAuthCallbackProxy)

		// 邮箱验证相关路由
		authGroup.POST("/email/send-code", email.SendVerificationCodeHandler)
		authGroup.POST("/email/verify-code", email.VerifyEmailCodeHandler)
		authGroup.POST("/email/reset-password", user.ResetPasswordWithEmailHandler)
	}

	router.GET("/user/profile/:id", user.GetUserProfileHandler)

	// 会话管理API
	sessionGroup := router.Group("/api/sessions")
	sessionGroup.Use(session.JWTMiddleware(sessionManager))
	{
		sessionHandlers := session.NewSessionHandlers(sessionManager)
		sessionGroup.GET("", sessionHandlers.GetUserSessions)
		sessionGroup.DELETE("/:session_id", sessionHandlers.RevokeSession)
		sessionGroup.POST("/revoke-all", sessionHandlers.RevokeAllSessions)
		sessionGroup.POST("/limit", sessionHandlers.LimitUserSessions)
	}

	protectedGroup := router.Group("/api")
	protectedGroup.Use(session.JWTMiddleware(sessionManager))
	{
		// 邮箱验证码（需要登录）
		protectedGroup.POST("/user/send-email-code", email.SendChangeEmailCodeHandler)

		// 用户密码管理（需要登录）
		protectedGroup.POST("/user/change-password-with-email", user.ChangePasswordWithEmailHandler)

		// OAuth绑定管理（需要登录）
		protectedGroup.POST("/oauth/:provider/bind", oauth.BindOAuthHandler)
		protectedGroup.DELETE("/oauth/:provider/unbind", oauth.UnbindOAuthHandler)

		// 项目相关API
		protectedGroup.GET("/project/list", project.GetProjectsHandler)
		protectedGroup.POST("/project/add", project.CreateProjectHandler)
		protectedGroup.PUT("/project/update", project.UpdateProjectHandler)
		protectedGroup.DELETE("/project/delete/:id", project.DeleteProjectHandler)
		protectedGroup.DELETE("/project/batch-delete", project.BatchDeleteProjectsHandler)
		// 问卷相关API
		protectedGroup.GET("/survey/list", survey.GetSurveysHandler)
		protectedGroup.POST("/survey/add", survey.CreateSurveyHandler)
		protectedGroup.PUT("/survey/update", survey.UpdateSurveyHandler)
		protectedGroup.DELETE("/survey/delete/:id", survey.DeleteSurveyHandler)
		protectedGroup.DELETE("/survey/batch-delete", survey.BatchDeleteSurveysHandler)
		protectedGroup.GET("/survey/detail/:id", survey.GetSurveyByIDHandler)
		// 答卷相关API
		protectedGroup.POST("/answer/submit", answer.SubmitAnswerHandler)
		protectedGroup.GET("/answer/list/:surveyId", answer.GetAnswersHandler)
		protectedGroup.GET("/answer/:id", answer.GetAnswerByIDHandler)
		protectedGroup.DELETE("/answer/:id", answer.DeleteAnswerHandler)                          // 物理删除 (仅创建者)
		protectedGroup.DELETE("/answers/batch", answer.BatchDeleteAnswersHandler)                 // 批量物理删除 (仅创建者)
		protectedGroup.POST("/answer/logic-delete/:id", answer.LogicDeleteAnswerHandler)          // 逻辑删除
		protectedGroup.POST("/answers/batch-logic-delete", answer.BatchLogicDeleteAnswersHandler) // 批量逻辑删除
		// 回收站 API
		protectedGroup.GET("/answer/recycle-bin/:surveyId", answer.GetDeletedAnswersHandler)         // 获取回收站列表
		protectedGroup.POST("/answer/recycle-bin/restore/:id", answer.RestoreAnswerHandler)          // 恢复单个答卷
		protectedGroup.POST("/answers/recycle-bin/batch-restore", answer.BatchRestoreAnswersHandler) // 批量恢复答卷
		// 上传文件相关API
		protectedGroup.GET("/user/current", user.GetCurrentUserHandler)
		protectedGroup.POST("/user/generate-token", user.GenerateCustomTokenHandler)
		// 统计相关API
		protectedGroup.GET("/survey/stats/:id", analytics.GetSurveyStatsHandler)
		protectedGroup.GET("/survey/stats", analytics.GetAllSurveyStatsHandler)
		protectedGroup.GET("/survey/check-name/:name", analytics.CheckSurveyNameHandler)
		protectedGroup.POST("/survey/view/:id", analytics.RecordSurveyViewHandler)
		protectedGroup.GET("/survey/recent-submissions", analytics.GetRecentSubmissionsHandler)
		protectedGroup.GET("/survey/submissions/history", analytics.GetSubmissionHistoryHandler)
		protectedGroup.GET("/survey/submissions/:answerId/detail", analytics.GetSubmissionDetailHandler)
		// 总览与趋势
		protectedGroup.GET("/analytics/overview", analytics.GetOverviewHandler)
		protectedGroup.GET("/analytics/submit-trend", analytics.GetSubmitTrendHandler)
		// 问题相关API
		protectedGroup.GET("/survey/:surveyId/questions", question.GetSurveyQuestionsHandler)
		protectedGroup.POST("/survey/:surveyId/question", question.AddSurveyQuestionHandler)
		protectedGroup.PUT("/survey/:surveyId/question/:questionId", question.UpdateSurveyQuestionHandler)
		protectedGroup.DELETE("/survey/:surveyId/question/:questionId", question.DeleteSurveyQuestionHandler)
		protectedGroup.PUT("/survey/:surveyId/questions/reorder", question.ReorderSurveyQuestionsHandler)

		// 媒体文件相关 API
		protectedGroup.POST("/survey/:surveyId/media", media.UploadSurveyMediaHandler)
		protectedGroup.GET("/survey/:surveyId/media", media.GetSurveyMediaFilesHandler)
		protectedGroup.DELETE("/survey/:surveyId/media/:fileId", media.DeleteSurveyMediaFileHandler)
		protectedGroup.PUT("/survey/:surveyId/background", media.UpdateSurveyBackgroundHandler)
		protectedGroup.GET("/survey/:surveyId/background", media.GetSurveyBackgroundHandler)

		// 图像管理 API
		protectedGroup.POST("/images/upload", media.UploadImageHandler)
		protectedGroup.GET("/images/list", media.GetImagesHandler)
		protectedGroup.GET("/images/:imageId", media.GetImageHandler)
		protectedGroup.DELETE("/images/:imageId", media.DeleteImageHandler)
		protectedGroup.GET("/images/storage", media.GetUserImageStorageHandler)
		protectedGroup.POST("/images/batch-upload", media.BatchUploadImagesHandler)
		protectedGroup.DELETE("/images/batch-delete", media.BatchDeleteImagesHandler)

		// 头像上传API
		protectedGroup.POST("/user/avatar/upload", media.UploadAvatarHandler)
		// 用户名修改API
		protectedGroup.PUT("/user/username", user.UpdateUsernameHandler)
		// 更换邮箱API（需要登录和密码验证）
		protectedGroup.POST("/user/change-email", user.ChangeEmailHandler)
		// 修改密码API（需要登录和旧密码验证）
		protectedGroup.POST("/user/change-password", user.ChangePasswordHandler)

	}

	router.Static("/uploads", "./uploads")
	router.POST("/api/getCaptcha", utils.GetCaptchaHandler)
	router.POST("/api/verifyCaptcha", utils.VerifyCaptchaHandler)

	// 公开问卷访问路由（支持可选认证：有token则识别用户，无token则匿名）
	publicGroup := router.Group("/api/public")
	publicGroup.Use(middleware.OptionalAuthMiddleware())
	{
		publicGroup.GET("/survey/:uid", survey.GetPublicSurveyHandler)
		publicGroup.POST("/survey/:uid/submit", survey.SubmitPublicAnswerHandler)
	}

	// 需要认证的公共问卷路由（已登录用户访问）
	publicAuthGroup := router.Group("/api/public/auth")
	publicAuthGroup.Use(middleware.AuthMiddleware())
	{
		// 可以在这里添加需要认证的公共问卷相关功能
	}

	// ===================================================================
	// OpenAssets 服务路由 (集成到主 Router)
	// ===================================================================
	// 公共文件访问接口 (无需认证)
	router.GET("/openassets/files/:bucket/:filename", openAssetsService.DownloadHandler)

	// 管理接口 (需要认证, 使用主应用的 AuthMiddleware)
	openAssetsGroup := router.Group("/openassets")
	openAssetsGroup.Use(middleware.AuthMiddleware()) // 复用主应用的认证中间件
	{
		openAssetsGroup.POST("/upload/:bucket", openAssetsService.UploadHandler)
		openAssetsGroup.DELETE("/delete/:bucket/:filename", openAssetsService.DeleteHandler)
		openAssetsGroup.GET("/list/:bucket", openAssetsService.ListHandler)
		openAssetsGroup.GET("/info/:bucket/:filename", openAssetsService.InfoHandler)
		openAssetsGroup.GET("/user/storage/:username", openAssetsService.GetUserStorageHandler)
		openAssetsGroup.GET("/stats", openAssetsService.GetStatsHandler)
	}

	// 启动服务器
	startServer(router, port)
}

func startSurveyExpiryScheduler() {
	// 启动时先运行一次，确保状态及时更新
	go func() {
		updateExpiredSurveys()
	}()

	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			updateExpiredSurveys()
		}
	}()
}

func updateExpiredSurveys() {
	if db == nil {
		return
	}
	// 将已到期且仍为发布中的问卷设为已完结
	res, err := db.Exec(`
        UPDATE surveys
        SET survey_status = 2
        WHERE survey_status = 1
          AND deadline IS NOT NULL
          AND deadline <= NOW()
    `)
	if err != nil {
		log.Printf("自动完结到期问卷失败: %v", err)
		return
	}
	if rows, _ := res.RowsAffected(); rows > 0 {
		log.Printf("自动完结到期问卷 %d 条", rows)
	}
}

// startRecycleBinCleanupScheduler 启动回收站定时清理任务
func startRecycleBinCleanupScheduler() {
	cronExpr := os.Getenv("RECYCLE_BIN_CLEANUP_CRON")
	if cronExpr == "" {
		cronExpr = "0 0 * * *" // 默认每天凌晨执行
	}

	retentionDaysStr := os.Getenv("RECYCLE_BIN_RETENTION_DAYS")
	retentionDays := 30 // 默认保留30天
	if retentionDaysStr != "" {
		if d, err := strconv.Atoi(retentionDaysStr); err == nil {
			retentionDays = d
		}
	}

	c := cron.New()
	_, err := c.AddFunc(cronExpr, func() {
		log.Printf("开始执行回收站自动清理任务 (保留天数: %d)...", retentionDays)
		count, err := answer.CleanupRecycleBinTask(retentionDays)
		if err != nil {
			log.Printf("执行回收站自动清理任务失败: %v", err)
		} else if count > 0 {
			log.Printf("回收站自动清理任务完成，共物理删除 %d 条过期数据", count)
		}
	})

	if err != nil {
		log.Printf("启动回收站自动清理计划任务失败: %v", err)
		return
	}

	c.Start()
	log.Printf("回收站自动清理计划任务已启动，Cron表达式: %s, 保留天数: %d", cronExpr, retentionDays)
}

// startServer 启动HTTP/HTTPS服务器
func startServer(router *gin.Engine, port string) {
	// 获取SSL配置
	httpsEnabled := os.Getenv("HTTPS_ENABLED") == "true"
	sslCertFile := os.Getenv("SSL_CERT_FILE")
	sslKeyFile := os.Getenv("SSL_KEY_FILE")
	httpsPort := os.Getenv("HTTPS_PORT")
	httpRedirect := os.Getenv("HTTP_REDIRECT") == "true"

	// 检查是否启用HTTPS
	if httpsEnabled && sslCertFile != "" && sslKeyFile != "" {
		// 检查证书文件是否存在
		if _, err := os.Stat(sslCertFile); os.IsNotExist(err) {
			log.Printf("警告: SSL证书文件不存在: %s", sslCertFile)
			log.Printf("回退到HTTP模式")
			startHTTPServer(router, port)
			return
		}
		if _, err := os.Stat(sslKeyFile); os.IsNotExist(err) {
			log.Printf("警告: SSL私钥文件不存在: %s", sslKeyFile)
			log.Printf("回退到HTTP模式")
			startHTTPServer(router, port)
			return
		}

		if httpsPort == "" {
			httpsPort = "443"
		}

		// 启动HTTPS服务器
		startHTTPSServer(router, httpsPort, sslCertFile, sslKeyFile, httpRedirect, port)
	} else {
		// HTTPS未启用或证书配置不完整，启动HTTP服务器
		if !httpsEnabled {
			log.Printf("HTTPS已禁用，启动HTTP模式")
		} else {
			log.Printf("HTTPS配置不完整，回退到HTTP模式")
		}
		startHTTPServer(router, port)
	}
}

// startHTTPServer 启动HTTP服务器
func startHTTPServer(router *gin.Engine, port string) {
	log.Printf("启动HTTP服务器，端口: %s", port)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: router,
		// 安全配置 - 增加超时以支持大文件上传
		ReadTimeout:  300 * time.Second, // 5分钟读取超时
		WriteTimeout: 300 * time.Second, // 5分钟写入超时
		IdleTimeout:  120 * time.Second, // 2分钟空闲超时
	}

	// 优雅关闭
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP服务器启动失败: %v", err)
		}
	}()

	gracefulShutdown(server, nil)
}

// startHTTPSServer 启动HTTPS服务器
func startHTTPSServer(router *gin.Engine, httpsPort, certFile, keyFile string, httpRedirect bool, httpPort string) {
	log.Printf("启动HTTPS服务器，端口: %s", httpsPort)
	log.Printf("证书文件: %s", certFile)
	log.Printf("私钥文件: %s", keyFile)

	// HTTPS服务器配置
	httpsServer := &http.Server{
		Addr:    ":" + httpsPort,
		Handler: router,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
		ReadTimeout:  300 * time.Second, // 5分钟读取超时
		WriteTimeout: 300 * time.Second, // 5分钟写入超时
		IdleTimeout:  120 * time.Second, // 2分钟空闲超时
	}

	// 启动HTTPS服务器
	go func() {
		if err := httpsServer.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS服务器启动失败: %v", err)
		}
	}()

	var httpServer *http.Server
	// 如果启用HTTP重定向，启动HTTP重定向服务器
	if httpRedirect {
		log.Printf("启动HTTP重定向服务器，端口: %s -> HTTPS:%s", httpPort, httpsPort)

		redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 构建HTTPS URL
			httpsURL := "https://" + r.Host
			if httpsPort != "443" {
				httpsURL = "https://" + r.Host + ":" + httpsPort
			}
			httpsURL += r.RequestURI

			http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
		})

		httpServer = &http.Server{
			Addr:         ":" + httpPort,
			Handler:      redirectHandler,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  15 * time.Second,
		}

		go func() {
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("HTTP重定向服务器启动失败: %v", err)
			}
		}()
	}

	gracefulShutdown(httpsServer, httpServer)
}

// gracefulShutdown 优雅关闭服务器
func gracefulShutdown(httpsServer *http.Server, httpServer *http.Server) {
	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("正在关闭服务器...")

	// 设置关闭超时
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 关闭HTTPS服务器
	if err := httpsServer.Shutdown(ctx); err != nil {
		log.Printf("HTTPS服务器强制关闭: %v", err)
	}

	// 关闭HTTP服务器（如果存在）
	if httpServer != nil {
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("HTTP服务器强制关闭: %v", err)
		}
	}

	log.Println("服务器已关闭")
}
