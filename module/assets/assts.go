package assets

import (
	"Dext-Server/security"
	"Dext-Server/utils"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Config 用于配置 OpenAssets 服务。
type Config struct {
	BaseURL        string          // 用于构建文件URL的基础URL（可选）；现在默认返回相对路径，避免域名变更造成死链
	StoragePath    string          // 存储文件的根路径
	MaxFileSize    int64           // 单个文件上传的最大大小
	MaxUserStorage int64           // 每个用户的最大总存储空间
	AllowedTypes   map[string]bool // 允许的MIME类型映射
	AuthRequired   bool            // API访问是否需要身份验证
}

// FileMetadata 存储有关已存储文件的信息。
type FileMetadata struct {
	ID           string    `json:"id"`
	FileName     string    `json:"fileName"`
	OriginalName string    `json:"originalName"`
	FileSize     int64     `json:"fileSize"`
	ContentType  string    `json:"contentType"`
	MD5Hash      string    `json:"md5Hash"`
	UploadTime   time.Time `json:"uploadTime"`
	Bucket       string    `json:"bucket"`
	URL          string    `json:"url"`
	Owner        string    `json:"owner"` // 文件所有者（用户名）
}

// UserStorage 跟踪单个用户的存储使用情况。
type UserStorage struct {
	Username  string
	UsedSize  int64
	FileCount int
}

// Service 是 OpenAssets 服务的主结构。
type Service struct {
	config      *Config
	db          *sql.DB                  // 用于用户验证的数据库连接
	fileStore   map[string]*FileMetadata // 文件元数据的内存存储
	userStorage map[string]*UserStorage  // 用户存储统计的内存存储
	mutex       sync.RWMutex
}

// NewService 创建并初始化一个新的 OpenAssets 服务实例。
func NewService(config *Config, db *sql.DB) (*Service, error) {
	if config.StoragePath == "" {
		return nil, fmt.Errorf("StoragePath 不能为空")
	}
	if config.BaseURL == "" {
		log.Printf("[OpenAssets] 提示: BaseURL 未设置，将返回相对路径URL，避免域名变更导致死链")
	}
	if db == nil {
		return nil, fmt.Errorf("数据库连接不能为空")
	}

	if err := os.MkdirAll(config.StoragePath, 0755); err != nil {
		log.Printf("[OpenAssets] 错误: 创建存储目录失败: %v", err)
		return nil, fmt.Errorf("创建存储目录失败: %w", err)
	}
	log.Printf("[OpenAssets] 信息: 存储目录已就绪: %s", config.StoragePath)

	// 预先创建一些通用的桶
	buckets := []string{"survey-assets", "images", "videos", "audio"}
	for _, bucket := range buckets {
		bucketPath := filepath.Join(config.StoragePath, bucket)
		if err := os.MkdirAll(bucketPath, 0755); err != nil {
			log.Printf("[OpenAssets] 错误: 创建桶目录 [%s] 失败: %v", bucket, err)
			return nil, fmt.Errorf("创建桶目录失败: %w", err)
		}
	}

	service := &Service{
		config:      config,
		db:          db,
		fileStore:   make(map[string]*FileMetadata),
		userStorage: make(map[string]*UserStorage),
	}

	log.Println("[OpenAssets] 信息: OpenAssets 服务初始化成功。")
	// 注意：在实际应用中，您可能希望在此处从持久化存储（如数据库或文件）加载现有的文件元数据。
	return service, nil
}

// AuthMiddleware 创建一个用于验证 OpenAssets 端点请求的 Gin 中间件。
func (s *Service) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !s.config.AuthRequired {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			log.Println("[OpenAssets] 错误: 缺少 Authorization 头")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "缺少认证令牌"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			log.Printf("[OpenAssets] 错误: 无效的 Authorization 头格式: %s", authHeader)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的认证格式"})
			c.Abort()
			return
		}

		tokenString := parts[1]
		username, err := validateToken(tokenString)
		if err != nil {
			log.Printf("[OpenAssets] 错误: 令牌验证失败: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的令牌"})
			c.Abort()
			return
		}

		if err := s.validateUser(username); err != nil {
			log.Printf("[OpenAssets] 错误: 用户验证失败: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "用户不存在或已被删除"})
			c.Abort()
			return
		}

		c.Set("username", username)
		c.Next()
	}
}

// validateToken 根据存储的密钥验证 JWT 令牌。
// 这是一个包内辅助函数。
func validateToken(tokenString string) (string, error) {
	secrets, err := security.LoadSecrets() // 假设 security 包可访问
	if err != nil {
		return "", fmt.Errorf("加载JWT密钥失败: %w", err)
	}
	if len(secrets) == 0 {
		return "", fmt.Errorf("没有可用于验证的JWT密钥")
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
			if claims.ExpiresAt.Before(time.Now()) {
				return "", fmt.Errorf("令牌已过期")
			}
			if claims.Subject == "" {
				return "", fmt.Errorf("令牌缺少 'sub' (subject) 声明")
			}
			return claims.Subject, nil // 成功
		}
		lastErr = err
	}

	return "", fmt.Errorf("令牌验证失败: %w", lastErr)
}

// validateUser 检查用户是否存在于数据库中。
// 它是 Service 的一个方法，因为它需要数据库连接。
func (s *Service) validateUser(username string) error {
	var userID string
	err := s.db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("用户 '%s' 未找到", username)
		}
		return fmt.Errorf("验证用户时发生数据库错误: %w", err)
	}
	return nil
}

// checkUserStorageLimit 检查新文件是否会超过用户的存储配额。
func (s *Service) checkUserStorageLimit(username string, fileSize int64) error {
	s.mutex.RLock()
	userStorage, exists := s.userStorage[username]
	s.mutex.RUnlock()

	if !exists {
		if fileSize > s.config.MaxUserStorage {
			log.Printf("[OpenAssets] 警告: 用户 [%s] 的单个文件大小 (%d 字节) 超过总存储限制 (%d 字节)", username, fileSize, s.config.MaxUserStorage)
			return fmt.Errorf("文件大小超过用户总存储限制")
		}
		return nil
	}

	if userStorage.UsedSize+fileSize > s.config.MaxUserStorage {
		log.Printf("[OpenAssets] 警告: 用户 [%s] 存储配额超出。已使用: %d, 新增: %d, 限制: %d",
			username, userStorage.UsedSize, fileSize, s.config.MaxUserStorage)
		return fmt.Errorf("用户存储配额超出。已使用: %d 字节, 限制: %d 字节",
			userStorage.UsedSize, s.config.MaxUserStorage)
	}
	return nil
}

// updateUserStorage 更新用户的内存中存储统计信息。
func (s *Service) updateUserStorage(username string, fileSize int64, isAdd bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	userStorage, exists := s.userStorage[username]
	if !exists {
		if isAdd {
			s.userStorage[username] = &UserStorage{Username: username, UsedSize: fileSize, FileCount: 1}
			log.Printf("[OpenAssets] 信息: 为新用户 [%s] 创建了存储统计。已使用: %d 字节", username, fileSize)
		}
		return
	}

	if isAdd {
		userStorage.UsedSize += fileSize
		userStorage.FileCount++
	} else {
		userStorage.UsedSize -= fileSize
		userStorage.FileCount--
		if userStorage.FileCount < 0 {
			userStorage.FileCount = 0
		}
		if userStorage.UsedSize < 0 {
			userStorage.UsedSize = 0
		}
	}
}

// UploadFile 是用于上传文件的核心服务逻辑。
// 它是导出的，因此可以从其他模块直接调用。
func (s *Service) UploadFile(bucket, filename, originalName, contentType, owner string, fileSize int64, fileData io.Reader) (*FileMetadata, error) {
	if fileSize > s.config.MaxFileSize {
		return nil, fmt.Errorf("文件大小 (%d 字节) 超过允许的最大大小 (%d 字节)", fileSize, s.config.MaxFileSize)
	}
	if !s.config.AllowedTypes[contentType] {
		return nil, fmt.Errorf("不允许的文件类型 '%s'", contentType)
	}
	if err := s.checkUserStorageLimit(owner, fileSize); err != nil {
		return nil, err
	}

	filePath := filepath.Join(s.config.StoragePath, bucket, filename)
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return nil, fmt.Errorf("创建桶目录失败: %w", err)
	}

	dst, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("创建目标文件失败: %w", err)
	}
	defer dst.Close()

	hash := md5.New()
	teeReader := io.TeeReader(fileData, hash)

	written, err := io.Copy(dst, teeReader)
	if err != nil {
		os.Remove(filePath) // 失败时清理
		return nil, fmt.Errorf("保存文件内容失败: %w", err)
	}
	md5Hash := hex.EncodeToString(hash.Sum(nil))

	fileID := uuid.New().String()

	// 统一使用相对路径，避免硬编码域名
	relURL := fmt.Sprintf("/openassets/files/%s/%s", bucket, filename)
	metadata := &FileMetadata{
		ID:           fileID,
		FileName:     filename,
		OriginalName: originalName,
		FileSize:     written,
		ContentType:  contentType,
		MD5Hash:      md5Hash,
		UploadTime:   time.Now(),
		Bucket:       bucket,
		URL:          relURL,
		Owner:        owner,
	}

	s.mutex.Lock()
	s.fileStore[fileID] = metadata
	s.mutex.Unlock()
	s.updateUserStorage(owner, written, true)

	log.Printf("[OpenAssets] 信息: 文件上传成功。所有者: %s, 路径: %s/%s, 大小: %d", owner, bucket, filename, written)
	return metadata, nil
}

// DeleteFile 是用于删除文件的核心服务逻辑。
func (s *Service) DeleteFile(bucket, filename, owner string) error {
	filePath := filepath.Join(s.config.StoragePath, bucket, filename)
	fileInfo, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return fmt.Errorf("文件未找到")
	}
	if err != nil {
		return fmt.Errorf("获取文件信息失败: %w", err)
	}

	// 先删除物理文件
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("删除物理文件失败: %w", err)
	}

	// 然后更新内存数据（使用锁保护）
	s.mutex.Lock()
	var fileIDToDelete string
	found := false
	for id, metadata := range s.fileStore {
		if metadata.FileName == filename && metadata.Bucket == bucket && metadata.Owner == owner {
			found = true
			fileIDToDelete = id
			break
		}
	}

	if !found {
		log.Printf("[OpenAssets] 警告: 正在为用户 [%s] 删除文件 [%s/%s]，但没有匹配的内存元数据记录。", owner, bucket, filename)
	}

	if fileIDToDelete != "" {
		delete(s.fileStore, fileIDToDelete)
	}

	// 直接在锁内更新用户存储，避免嵌套锁调用
	userStorage, exists := s.userStorage[owner]
	if !exists {
		userStorage = &UserStorage{Username: owner}
		s.userStorage[owner] = userStorage
	}
	userStorage.UsedSize -= fileInfo.Size()
	if userStorage.UsedSize < 0 {
		userStorage.UsedSize = 0
	}
	s.mutex.Unlock()

	log.Printf("[OpenAssets] 信息: 文件删除成功。所有者: %s, 路径: %s/%s", owner, bucket, filename)
	return nil
}

// UploadHandler 是文件上传的 Gin 处理程序。
func (s *Service) UploadHandler(c *gin.Context) {
	bucket := c.Param("bucket")
	username := c.MustGet("username").(string)

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "在请求中未找到文件"})
		return
	}
	defer file.Close()

	contentType := header.Header.Get("Content-Type")
	if contentType == "" || contentType == "application/octet-stream" {
		contentType = utils.GetContentTypeByExtension(header.Filename)
	}

	// 生成唯一且安全的文件名，以防止覆盖和路径遍历。
	safeFilename := fmt.Sprintf("%s-%s", uuid.NewString(), filepath.Base(header.Filename))

	metadata, err := s.UploadFile(bucket, safeFilename, header.Filename, contentType, username, header.Size, file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "上传失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, metadata)
}

// ImageQuality 定义图片质量级别
type ImageQuality struct {
	Name     string
	Quality  int
	MaxWidth int // 0 表示不限制
}

var (
	// 缩略图：低质量、小尺寸
	QualityThumb = ImageQuality{Name: "thumb", Quality: 60, MaxWidth: 300}
	// 中等质量：适合移动端
	QualityMedium = ImageQuality{Name: "medium", Quality: 75, MaxWidth: 1200}
	// 原图：高质量
	QualityOriginal = ImageQuality{Name: "original", Quality: 95, MaxWidth: 0}
)

// getCompressedPath 获取压缩图的存储路径
func (s *Service) getCompressedPath(bucket, filename, qualityType string) string {
	// 压缩图存储在 compressed 子目录
	base := filepath.Base(filename)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	compressedName := fmt.Sprintf("%s_%s.jpg", name, qualityType)
	return filepath.Join(s.config.StoragePath, bucket, "compressed", compressedName)
}

// resizeImage 调整图片尺寸（简单的最近邻算法）
func resizeImage(img image.Image, maxWidth int) image.Image {
	if maxWidth == 0 {
		return img
	}

	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	if width <= maxWidth {
		return img
	}

	// 计算新尺寸
	newWidth := maxWidth
	newHeight := height * maxWidth / width

	// 创建新图片
	resized := image.NewRGBA(image.Rect(0, 0, newWidth, newHeight))

	// 简单的最近邻缩放
	for y := 0; y < newHeight; y++ {
		for x := 0; x < newWidth; x++ {
			srcX := x * width / newWidth
			srcY := y * height / newHeight
			resized.Set(x, y, img.At(srcX, srcY))
		}
	}

	return resized
}

// generateCompressedImage 生成压缩图并保存到磁盘
func (s *Service) generateCompressedImage(originalPath, compressedPath string, quality ImageQuality) error {
	// 打开原始文件
	file, err := os.Open(originalPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// 解码图片
	var img image.Image
	ext := strings.ToLower(filepath.Ext(originalPath))
	switch ext {
	case ".jpg", ".jpeg":
		img, err = jpeg.Decode(file)
	case ".png":
		img, err = png.Decode(file)
	default:
		return fmt.Errorf("不支持的图片格式: %s", ext)
	}

	if err != nil {
		return fmt.Errorf("解码图片失败: %w", err)
	}

	// 调整尺寸
	if quality.MaxWidth > 0 {
		img = resizeImage(img, quality.MaxWidth)
	}

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(compressedPath), 0755); err != nil {
		return fmt.Errorf("创建压缩图目录失败: %w", err)
	}

	// 创建输出文件
	outFile, err := os.Create(compressedPath)
	if err != nil {
		return fmt.Errorf("创建压缩图文件失败: %w", err)
	}
	defer outFile.Close()

	// 编码为 JPEG
	if err := jpeg.Encode(outFile, img, &jpeg.Options{Quality: quality.Quality}); err != nil {
		return fmt.Errorf("编码图片失败: %w", err)
	}

	log.Printf("[OpenAssets] 生成压缩图成功: %s (质量: %s, %d%%)", compressedPath, quality.Name, quality.Quality)
	return nil
}

// DownloadHandler 是文件下载的 Gin 处理程序。此端点通常是公开的。
func (s *Service) DownloadHandler(c *gin.Context) {
	bucket := c.Param("bucket")
	filename := c.Param("filename")

	// 基本的安全检查，防止路径遍历
	if strings.Contains(filename, "..") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的文件名"})
		return
	}

	// 原图路径
	originalPath := filepath.Join(s.config.StoragePath, bucket, filename)

	// 检查原图是否存在
	if _, err := os.Stat(originalPath); os.IsNotExist(err) {
		log.Printf("拒绝连接: 访问不存在的文件 %s/%s", bucket, filename)
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	// 判断是否为图片文件
	ext := strings.ToLower(filepath.Ext(filename))
	isImage := ext == ".jpg" || ext == ".jpeg" || ext == ".png"

	// 设置缓存头（7天）
	c.Header("Cache-Control", "public, max-age=604800")
	c.Header("Content-Disposition", fmt.Sprintf("inline; filename=%q", filename))

	// 非图片文件直接返回
	if !isImage {
		contentType := utils.GetContentTypeByExtension(filename)
		if contentType != "" {
			c.Header("Content-Type", contentType)
		} else {
			c.Header("Content-Type", "application/octet-stream")
		}
		c.File(originalPath)
		return
	}

	// 图片文件：获取质量参数
	qualityType := c.DefaultQuery("type", "medium") // 默认中等质量
	_, hasYt := c.GetQuery("yt")

	// yt 参数优先，返回原图
	if hasYt {
		qualityType = "original"
	}

	// 根据质量类型选择配置
	var quality ImageQuality
	switch qualityType {
	case "thumb":
		quality = QualityThumb
	case "medium":
		quality = QualityMedium
	case "original":
		// 返回原图
		c.Header("Content-Type", "image/"+strings.TrimPrefix(ext, "."))
		c.File(originalPath)
		return
	default:
		// 未知类型，返回中等质量
		quality = QualityMedium
	}

	// 获取压缩图路径
	compressedPath := s.getCompressedPath(bucket, filename, quality.Name)

	// 懒生成策略：检查压缩图是否存在
	if _, err := os.Stat(compressedPath); os.IsNotExist(err) {
		// 压缩图不存在，生成它
		log.Printf("[OpenAssets] 压缩图不存在，开始生成: %s", compressedPath)
		if err := s.generateCompressedImage(originalPath, compressedPath, quality); err != nil {
			// 生成失败，返回原图
			log.Printf("[OpenAssets] 生成压缩图失败: %v，返回原图", err)
			c.Header("Content-Type", "image/"+strings.TrimPrefix(ext, "."))
			c.File(originalPath)
			return
		}
	}

	// 返回压缩图
	c.Header("Content-Type", "image/jpeg")
	c.File(compressedPath)
}

// DeleteHandler 是删除文件的 Gin 处理程序。
func (s *Service) DeleteHandler(c *gin.Context) {
	bucket := c.Param("bucket")
	filename := c.Param("filename")
	username := c.MustGet("username").(string)

	err := s.DeleteFile(bucket, filename, username)
	if err != nil {
		if strings.Contains(err.Error(), "未找到") {
			log.Printf("拒绝连接: %v", err)
			c.AbortWithStatus(http.StatusNotFound)
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "文件删除成功"})
}

// ListHandler 是用于列出特定桶中用户文件的 Gin 处理程序。
func (s *Service) ListHandler(c *gin.Context) {
	bucket := c.Param("bucket")
	username := c.MustGet("username").(string)

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var files []*FileMetadata
	for _, metadata := range s.fileStore {
		if metadata.Bucket == bucket && metadata.Owner == username {
			files = append(files, metadata)
		}
	}

	c.JSON(http.StatusOK, gin.H{"files": files, "count": len(files), "bucket": bucket, "owner": username})
}

// InfoHandler 是获取特定文件元数据的 Gin 处理程序。
func (s *Service) InfoHandler(c *gin.Context) {
	bucket := c.Param("bucket")
	filename := c.Param("filename")
	username := c.MustGet("username").(string)

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var metadata *FileMetadata
	for _, meta := range s.fileStore {
		if meta.FileName == filename && meta.Bucket == bucket && meta.Owner == username {
			metadata = meta
			break
		}
	}

	if metadata == nil {
		log.Printf("拒绝连接: 文件未找到或访问被拒绝")
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	c.JSON(http.StatusOK, metadata)
}

// GetUserStorageHandler 是获取用户存储统计信息的 Gin 处理程序。
func (s *Service) GetUserStorageHandler(c *gin.Context) {
	username := c.MustGet("username").(string)
	paramUsername := c.Param("username")

	if paramUsername != username {
		// 将来可在此处为管理员角色添加逻辑
		c.JSON(http.StatusForbidden, gin.H{"error": "无权查看其他用户的存储信息"})
		return
	}

	s.mutex.RLock()
	userStorage, exists := s.userStorage[paramUsername]
	s.mutex.RUnlock()

	if !exists {
		userStorage = &UserStorage{Username: paramUsername, UsedSize: 0, FileCount: 0}
	}

	remainingSize := s.config.MaxUserStorage - userStorage.UsedSize
	if remainingSize < 0 {
		remainingSize = 0
	}

	usagePercent := 0.0
	if s.config.MaxUserStorage > 0 {
		usagePercent = (float64(userStorage.UsedSize) / float64(s.config.MaxUserStorage)) * 100
	}

	c.JSON(http.StatusOK, gin.H{
		"username":      paramUsername,
		"usedSize":      userStorage.UsedSize,
		"fileCount":     userStorage.FileCount,
		"maxSize":       s.config.MaxUserStorage,
		"remainingSize": remainingSize,
		"usagePercent":  usagePercent,
	})
}

// GetStatsHandler 是获取整体服务统计信息的 Gin 处理程序。
func (s *Service) GetStatsHandler(c *gin.Context) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	totalFiles := len(s.fileStore)
	totalUsersWithFiles := len(s.userStorage)
	var totalSize int64
	for _, storage := range s.userStorage {
		totalSize += storage.UsedSize
	}

	c.JSON(http.StatusOK, gin.H{
		"totalFiles":          totalFiles,
		"totalUsersWithFiles": totalUsersWithFiles,
		"totalSize":           totalSize,
		"maxFileSize":         s.config.MaxFileSize,
		"maxUserStorage":      s.config.MaxUserStorage,
	})
}

func (s *Service) Config() *Config {
	return s.config
}
