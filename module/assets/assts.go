package assets

import (
	"Dext-Server/env"
	"Dext-Server/security"
	"Dext-Server/utils"
	"bytes"
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
	"golang.org/x/sync/singleflight"
)

// Config 用于配置 OpenAssets 服务。
type Config struct {
	BaseURL        string          // 用于构建文件URL的基础URL（可选）；现在默认返回相对路径，避免域名变更造成死链
	StoragePath    string          // 存储文件的根路径（github 模式下作为本地缓存目录）
	MaxFileSize    int64           // 单个文件上传的最大大小
	MaxUserStorage int64           // 每个用户的最大总存储空间
	AllowedTypes   map[string]bool // 允许的MIME类型映射
	AuthRequired   bool            // API访问是否需要身份验证
	Backend        string          // 存储后端: "local"（默认）或 "github"
	GitHub         GitHubConfig    // GitHub 图床配置（Backend="github" 时生效）
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
	PublicName   string    `json:"publicName"`
	URL          string    `json:"url"`
	Owner        string    `json:"owner"`
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
	assetsDB    *sql.DB                  // assets 文件元数据数据库连接
	backend     StorageBackend           // 存储后端（local / github）
	fileStore   map[string]*FileMetadata // 文件元数据的内存存储
	nameIndex   map[string]*FileMetadata // 文件名索引: bucket/publicName -> metadata
	userStorage map[string]*UserStorage  // 用户存储统计的内存存储
	mutex       sync.RWMutex
	sfGroup     singleflight.Group
}

func isProduction() bool {
	return env.IsProduction()
}

func shouldLog() bool {
	return env.ShouldLog()
}

// NewService 创建并初始化一个新的 OpenAssets 服务实例。
func isSafeBucketName(bucket string) bool {
	if bucket == "" || len(bucket) > 64 {
		return false
	}
	for _, r := range bucket {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func isSafeFileName(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	if strings.Contains(name, "..") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	return filepath.Base(name) == name
}

func stripExtension(name string) string {
	ext := filepath.Ext(name)
	return strings.TrimSuffix(name, ext)
}

func stripQualitySuffix(name string) string {
	name = stripExtension(name)
	for _, suffix := range []string{"_thumb", "_medium", "_original"} {
		name = strings.TrimSuffix(name, suffix)
	}
	return name
}

func (s *Service) resolveStoragePath(bucket, filename string) (string, error) {
	return s.backend.LocalPath(bucket, filename)
}

func (s *Service) rebuildIndex() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	entries, err := os.ReadDir(s.config.StoragePath)
	if err != nil {
		return fmt.Errorf("读取存储目录失败: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		bucket := entry.Name()
		if !isSafeBucketName(bucket) {
			continue
		}

		bucketPath := filepath.Join(s.config.StoragePath, bucket)
		files, err := os.ReadDir(bucketPath)
		if err != nil {
			if shouldLog() {
				log.Printf("[OpenAssets] 警告: 读取桶 [%s] 失败: %v", bucket, err)
			}
			continue
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}
			filename := file.Name()
			if !isSafeFileName(filename) {
				continue
			}

			publicName := stripQualitySuffix(filename)
			publicName = stripExtension(publicName)
			indexKey := bucket + "/" + publicName

			if _, exists := s.nameIndex[indexKey]; exists {
				continue
			}

			info, err := file.Info()
			if err != nil {
				continue
			}

			contentType := utils.GetContentTypeByExtension(filename)
			if contentType == "" {
				contentType = "application/octet-stream"
			}

			metadata := &FileMetadata{
				ID:           uuid.New().String(),
				FileName:     filename,
				OriginalName: filename,
				FileSize:     info.Size(),
				ContentType:  contentType,
				UploadTime:   info.ModTime(),
				Bucket:       bucket,
				PublicName:   publicName,
				URL:          fmt.Sprintf("/openassets/files/%s/%s", bucket, publicName),
				Owner:        "unknown",
			}
			s.fileStore[metadata.ID] = metadata
			s.nameIndex[indexKey] = metadata
			if err := SaveFileToDB(s.assetsDB, metadata); err != nil {
				if shouldLog() {
					log.Printf("[OpenAssets] 警告: 保存文件 %s 到数据库失败: %v", filename, err)
				}
			}

			compressedPath := filepath.Join(bucketPath, "compressed")
			cfEntries, err := os.ReadDir(compressedPath)
			if err != nil {
				continue
			}
			for _, cf := range cfEntries {
				if cf.IsDir() {
					continue
				}
				cfName := cf.Name()
				cfExt := strings.ToLower(filepath.Ext(cfName))
				if cfExt != ".jpg" && cfExt != ".png" {
					continue
				}
				cfBase := publicName + "_"
				if !strings.HasPrefix(cfName, cfBase) {
					continue
				}
				quality := strings.TrimSuffix(strings.TrimPrefix(stripExtension(cfName), publicName+"_"), cfExt)
				if quality == cfName {
					continue
				}
				cfInfo, _ := cf.Info()
				cfile := &CompressedFile{
					ID:                 uuid.New().String(),
					Bucket:             bucket,
					OriginalFileName:   filename,
					CompressedFileName: cfName,
					Quality:            quality,
					FileSize:           cfInfo.Size(),
					ContentType:        "image/" + strings.TrimPrefix(cfExt, "."),
					OriginalID:         metadata.ID,
				}
				_ = SaveCompressedFile(s.assetsDB, cfile)
			}
		}
	}

	fileCount := len(s.fileStore)
	if shouldLog() {
		log.Printf("[OpenAssets] 信息: 索引重建完成，共加载 %d 个文件", fileCount)
	}
	return nil
}

func (s *Service) loadFromDB() error {
	if s.assetsDB == nil {
		return fmt.Errorf("数据库连接未初始化")
	}

	rows, err := s.assetsDB.Query(`
		SELECT id, file_name, original_name, file_size, content_type, md5_hash, upload_time, bucket, public_name, owner, url
		FROM assets_files`)
	if err != nil {
		return fmt.Errorf("查询数据库失败: %w", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		m, err := ScanFileMetadata(rows)
		if err != nil {
			continue
		}
		s.fileStore[m.ID] = m
		s.nameIndex[m.Bucket+"/"+m.PublicName] = m
		count++
	}

	diskCount := s.countDiskFiles()
	// 仅本地后端强制磁盘与数据库一致；github 后端磁盘只是缓存，数量不匹配是正常的
	if count > 0 && count != diskCount && s.backend.DiskAuthoritative() {
		if shouldLog() {
			log.Printf("[OpenAssets] 警告: 数据库记录数(%d)与磁盘文件数(%d)不匹配，清空数据库并重新导入", count, diskCount)
		}
		_, _ = s.assetsDB.Exec("TRUNCATE TABLE assets_files")
		s.fileStore = make(map[string]*FileMetadata)
		s.nameIndex = make(map[string]*FileMetadata)
		return fmt.Errorf("数据库与磁盘不一致，需要重新导入")
	}

	if shouldLog() {
		log.Printf("[OpenAssets] 信息: 从数据库加载 %d 条文件记录", count)
	}
	if count == 0 {
		return fmt.Errorf("数据库为空，需要从磁盘导入")
	}

	s.loadCompressedIndex()
	return nil
}

func (s *Service) loadCompressedIndex() {
	entries, err := os.ReadDir(s.config.StoragePath)
	if err != nil {
		return
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		bucket := entry.Name()
		if !isSafeBucketName(bucket) {
			continue
		}
		compressedPath := filepath.Join(s.config.StoragePath, bucket, "compressed")
		cfEntries, err := os.ReadDir(compressedPath)
		if err != nil {
			continue
		}
		for _, cf := range cfEntries {
			if cf.IsDir() {
				continue
			}
			cfName := cf.Name()
			ext := strings.ToLower(filepath.Ext(cfName))
			if ext != ".jpg" && ext != ".png" {
				continue
			}
			base := stripExtension(cfName)
			parts := strings.SplitN(base, "_", 2)
			if len(parts) != 2 {
				continue
			}
			publicName := parts[0]
			quality := parts[1]
			indexKey := bucket + "/" + publicName
			meta, ok := s.nameIndex[indexKey]
			cfInfo, _ := cf.Info()
			cfile := &CompressedFile{
				ID:                 uuid.New().String(),
				Bucket:             bucket,
				OriginalFileName:   "",
				CompressedFileName: cfName,
				Quality:            quality,
				FileSize:           cfInfo.Size(),
				ContentType:        "image/" + strings.TrimPrefix(ext, "."),
				OriginalID:         "",
			}
			if ok {
				cfile.OriginalID = meta.ID
				cfile.OriginalFileName = meta.FileName
			}
			if err := SaveCompressedFile(s.assetsDB, cfile); err != nil {
				if shouldLog() {
					log.Printf("[OpenAssets] 警告: 保存压缩图索引失败: %v", err)
				}
			}
			count++
		}
	}
	if shouldLog() {
		log.Printf("[OpenAssets] 信息: 加载 %d 个压缩图索引", count)
	}
}

func (s *Service) countDiskFiles() int {
	count := 0
	entries, err := os.ReadDir(s.config.StoragePath)
	if err != nil {
		return 0
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		bucket := entry.Name()
		if !isSafeBucketName(bucket) {
			continue
		}
		bucketPath := filepath.Join(s.config.StoragePath, bucket)
		files, err := os.ReadDir(bucketPath)
		if err != nil {
			continue
		}
		for _, f := range files {
			if !f.IsDir() {
				count++
			}
		}
	}
	return count
}

func NewService(config *Config, db *sql.DB) (*Service, error) {
	if config.StoragePath == "" {
		return nil, fmt.Errorf("StoragePath 不能为空")
	}
	// BaseURL is no longer used; all URLs are generated as relative paths
	// to avoid broken links when domain changes
	if db == nil {
		return nil, fmt.Errorf("数据库连接不能为空")
	}

	if err := os.MkdirAll(config.StoragePath, 0755); err != nil {
		log.Printf("[OpenAssets] 错误: 创建存储目录失败: %v", err)
		return nil, fmt.Errorf("创建存储目录失败: %w", err)
	}
	if shouldLog() {
		log.Printf("[OpenAssets] 信息: 存储目录已就绪: %s", config.StoragePath)
	}

	// 预先创建一些通用的桶
	buckets := []string{"survey-assets", "images", "videos"}
	for _, bucket := range buckets {
		bucketPath := filepath.Join(config.StoragePath, bucket)
		if err := os.MkdirAll(bucketPath, 0755); err != nil {
			log.Printf("[OpenAssets] 错误: 创建桶目录 [%s] 失败: %v", bucket, err)
			return nil, fmt.Errorf("创建桶目录失败: %w", err)
		}
		// compressed 子目录始终基于本地缓存路径创建（压缩图只存本地）
		if err := os.MkdirAll(filepath.Join(bucketPath, "compressed"), 0755); err != nil {
			log.Printf("[OpenAssets] 错误: 创建桶压缩目录 [%s/compressed] 失败: %v", bucket, err)
			return nil, fmt.Errorf("创建桶压缩目录失败: %w", err)
		}
	}

	// 根据配置初始化存储后端
	var backend StorageBackend
	switch strings.ToLower(config.Backend) {
	case "github":
		// github 模式下 StoragePath 作为本地缓存目录
		config.GitHub.StoragePath = config.StoragePath
		githubBackend, err := newGitHubStorage(config.GitHub)
		if err != nil {
			return nil, fmt.Errorf("初始化 GitHub 存储后端失败: %w", err)
		}
		backend = githubBackend
		if shouldLog() {
			log.Printf("[OpenAssets] 信息: 使用 GitHub 存储后端 (owner=%s repo=%s branch=%s)",
				config.GitHub.Owner, config.GitHub.Repo, config.GitHub.Branch)
		}
	default:
		backend = newLocalStorage(config.StoragePath)
		if shouldLog() {
			log.Printf("[OpenAssets] 信息: 使用本地存储后端")
		}
	}

	service := &Service{
		config:      config,
		db:          db,
		assetsDB:    db,
		backend:     backend,
		fileStore:   make(map[string]*FileMetadata),
		nameIndex:   make(map[string]*FileMetadata),
		userStorage: make(map[string]*UserStorage),
	}

	if err := RunMigrations(db); err != nil {
		log.Printf("[OpenAssets] 错误: 数据库迁移失败: %v", err)
		return nil, fmt.Errorf("数据库迁移失败: %w", err)
	}

	if err := service.loadFromDB(); err != nil {
		log.Printf("[OpenAssets] 警告: 从数据库加载失败: %v，将使用冷启动索引", err)
		if err := service.rebuildIndex(); err != nil {
			log.Printf("[OpenAssets] 警告: 索引重建也失败: %v", err)
		}
	}

	log.Println("[OpenAssets] 信息: OpenAssets 服务初始化成功。")
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
			if shouldLog() {
				log.Printf("[OpenAssets] 信息: 为新用户 [%s] 创建了存储统计。已使用: %d 字节", username, fileSize)
			}
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
	// header.Size 可能不可信/为 0：若可用则先做一次预检查，最终以实际写入大小为准再校验。
	if fileSize > 0 {
		if err := s.checkUserStorageLimit(owner, fileSize); err != nil {
			return nil, err
		}
	}

	hash := md5.New()
	// 限制读取，避免客户端伪报 size 导致超大文件写入
	limited := io.LimitReader(fileData, s.config.MaxFileSize+1)
	teeReader := io.TeeReader(limited, hash)

	// 通过存储后端写入：local 直接落盘；github 先落本地缓存再异步推送
	written, err := s.backend.Put(bucket, filename, teeReader)
	if err != nil {
		return nil, fmt.Errorf("保存文件内容失败: %w", err)
	}
	if written > s.config.MaxFileSize {
		_ = s.backend.Delete(bucket, filename)
		return nil, fmt.Errorf("文件大小 (%d 字节) 超过允许的最大大小 (%d 字节)", written, s.config.MaxFileSize)
	}
	if err := s.checkUserStorageLimit(owner, written); err != nil {
		_ = s.backend.Delete(bucket, filename)
		return nil, err
	}
	md5Hash := hex.EncodeToString(hash.Sum(nil))

	fileID := uuid.New().String()

	publicName := stripQualitySuffix(filename)
	publicName = stripExtension(publicName)

	relURL := fmt.Sprintf("/openassets/files/%s/%s", bucket, publicName)
	metadata := &FileMetadata{
		ID:           fileID,
		FileName:     filename,
		OriginalName: originalName,
		FileSize:     written,
		ContentType:  contentType,
		MD5Hash:      md5Hash,
		UploadTime:   time.Now(),
		Bucket:       bucket,
		PublicName:   publicName,
		URL:          relURL,
		Owner:        owner,
	}

	if err := SaveFileToDB(s.assetsDB, metadata); err != nil {
		if shouldLog() {
			log.Printf("[OpenAssets] 警告: 保存文件元数据到数据库失败: %v", err)
		}
	}

	s.mutex.Lock()
	s.fileStore[fileID] = metadata
	s.nameIndex[bucket+"/"+publicName] = metadata
	s.mutex.Unlock()
	s.updateUserStorage(owner, written, true)

	if shouldLog() {
		log.Printf("[OpenAssets] 信息: 文件上传成功。所有者: %s, 路径: %s/%s, 大小: %d", owner, bucket, filename, written)
	}
	return metadata, nil
}

// DeleteFile 是用于删除文件的核心服务逻辑。
func (s *Service) DeleteFile(bucket, filename, owner string) error {
	filePath, err := s.resolveStoragePath(bucket, filename)
	if err != nil {
		return err
	}

	// 先从内存索引拿到元数据（用于存储配额回退和存在性判断）
	s.mutex.RLock()
	var meta *FileMetadata
	for _, m := range s.fileStore {
		if m.FileName == filename && m.Bucket == bucket && m.Owner == owner {
			meta = m
			break
		}
	}
	s.mutex.RUnlock()

	fileInfo, statErr := os.Stat(filePath)
	// 本地缓存不存在时：github 后端仍可凭远端 SHA 删除；local 后端则视为未找到
	if os.IsNotExist(statErr) {
		if s.backend.DiskAuthoritative() {
			return fmt.Errorf("文件未找到")
		}
		// github 模式：若索引中也没有，则视为未找到
		if meta == nil {
			return fmt.Errorf("文件未找到")
		}
	} else if statErr != nil {
		return fmt.Errorf("获取文件信息失败: %w", statErr)
	}

	// 通过存储后端删除：local 删本地；github 同时删远端和本地缓存
	if err := s.backend.Delete(bucket, filename); err != nil {
		return fmt.Errorf("删除物理文件失败: %w", err)
	}

	// 压缩图始终只存本地缓存，直接清理
	compressedDir := filepath.Join(s.config.StoragePath, bucket, "compressed")
	compressedBase := stripExtension(filename)
	compressedFiles, _ := filepath.Glob(filepath.Join(compressedDir, compressedBase+"_*"))
	for _, f := range compressedFiles {
		os.Remove(f)
	}

	s.mutex.Lock()
	var fileIDToDelete string
	var publicName string
	for id, metadata := range s.fileStore {
		if metadata.FileName == filename && metadata.Bucket == bucket && metadata.Owner == owner {
			fileIDToDelete = id
			publicName = stripQualitySuffix(metadata.FileName)
			publicName = stripExtension(publicName)
			break
		}
	}

	if fileIDToDelete != "" {
		delete(s.fileStore, fileIDToDelete)
		delete(s.nameIndex, bucket+"/"+publicName)
		if err := DeleteFileFromDB(s.assetsDB, bucket, publicName); err != nil {
			if shouldLog() {
				log.Printf("[OpenAssets] 警告: 从数据库删除文件记录失败: %v", err)
			}
		}
		if err := DeleteCompressedFilesByOriginal(s.assetsDB, filename); err != nil {
			if shouldLog() {
				log.Printf("[OpenAssets] 警告: 从数据库删除压缩图记录失败: %v", err)
			}
		}
	}

	// 计算要扣减的存储大小：优先用磁盘实际大小，磁盘不存在时回退到元数据记录
	var sizeToDeduct int64
	if fileInfo != nil {
		sizeToDeduct = fileInfo.Size()
	} else if meta != nil {
		sizeToDeduct = meta.FileSize
	}
	userStorage, exists := s.userStorage[owner]
	if !exists {
		userStorage = &UserStorage{Username: owner}
		s.userStorage[owner] = userStorage
	}
	userStorage.UsedSize -= sizeToDeduct
	if userStorage.UsedSize < 0 {
		userStorage.UsedSize = 0
	}
	s.mutex.Unlock()

	if shouldLog() {
		log.Printf("[OpenAssets] 信息: 文件删除成功。所有者: %s, 路径: %s/%s", owner, bucket, filename)
	}
	return nil
}

// UploadHandler 是文件上传的 Gin 处理程序。
func (s *Service) UploadHandler(c *gin.Context) {
	bucket := c.Param("bucket")
	username := c.MustGet("username").(string)
	if !isSafeBucketName(bucket) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid bucket"})
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "在请求中未找到文件"})
		return
	}
	defer file.Close()

	// 不信任客户端声明的 Content-Type：优先基于文件内容嗅探，其次基于扩展名兜底。
	extType := utils.GetContentTypeByExtension(header.Filename)

	sniffBuf := make([]byte, 512)
	n, _ := file.Read(sniffBuf)
	sniff := sniffBuf[:n]
	detectedType := strings.TrimSpace(strings.Split(http.DetectContentType(sniff), ";")[0])
	if detectedType == "application/octet-stream" {
		detectedType = ""
	}

	contentType := detectedType
	if contentType == "" {
		contentType = extType
	}
	if contentType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无法识别文件类型"})
		return
	}

	// 对高风险二进制类型更严格：若扩展名表示为图片/音视频/PDF，但内容嗅探失败，则拒绝。
	if strings.HasPrefix(extType, "image/") || strings.HasPrefix(extType, "video/") || strings.HasPrefix(extType, "audio/") || extType == "application/pdf" {
		if detectedType == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "文件类型校验失败"})
			return
		}
	}

	// 还原 reader：先读到的 sniff 字节要拼回去，否则会导致文件头丢失
	fileReader := io.MultiReader(bytes.NewReader(sniff), file)

	// 生成唯一且安全的文件名，以防止覆盖和路径遍历。
	safeFilename := fmt.Sprintf("%s-%s", uuid.NewString(), filepath.Base(header.Filename))

	metadata, err := s.UploadFile(bucket, safeFilename, header.Filename, contentType, username, header.Size, fileReader)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "上传失败: " + err.Error()})
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
	base := filepath.Base(filename)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	compressedName := fmt.Sprintf("%s_%s%s", name, qualityType, ext)
	return filepath.Join(s.config.StoragePath, bucket, "compressed", compressedName)
}

func (s *Service) findRealFilename(bucket, publicName string) (string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	indexKey := bucket + "/" + publicName
	if meta, ok := s.nameIndex[indexKey]; ok {
		return meta.FileName, nil
	}

	return "", fmt.Errorf("file not found")
}

func (s *Service) findMetadataByFilename(bucket, filename string) (*FileMetadata, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, meta := range s.fileStore {
		if meta.Bucket == bucket && meta.FileName == filename {
			return meta, true
		}
	}
	return nil, false
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
func (s *Service) generateCompressedImage(bucket, realFilename, compressedPath string, quality ImageQuality) error {
	// 通过后端 Get 确保原图在本地缓存可用（github 模式下未命中会从 CDN 拉取）
	originalPath, err := s.backend.Get(bucket, realFilename)
	if err != nil {
		return err
	}
	file, err := os.Open(originalPath)
	if err != nil {
		return err
	}
	defer file.Close()

	header := make([]byte, 8)
	if _, err := file.Read(header); err != nil {
		return fmt.Errorf("读取文件头失败: %w", err)
	}

	file.Seek(0, 0)

	var img image.Image
	var decodeErr error

	if isJPEG(header) {
		img, decodeErr = jpeg.Decode(file)
	} else if isPNG(header) {
		img, decodeErr = png.Decode(file)
	} else {
		return fmt.Errorf("无法识别的图片格式: %v", header[:4])
	}

	if decodeErr != nil {
		return fmt.Errorf("解码图片失败: %w", decodeErr)
	}

	if quality.MaxWidth > 0 {
		img = resizeImage(img, quality.MaxWidth)
	}

	if err := os.MkdirAll(filepath.Dir(compressedPath), 0755); err != nil {
		return fmt.Errorf("创建压缩图目录失败: %w", err)
	}

	outFile, err := os.Create(compressedPath)
	if err != nil {
		return fmt.Errorf("创建压缩图文件失败: %w", err)
	}
	defer outFile.Close()

	var contentType string
	if isJPEG(header) {
		if err := jpeg.Encode(outFile, img, &jpeg.Options{Quality: quality.Quality}); err != nil {
			return fmt.Errorf("编码图片失败: %w", err)
		}
		contentType = "image/jpeg"
	} else if isPNG(header) {
		if err := png.Encode(outFile, img); err != nil {
			return fmt.Errorf("编码图片失败: %w", err)
		}
		contentType = "image/png"
	}

	info, _ := os.Stat(compressedPath)
	cfile := &CompressedFile{
		ID:                 uuid.New().String(),
		Bucket:             bucket,
		OriginalFileName:   realFilename,
		CompressedFileName: filepath.Base(compressedPath),
		Quality:            quality.Name,
		FileSize:           info.Size(),
		ContentType:        contentType,
	}
	if meta, ok := s.findMetadataByFilename(bucket, realFilename); ok {
		cfile.OriginalID = meta.ID
	}
	if s.assetsDB != nil {
		_ = SaveCompressedFile(s.assetsDB, cfile)
	}

	if shouldLog() {
		log.Printf("[OpenAssets] 生成压缩图成功: %s (质量: %s, %d%%)", compressedPath, quality.Name, quality.Quality)
	}
	return nil
}

func isJPEG(header []byte) bool {
	return len(header) >= 3 && header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF
}

func isPNG(header []byte) bool {
	return len(header) >= 8 && header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47
}

// DownloadHandler 是文件下载的 Gin 处理程序。此端点通常是公开的。
func (s *Service) DownloadHandler(c *gin.Context) {
	bucket := c.Param("bucket")
	publicName := c.Param("filename")

	if !isSafeBucketName(bucket) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的bucket"})
		return
	}

	publicName = stripExtension(publicName)

	realFilename, err := s.findRealFilename(bucket, publicName)
	if err != nil {
		log.Printf("拒绝连接: 访问不存在的文件 %s/%s: %v", bucket, publicName, err)
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	originalPath, err := s.backend.Get(bucket, realFilename)
	if err != nil {
		log.Printf("拒绝连接: 获取文件失败 %s/%s: %v", bucket, realFilename, err)
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	if _, err := os.Stat(originalPath); os.IsNotExist(err) {
		log.Printf("拒绝连接: 物理文件不存在 %s/%s", bucket, realFilename)
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	ext := strings.ToLower(filepath.Ext(realFilename))
	isImage := ext == ".jpg" || ext == ".jpeg" || ext == ".png"

	qualityType := c.DefaultQuery("type", "medium")
	_, hasYt := c.GetQuery("yt")
	if hasYt {
		qualityType = "original"
	}

	c.Header("Cache-Control", "public, max-age=31536000, immutable")

	if !isImage {
		contentType := utils.GetContentTypeByExtension(realFilename)
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		c.Header("Content-Type", contentType)
		// 非图片一律按下载处理，降低被浏览器当作可执行内容渲染的风险
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", realFilename))
		c.File(originalPath)
		return
	}

	var quality ImageQuality
	switch qualityType {
	case "thumb":
		quality = QualityThumb
	case "medium":
		quality = QualityMedium
	case "original":
		c.Header("Content-Type", "image/"+strings.TrimPrefix(ext, "."))
		c.Header("Content-Disposition", fmt.Sprintf("inline; filename=%q", realFilename))
		c.File(originalPath)
		return
	default:
		quality = QualityMedium
	}

	compressedPath := s.getCompressedPath(bucket, realFilename, quality.Name)

	if s.assetsDB != nil {
		if cf, err := GetCompressedFile(s.assetsDB, realFilename, quality.Name); err == nil && cf != nil {
			if _, statErr := os.Stat(compressedPath); statErr == nil {
				if shouldLog() {
					log.Printf("[OpenAssets] DB命中压缩图: %s -> %s", realFilename, cf.CompressedFileName)
				}
				c.Header("Content-Type", cf.ContentType)
				c.Header("Content-Disposition", fmt.Sprintf("inline; filename=%q", realFilename))
				c.File(compressedPath)
				return
			}
			if shouldLog() {
				log.Printf("[OpenAssets] DB命中但文件不存在，将重新生成: %s", compressedPath)
			}
		} else if err != nil {
			if shouldLog() {
				log.Printf("[OpenAssets] DB查询压缩图失败: %v", err)
			}
		} else {
			if shouldLog() {
				log.Printf("[OpenAssets] DB未命中压缩图: %s (quality=%s)", realFilename, quality.Name)
			}
		}
	}

	_, statErr := os.Stat(compressedPath)
	if os.IsNotExist(statErr) {
		sfKey := fmt.Sprintf("%s/%s/%s", bucket, realFilename, quality.Name)
		_, err, _ = s.sfGroup.Do(sfKey, func() (interface{}, error) {
			if _, err := os.Stat(compressedPath); err == nil {
				return nil, nil
			}
			if shouldLog() {
				log.Printf("[OpenAssets] 压缩图不存在，开始生成: %s", compressedPath)
			}
			return nil, s.generateCompressedImage(bucket, realFilename, compressedPath, quality)
		})
		if err != nil {
			if shouldLog() {
				log.Printf("[OpenAssets] 生成压缩图失败: %v，返回原图", err)
			}
			c.Header("Content-Type", "image/"+strings.TrimPrefix(ext, "."))
			c.File(originalPath)
			return
		}
	}

	cfExt := filepath.Ext(compressedPath)
	c.Header("Content-Type", "image/"+strings.TrimPrefix(cfExt, "."))
	c.Header("Content-Disposition", fmt.Sprintf("inline; filename=%q", realFilename))
	c.File(compressedPath)
}

// DeleteHandler 是删除文件的 Gin 处理程序。
func (s *Service) DeleteHandler(c *gin.Context) {
	bucket := c.Param("bucket")
	filename := c.Param("filename")
	username := c.MustGet("username").(string)
	if !isSafeBucketName(bucket) || !isSafeFileName(filename) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request path"})
		return
	}

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
	if !isSafeBucketName(bucket) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid bucket"})
		return
	}

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
	if !isSafeBucketName(bucket) || !isSafeFileName(filename) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request path"})
		return
	}

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
