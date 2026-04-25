package clean

import (
	"Dext-Server/env"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func shouldCleanLog() bool {
	return env.ShouldLog()
}

// Cleaner 清理器 - 自动删除模式
type Cleaner struct {
	db *sql.DB
}

// RunFullCleanup 执行完整清理（兼容旧接口）
func (c *Cleaner) RunFullCleanup() error {
	return c.CleanUnusedFiles()
}

// GetFileBindings 获取文件绑定关系（兼容旧接口）
func (c *Cleaner) GetFileBindings(fileName string) (map[string]interface{}, error) {
	// 查询文件被哪些表绑定
	bindingTables := []string{}

	// 检查survey_backgrounds表
	var backgroundCount int
	err := c.db.QueryRow(`
		SELECT COUNT(*) FROM survey_backgrounds 
		WHERE desktop_background LIKE ? OR mobile_background LIKE ?
	`, "%"+fileName+"%", "%"+fileName+"%").Scan(&backgroundCount)
	if err != nil {
		return nil, fmt.Errorf("查询survey_backgrounds绑定关系失败: %w", err)
	}

	if backgroundCount > 0 {
		bindingTables = append(bindingTables, "survey_backgrounds")
	}

	// 检查question_options表
	var optionCount int
	err = c.db.QueryRow(`
		SELECT COUNT(*) FROM question_options 
		WHERE media_url LIKE ?
	`, "%"+fileName+"%").Scan(&optionCount)
	if err != nil {
		return nil, fmt.Errorf("查询question_options绑定关系失败: %w", err)
	}

	if optionCount > 0 {
		bindingTables = append(bindingTables, "question_options")
	}

	// 检查questions表
	var questionCount int
	err = c.db.QueryRow(`
		SELECT COUNT(*) FROM questions 
		WHERE media_urls LIKE ?
	`, "%"+fileName+"%").Scan(&questionCount)
	if err != nil {
		return nil, fmt.Errorf("查询questions绑定关系失败: %w", err)
	}

	if questionCount > 0 {
		bindingTables = append(bindingTables, "questions")
	}

	result := map[string]interface{}{
		"fileName":      fileName,
		"bindingTables": bindingTables,
		"totalBindings": len(bindingTables),
	}

	return result, nil
}

// NewCleaner 创建新的清理器
func NewCleaner(db *sql.DB) *Cleaner {
	return &Cleaner{
		db: db,
	}
}

// isVerboseLogging 判断是否启用详细日志
func (c *Cleaner) isVerboseLogging() bool {
	return shouldCleanLog()
}

// CleanUnusedFiles 清理未使用的文件 - 自动删除模式
func (c *Cleaner) CleanUnusedFiles() error {
	if c.isVerboseLogging() {
		log.Printf("[Cleaner] 开始自动清理未使用的文件")
	}
	startTime := time.Now()

	compressedDB, err := c.getCompressedFilesFromDB()
	if err != nil {
		if c.isVerboseLogging() {
			log.Printf("[Cleaner] 警告: 获取压缩图索引失败: %v，将使用文件名规则", err)
		}
		compressedDB = nil
	} else {
		if c.isVerboseLogging() {
			log.Printf("[Cleaner] 加载 %d 个压缩图索引", len(compressedDB))
		}
	}

	// 获取存储目录中的所有文件
	storageFiles, err := c.getStorageFiles()
	if err != nil {
		return fmt.Errorf("获取存储文件列表失败: %w", err)
	}

	if c.isVerboseLogging() {
		log.Printf("[Cleaner] 存储目录中有 %d 个文件", len(storageFiles))
	}

	// 找出未使用的文件
	unusedFiles, err := c.findUnusedFiles(storageFiles, compressedDB)
	if err != nil {
		return fmt.Errorf("查找未使用文件失败: %w", err)
	}

	if c.isVerboseLogging() {
		log.Printf("[Cleaner] 发现 %d 个未使用的文件", len(unusedFiles))
	}

	// 分离普通文件和压缩图像
	regularFiles, compressedImages := c.separateFileTypes(unusedFiles, compressedDB)

	// 先删除普通文件
	regularDeleted, err := c.deleteFiles(regularFiles, compressedDB)
	if err != nil {
		return fmt.Errorf("删除普通文件失败: %w", err)
	}

	// 最后处理压缩图像
	compressedDeleted, err := c.processCompressedImages(compressedImages, compressedDB)
	if err != nil {
		return fmt.Errorf("处理压缩图像失败: %w", err)
	}

	totalDeleted := regularDeleted + compressedDeleted
	duration := time.Since(startTime)

	if c.isVerboseLogging() {
		log.Printf("[Cleaner] 清理完成: 删除 %d 个文件 (普通文件: %d, 压缩图像: %d), 耗时: %v",
			totalDeleted, regularDeleted, compressedDeleted, duration)
	}

	return nil
}

// separateFileTypes 分离普通文件和压缩图像
func (c *Cleaner) separateFileTypes(files []string, compressedDB map[string]*compressedFileInfo) ([]string, []string) {
	var regularFiles []string
	var compressedImages []string

	for _, filePath := range files {
		fileName := filepath.Base(filePath)
		if c.isCompressedImage(fileName, compressedDB) {
			compressedImages = append(compressedImages, filePath)
		} else {
			regularFiles = append(regularFiles, filePath)
		}
	}

	if c.isVerboseLogging() {
		log.Printf("[Cleaner] 文件分类: 普通文件 %d 个, 压缩图像 %d 个",
			len(regularFiles), len(compressedImages))
	}

	return regularFiles, compressedImages
}

// findUnusedFiles 找出未使用的文件
func (c *Cleaner) findUnusedFiles(storageFiles []string, compressedDB map[string]*compressedFileInfo) ([]string, error) {
	// 获取被数据库绑定的文件
	boundedFiles, err := c.getBoundedFiles()
	if err != nil {
		return nil, fmt.Errorf("获取绑定文件列表失败: %w", err)
	}

	var unusedFiles []string
	var usedFiles []string

	for _, filePath := range storageFiles {
		fileName := filepath.Base(filePath)

		// 只检查文件是否被其他表绑定，不检查survey_assets_files表
		isBounded := boundedFiles[fileName]

		// 如果是压缩图像，通过DB索引检查原始图像是否被绑定
		if c.isCompressedImage(fileName, compressedDB) {
			originalFileName := c.getOriginalImageFileName(fileName, compressedDB)
			if originalFileName != "" && boundedFiles[originalFileName] {
				isBounded = true
				if c.isVerboseLogging() {
					log.Printf("[Cleaner] 压缩图像 %s 的原始图像 %s 被绑定，保留压缩图像",
						fileName, originalFileName)
				}
			}
		}

		// 如果文件没有被其他表绑定，则认为是未使用文件
		if !isBounded {
			unusedFiles = append(unusedFiles, filePath)
			if c.isVerboseLogging() {
				log.Printf("[Cleaner] 发现未使用文件: %s (绑定状态: %t)",
					fileName, isBounded)
			}
		} else {
			usedFiles = append(usedFiles, fileName)
			if c.isVerboseLogging() {
				log.Printf("[Cleaner] 文件被使用: %s (绑定状态: %t)",
					fileName, isBounded)
			}
		}
	}

	if c.isVerboseLogging() {
		log.Printf("[Cleaner] 文件使用统计: 总文件数 %d, 未使用文件 %d, 已使用文件 %d",
			len(storageFiles), len(unusedFiles), len(usedFiles))
	}

	return unusedFiles, nil
}

// processCompressedImages 处理压缩图像
func (c *Cleaner) processCompressedImages(compressedImages []string, compressedDB map[string]*compressedFileInfo) (int, error) {
	if len(compressedImages) == 0 {
		return 0, nil
	}

	if c.isVerboseLogging() {
		log.Printf("[Cleaner] 开始处理 %d 个压缩图像", len(compressedImages))
	}

	boundedFiles, err := c.getBoundedFiles()
	if err != nil {
		return 0, fmt.Errorf("获取绑定文件失败: %w", err)
	}

	var filesToDelete []string

	for _, filePath := range compressedImages {
		fileName := filepath.Base(filePath)

		if !c.isCompressedImage(fileName, compressedDB) {
			continue
		}

		originalFileName := c.getOriginalImageFileName(fileName, compressedDB)
		if originalFileName == "" {
			filesToDelete = append(filesToDelete, filePath)
			continue
		}

		if !boundedFiles[originalFileName] {
			filesToDelete = append(filesToDelete, filePath)
		}
	}

	return c.deleteFiles(filesToDelete, compressedDB)
}

// isFileUsed 检查文件是否被使用
func (c *Cleaner) isFileUsed(fileName string) bool {
	// 只检查绑定关系，不检查数据库记录（与主清理逻辑保持一致）
	isBounded, _ := c.isFileBounded(fileName)
	return isBounded
}

// deleteFiles 删除文件列表和数据库记录
func (c *Cleaner) deleteFiles(files []string, compressedDB map[string]*compressedFileInfo) (int, error) {
	if len(files) == 0 {
		return 0, nil
	}

	if c.isVerboseLogging() {
		log.Printf("[Cleaner] 准备删除 %d 个文件及其数据库记录", len(files))
	}

	// 先删除数据库记录
	dbDeleted, err := c.deleteDatabaseRecords(files, compressedDB)
	if err != nil {
		if c.isVerboseLogging() {
			log.Printf("[Cleaner] 警告: 删除数据库记录失败: %v", err)
		}
	}

	// 再删除文件
	fileDeleted, err := c.deletePhysicalFiles(files)
	if err != nil {
		return fileDeleted, err
	}

	if c.isVerboseLogging() {
		log.Printf("[Cleaner] 删除完成: 文件 %d 个, 数据库记录 %d 个", fileDeleted, dbDeleted)
	}
	return fileDeleted, nil
}

// deleteDatabaseRecords 删除数据库记录
func (c *Cleaner) deleteDatabaseRecords(files []string, compressedDB map[string]*compressedFileInfo) (int, error) {
	if len(files) == 0 {
		return 0, nil
	}

	// 提取文件名列表
	fileNames := make([]string, 0, len(files))
	for _, filePath := range files {
		fileName := filepath.Base(filePath)
		fileNames = append(fileNames, fileName)
	}

	// 批量删除数据库记录
	const batchSize = 100
	deletedCount := 0

	for i := 0; i < len(fileNames); i += batchSize {
		end := i + batchSize
		if end > len(fileNames) {
			end = len(fileNames)
		}

		batch := fileNames[i:end]
		placeholders := make([]string, 0, len(batch))
		args := make([]interface{}, 0, len(batch))

		for _, fileName := range batch {
			placeholders = append(placeholders, "?")
			args = append(args, fileName)
		}

		// 删除 survey_assets_files 记录
		query := fmt.Sprintf(`
			DELETE FROM survey_assets_files
			WHERE file_name IN (%s)
		`, strings.Join(placeholders, ","))

		result, err := c.db.Exec(query, args...)
		if err != nil {
			return deletedCount, fmt.Errorf("批量删除数据库记录失败: %w", err)
		}

		rowsAffected, _ := result.RowsAffected()
		deletedCount += int(rowsAffected)

		// 删除 assets_compressed_files 记录（如果compressedDB存在）
		if compressedDB != nil {
			cfPlaceholders := make([]string, 0, len(batch))
			cfArgs := make([]interface{}, 0, len(batch))
			for _, fileName := range batch {
				if c.isCompressedImage(fileName, compressedDB) {
					cfPlaceholders = append(cfPlaceholders, "?")
					cfArgs = append(cfArgs, fileName)
				}
			}
			if len(cfPlaceholders) > 0 {
				cfQuery := fmt.Sprintf(`
					DELETE FROM assets_compressed_files
					WHERE compressed_filename IN (%s)
				`, strings.Join(cfPlaceholders, ","))
				cfResult, err := c.db.Exec(cfQuery, cfArgs...)
				if err != nil {
					if c.isVerboseLogging() {
						log.Printf("[Cleaner] 警告: 删除压缩图记录失败: %v", err)
					}
				} else {
					cfRowsAffected, _ := cfResult.RowsAffected()
					deletedCount += int(cfRowsAffected)
				}
			}
		}
	}

	if c.isVerboseLogging() {
		log.Printf("[Cleaner] 删除数据库记录: %d 条", deletedCount)
	}
	return deletedCount, nil
}

// deletePhysicalFiles 删除物理文件
func (c *Cleaner) deletePhysicalFiles(files []string) (int, error) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	deletedCount := 0

	// 限制并发数，避免文件系统压力过大
	maxWorkers := 5
	fileChan := make(chan string, len(files))

	// 启动worker goroutines
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for filePath := range fileChan {
				if err := os.Remove(filePath); err != nil {
					log.Printf("[Cleaner] worker %d 删除文件失败 %s: %v",
						workerID, filePath, err)
				} else {
					mu.Lock()
					deletedCount++
					mu.Unlock()
				}
			}
		}(i)
	}

	// 发送文件到channel
	for _, filePath := range files {
		fileChan <- filePath
	}
	close(fileChan)

	// 等待所有worker完成
	wg.Wait()

	return deletedCount, nil
}

// 以下是辅助函数，保持不变

// isFileInDatabase 检查文件是否在数据库中有记录
func (c *Cleaner) isFileInDatabase(fileName string) (bool, error) {
	var exists bool
	err := c.db.QueryRow(`
		SELECT 1 FROM survey_assets_files WHERE file_name = ?
	`, fileName).Scan(&exists)

	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("查询文件存在性失败: %w", err)
	}
	return true, nil
}

// batchCheckFilesInDatabase 批量检查文件是否在数据库中有记录
func (c *Cleaner) batchCheckFilesInDatabase(fileNames []string) (map[string]bool, error) {
	if len(fileNames) == 0 {
		return make(map[string]bool), nil
	}

	placeholders := make([]string, len(fileNames))
	args := make([]interface{}, len(fileNames))
	for i, name := range fileNames {
		placeholders[i] = "?"
		args[i] = name
	}

	query := fmt.Sprintf(`
		SELECT file_name FROM survey_assets_files 
		WHERE file_name IN (%s)
	`, strings.Join(placeholders, ","))

	rows, err := c.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("批量查询文件失败: %w", err)
	}
	defer rows.Close()

	existingFiles := make(map[string]bool)
	for rows.Next() {
		var fileName string
		if err := rows.Scan(&fileName); err != nil {
			continue
		}
		existingFiles[fileName] = true
	}

	return existingFiles, nil
}

// isFileBounded 检查文件是否被绑定
func (c *Cleaner) isFileBounded(fileName string) (bool, error) {
	// 检查survey_backgrounds表
	var backgroundCount int
	err := c.db.QueryRow(`
		SELECT COUNT(*) FROM survey_backgrounds 
		WHERE desktop_background LIKE ? OR mobile_background LIKE ?
	`, "%"+fileName+"%", "%"+fileName+"%").Scan(&backgroundCount)
	if err != nil {
		return false, fmt.Errorf("检查survey_backgrounds绑定关系失败: %w", err)
	}

	if backgroundCount > 0 {
		return true, nil
	}

	// 检查question_options表
	var optionCount int
	err = c.db.QueryRow(`
		SELECT COUNT(*) FROM question_options 
		WHERE media_url LIKE ?
	`, "%"+fileName+"%").Scan(&optionCount)
	if err != nil {
		return false, fmt.Errorf("检查question_options绑定关系失败: %w", err)
	}

	if optionCount > 0 {
		return true, nil
	}

	// 检查questions表
	var questionCount int
	err = c.db.QueryRow(`
		SELECT COUNT(*) FROM questions 
		WHERE media_urls LIKE ?
	`, "%"+fileName+"%").Scan(&questionCount)
	if err != nil {
		return false, fmt.Errorf("检查questions绑定关系失败: %w", err)
	}

	return questionCount > 0, nil
}

// getBoundedFiles 获取被其他表绑定的文件
func (c *Cleaner) getBoundedFiles() (map[string]bool, error) {
	boundedFiles := make(map[string]bool)

	// 使用单个查询获取所有被绑定的文件URL
	query := `
		SELECT DISTINCT url FROM (
			-- survey_backgrounds 表的文件引用
			SELECT desktop_background AS url FROM survey_backgrounds WHERE desktop_background IS NOT NULL AND desktop_background != ''
			UNION ALL
			SELECT mobile_background AS url FROM survey_backgrounds WHERE mobile_background IS NOT NULL AND mobile_background != ''
			UNION ALL
			-- question_options 表的文件引用
			SELECT media_url AS url FROM question_options WHERE media_url IS NOT NULL AND media_url != ''
			UNION ALL
			-- questions 表的JSON格式文件引用（需要解析JSON）
			SELECT SUBSTRING_INDEX(SUBSTRING_INDEX(SUBSTRING_INDEX(media_urls, '"', n*2), '"', -1), '"', 1) AS url
			FROM questions 
			CROSS JOIN (
				SELECT 1 AS n UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5 
				UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9 UNION SELECT 10
			) numbers
			WHERE media_urls IS NOT NULL 
			AND media_urls != 'null' 
			AND media_urls != '[]'
			AND n <= (LENGTH(media_urls) - LENGTH(REPLACE(media_urls, '"', ''))) / 2
			AND SUBSTRING_INDEX(SUBSTRING_INDEX(SUBSTRING_INDEX(media_urls, '"', n*2), '"', -1), '"', 1) != ''
		) AS all_urls
		WHERE url IS NOT NULL AND url != ''
	`

	rows, err := c.db.Query(query)
	if err != nil {
		// 如果复杂查询失败，回退到原来的逐个查询方式
		if c.isVerboseLogging() {
			log.Printf("[Cleaner] 警告: 复杂查询失败，回退到逐个查询: %v", err)
		}
		return c.getBoundedFilesFallback()
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var url sql.NullString
		if err := rows.Scan(&url); err != nil {
			continue
		}

		if url.Valid && url.String != "" {
			if fileName := extractFileNameFromURL(url.String); fileName != "" {
				boundedFiles[fileName] = true
				count++
			}
		}
	}

	if c.isVerboseLogging() {
		log.Printf("[Cleaner] 发现 %d 个被绑定的文件", count)
	}
	return boundedFiles, nil
}

// getBoundedFilesFallback 回退方案：逐个查询
func (c *Cleaner) getBoundedFilesFallback() (map[string]bool, error) {
	boundedFiles := make(map[string]bool)
	if c.isVerboseLogging() {
		log.Printf("[Cleaner] 使用回退方案查询绑定文件")
	}

	// survey_backgrounds 表
	rows1, err := c.db.Query(`SELECT desktop_background, mobile_background FROM survey_backgrounds WHERE desktop_background IS NOT NULL OR mobile_background IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("查询survey_backgrounds失败: %w", err)
	}
	defer rows1.Close()

	for rows1.Next() {
		var desktopBg, mobileBg sql.NullString
		if err := rows1.Scan(&desktopBg, &mobileBg); err != nil {
			continue
		}

		if desktopBg.Valid && desktopBg.String != "" {
			if fileName := extractFileNameFromURL(desktopBg.String); fileName != "" {
				boundedFiles[fileName] = true
			}
		}

		if mobileBg.Valid && mobileBg.String != "" {
			if fileName := extractFileNameFromURL(mobileBg.String); fileName != "" {
				boundedFiles[fileName] = true
			}
		}
	}

	// question_options 表
	rows2, err := c.db.Query(`SELECT media_url FROM question_options WHERE media_url IS NOT NULL AND media_url != ''`)
	if err != nil {
		return nil, fmt.Errorf("查询question_options失败: %w", err)
	}
	defer rows2.Close()

	for rows2.Next() {
		var mediaUrl sql.NullString
		if err := rows2.Scan(&mediaUrl); err != nil {
			continue
		}

		if mediaUrl.Valid && mediaUrl.String != "" {
			if fileName := extractFileNameFromURL(mediaUrl.String); fileName != "" {
				boundedFiles[fileName] = true
			}
		}
	}

	// questions 表（JSON格式）
	rows3, err := c.db.Query(`SELECT media_urls FROM questions WHERE media_urls IS NOT NULL AND media_urls != 'null' AND media_urls != '[]'`)
	if err != nil {
		return nil, fmt.Errorf("查询questions失败: %w", err)
	}
	defer rows3.Close()

	for rows3.Next() {
		var mediaUrls sql.NullString
		if err := rows3.Scan(&mediaUrls); err != nil {
			continue
		}

		if mediaUrls.Valid && mediaUrls.String != "" && mediaUrls.String != "null" && mediaUrls.String != "[]" {
			var urls []string
			if err := json.Unmarshal([]byte(mediaUrls.String), &urls); err == nil {
				for _, url := range urls {
					if fileName := extractFileNameFromURL(url); fileName != "" {
						boundedFiles[fileName] = true
					}
				}
			}
		}
	}

	if c.isVerboseLogging() {
		log.Printf("[Cleaner] 回退方案发现 %d 个被绑定的文件", len(boundedFiles))
	}
	return boundedFiles, nil
}

// getStorageFiles 获取存储目录中的所有文件
func (c *Cleaner) getStorageFiles() ([]string, error) {
	var files []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 要扫描的目录列表
	dirsToScan := []string{
		"assets_storage/survey-assets",
		"assets_storage/images",
		"assets_storage/videos",
	}

	// 创建goroutine池（限制并发数）
	maxWorkers := 10
	dirChan := make(chan string, len(dirsToScan))

	// 启动worker goroutines
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dir := range dirChan {
				c.scanDirectory(dir, &files, &mu)
			}
		}()
	}

	// 发送目录到channel
	for _, dir := range dirsToScan {
		dirChan <- dir
	}
	close(dirChan)

	// 等待所有worker完成
	wg.Wait()

	if c.isVerboseLogging() {
		log.Printf("[Cleaner] 并发扫描完成，发现 %d 个文件", len(files))
	}
	return files, nil
}

// scanDirectory 扫描单个目录
func (c *Cleaner) scanDirectory(dir string, files *[]string, mu *sync.Mutex) {
	// 检查目录是否存在
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 跳过目录，只处理文件
		if info.IsDir() {
			return nil
		}

		// 添加文件到结果列表（需要加锁）
		mu.Lock()
		*files = append(*files, path)
		mu.Unlock()

		return nil
	})

	if err != nil {
		if c.isVerboseLogging() {
			log.Printf("[Cleaner] 警告: 扫描目录 %s 失败: %v", dir, err)
		}
	}
}

// extractFileNameFromURL 从URL中提取文件名
func extractFileNameFromURL(url string) string {
	if url == "" {
		return ""
	}

	// 移除URL参数
	urlWithoutParams := strings.Split(url, "?")[0]

	// 获取文件名
	fileName := filepath.Base(urlWithoutParams)

	// 如果文件名包含路径分隔符，再次提取
	if strings.Contains(fileName, "/") {
		fileName = filepath.Base(fileName)
	}

	// 处理Windows路径分隔符
	if strings.Contains(fileName, "\\") {
		fileName = filepath.Base(fileName)
	}

	// 移除URL编码和特殊字符
	fileName = strings.TrimSpace(fileName)

	// 如果文件名包含URL编码，尝试解码
	if strings.Contains(fileName, "%") {
		// 简单的URL解码（处理常见的编码字符）
		fileName = strings.ReplaceAll(fileName, "%20", " ")
		fileName = strings.ReplaceAll(fileName, "%2F", "/")
		fileName = strings.ReplaceAll(fileName, "%5C", "\\")
	}

	// 最终提取文件名
	fileName = filepath.Base(fileName)

	return fileName
}

type compressedFileInfo struct {
	OriginalFileName   string
	CompressedFileName string
	Quality            string
}

func (c *Cleaner) getCompressedFilesFromDB() (map[string]*compressedFileInfo, error) {
	result := make(map[string]*compressedFileInfo)

	rows, err := c.db.Query(`
		SELECT compressed_filename, original_filename, quality
		FROM assets_compressed_files
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var cf compressedFileInfo
		if err := rows.Scan(&cf.CompressedFileName, &cf.OriginalFileName, &cf.Quality); err != nil {
			continue
		}
		result[cf.CompressedFileName] = &cf
	}

	return result, nil
}

func (c *Cleaner) isCompressedImage(fileName string, compressedDB map[string]*compressedFileInfo) bool {
	if compressedDB == nil {
		return false
	}
	_, ok := compressedDB[fileName]
	return ok
}

func (c *Cleaner) getOriginalImageFileName(compressedFileName string, compressedDB map[string]*compressedFileInfo) string {
	if compressedDB == nil {
		return ""
	}
	if info, ok := compressedDB[compressedFileName]; ok {
		return info.OriginalFileName
	}
	return ""
}
