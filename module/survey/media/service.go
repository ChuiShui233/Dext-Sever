package media

import (
	"Dext-Server/model"
	"Dext-Server/module/assets"
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	_ "golang.org/x/image/webp"

	"github.com/disintegration/imaging"
	"github.com/google/uuid"
)

type Service interface {
	// 问卷媒体文件相关
	UploadSurveyMedia(surveyID, username, originalFilename, contentType string, fileSize int64, file io.Reader, openAssetsService *assets.Service) (*MediaUploadResult, error)
	DeleteSurveyMedia(surveyID, fileID, username string, openAssetsService *assets.Service) (string, error)
	GetSurveyMediaFiles(surveyID, username string) ([]model.SurveyMediaFile, error)

	// 问卷背景相关
	UpdateSurveyBackground(surveyID int, desktopBg, mobileBg, username string) error
	GetSurveyBackground(surveyID int) (*BackgroundInfo, error)

	// 用户图像相关
	UploadImage(username, originalFilename, contentType string, fileSize int64, file io.Reader, openAssetsService *assets.Service) (*ImageUploadResult, error)
	DeleteImage(imageID, username string, openAssetsService *assets.Service) (string, error)
	BatchUploadImages(username string, files []FileUploadInfo, openAssetsService *assets.Service) ([]BatchUploadResult, int64, int, error)
	BatchDeleteImages(imageIDs []int64, username string, openAssetsService *assets.Service) ([]BatchDeleteResult, int, error)
	GetImages(username string, page, pageSize int) ([]model.ImageInfo, int, int, error)
	GetImage(imageID, username string) (*model.ImageInfo, error)
	GetUserImageStorage(username string) (*StorageInfo, error)

	// 头像相关
	UploadAvatar(username string, file io.Reader, filename string, fileSize int64) (string, error)
}

// 判断是否图片扩展名
func isImageExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp":
		return true
	}
	return false
}

// 判断是否视频扩展名
func isVideoExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".mp4", ".mov", ".avi", ".webm", ".mkv":
		return true
	}
	return false
}

// 简单判断是否有透明通道（基于格式字符串）
func hasAlpha(format string) bool {
	f := strings.ToLower(format)
	return f == "png" || f == "gif" || f == "webp"
}

// 检查系统是否存在 ffmpeg
// 获取 ffmpeg 可执行路径：优先环境变量 FFMPEG_PATH，其次 PATH，最后项目本地 ./bin 目录
func getFFmpegPath() (string, bool) {
	// 环境变量优先
	if p := os.Getenv("FFMPEG_PATH"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	// 系统 PATH
	if p, err := exec.LookPath("ffmpeg"); err == nil {
		return p, true
	}
	// 项目本地 bin 目录（Windows 可执行）
	localWin := filepath.Join("bin", "ffmpeg.exe")
	if _, err := os.Stat(localWin); err == nil {
		return localWin, true
	}
	// 项目本地 bin 目录（Unix 可执行）
	localUnix := filepath.Join("bin", "ffmpeg")
	if _, err := os.Stat(localUnix); err == nil {
		return localUnix, true
	}
	return "", false
}

// 使用 ffmpeg 将任意输入字节转码为 MP4(H.264/AAC)
func transcodeToMP4With(ffmpegPath string, input []byte) ([]byte, error) {
	// 将输入写入临时文件
	inFile, err := ioutil.TempFile("", "upload_in_*.bin")
	if err != nil {
		return nil, err
	}
	defer os.Remove(inFile.Name())
	if _, err := inFile.Write(input); err != nil {
		inFile.Close()
		return nil, err
	}
	inFile.Close()

	outFile, err := ioutil.TempFile("", "upload_out_*.mp4")
	if err != nil {
		return nil, err
	}
	outPath := outFile.Name()
	outFile.Close()
	defer os.Remove(outPath)

	// 统一滤镜：hqdn3d 降噪 -> 720p -> 24fps
	filters := "hqdn3d=2:1:2:1,scale=720:-2,fps=24"

	// 可选：双通道（2-pass）x265 800k，仅当启用环境变量 ENABLE_X265=1 时才尝试
	if os.Getenv("ENABLE_X265") == "1" {
		passLogBase := filepath.Join(os.TempDir(), fmt.Sprintf("ffmpeg2pass_%s", uuid.NewString()))
		nullSink := "/dev/null"
		if runtime.GOOS == "windows" {
			nullSink = "NUL"
		}

		// Pass 1
		cmd1 := exec.Command(
			ffmpegPath,
			"-y",
			"-i", inFile.Name(),
			"-vf", filters,
			"-c:v", "libx265",
			"-b:v", "800k",
			"-pass", "1",
			"-passlogfile", passLogBase,
			"-an",
			"-f", "null", nullSink,
		)
		var stderr1 bytes.Buffer
		cmd1.Stderr = &stderr1
		if err := cmd1.Run(); err == nil {
			// Pass 2
			cmd2 := exec.Command(
				ffmpegPath,
				"-y",
				"-i", inFile.Name(),
				"-vf", filters,
				"-c:v", "libx265",
				"-b:v", "800k",
				"-pass", "2",
				"-passlogfile", passLogBase,
				"-c:a", "aac",
				"-b:a", "64k",
				"-movflags", "+faststart",
				outPath,
			)
			var stderr2 bytes.Buffer
			cmd2.Stderr = &stderr2
			if err := cmd2.Run(); err == nil {
				// 清理pass日志
				_ = os.Remove(passLogBase + ".log")
				_ = os.Remove(passLogBase + ".log.mbtree")
				// 读取输出
				outBytes, readErr := os.ReadFile(outPath)
				if readErr == nil {
					return outBytes, nil
				}
			}
		}
		// 若 x265 路径失败，继续走 x264 回退
		log.Printf("[Media] x265 未采用（失败或禁用），回退到 x264")
	} else {
		log.Printf("[Media] 已禁用 x265（ENABLE_X265!=1），统一使用 x264 以确保浏览器可播")
	}

	// Fallback：单通道 x264（veryslow / crf 30 / tune film）带相同滤镜
	cmd := exec.Command(
		ffmpegPath,
		"-y",
		"-i", inFile.Name(),
		"-c:v", "libx264",
		"-preset", "veryslow",
		"-crf", "30",
		"-tune", "film",
		"-vf", filters,
		"-c:a", "aac",
		"-b:a", "64k",
		"-movflags", "+faststart",
		outPath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffmpeg执行失败: %v, %s", err, stderr.String())
	}

	// 读取输出
	outBytes, err := os.ReadFile(outPath)
	if err != nil {
		return nil, err
	}
	return outBytes, nil
}

type service struct {
	repo Repository
}

func NewService(repo Repository) Service {
	return &service{repo: repo}
}

// ===== 数据结构 =====

type MediaUploadResult struct {
	URL      string
	Filename string
	Size     int64
	Type     string
	RecordID int64
}

type ImageUploadResult struct {
	ID          int64
	ImageName   string
	ImageURL    string
	ImageSize   int64
	ContentType string
	UploadTime  string
	Owner       string
}

type BackgroundInfo struct {
	DesktopBackground string
	MobileBackground  string
}

type StorageInfo struct {
	Username      string
	UsedSize      int64
	ImageCount    int64
	MaxSize       int64
	RemainingSize int64
	UsagePercent  float64
}

type FileUploadInfo struct {
	Filename string
	Size     int64
	Reader   io.Reader
}

type BatchUploadResult struct {
	FileName    string
	Success     bool
	Error       string
	ImageName   string
	ImageURL    string
	ImageSize   int64
	ContentType string
	RecordID    int64
}

type BatchDeleteResult struct {
	ImageID   int64
	Success   bool
	Error     string
	ImageName string
}

// ===== 问卷媒体文件相关 =====

func (s *service) UploadSurveyMedia(surveyID, username, originalFilename, contentType string, fileSize int64, file io.Reader, openAssetsService *assets.Service) (*MediaUploadResult, error) {
	// 检查权限
	owned, err := s.repo.CheckSurveyOwnership(surveyID, username)
	if err != nil || !owned {
		return nil, errors.New("无权上传文件到此问卷")
	}

	// 读取上传内容到内存以便处理（图片压缩/视频转码）。如需避免内存占用，可落盘到临时文件再处理。
	rawBytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("读取上传内容失败: %w", err)
	}

	// 推断扩展名（以原始文件名为主）
	fileExt := strings.ToLower(filepath.Ext(originalFilename))
	if fileExt == "" {
		// 尝试从 contentType 反推
		if exts, _ := mime.ExtensionsByType(contentType); len(exts) > 0 {
			fileExt = exts[0]
		}
	}
	processed := rawBytes
	outExt := fileExt
	outContentType := contentType

	log.Printf("[Media] 接收上传: name=%s ext=%s type=%s size=%d", originalFilename, fileExt, contentType, len(rawBytes))

	// 图片自动压缩：最大边1920。
	if isImageExt(fileExt) {
		if imgObj, format, err := image.Decode(bytes.NewReader(rawBytes)); err == nil {
			// 缩放
			maxSide := 1920
			w := imgObj.Bounds().Dx()
			h := imgObj.Bounds().Dy()
			if w > maxSide || h > maxSide {
				if w >= h {
					imgObj = imaging.Resize(imgObj, maxSide, 0, imaging.Lanczos)
				} else {
					imgObj = imaging.Resize(imgObj, 0, maxSide, imaging.Lanczos)
				}
			}
			// 透明图：保持 PNG，避免丢失透明；非透明：导出 JPEG 85
			if hasAlpha(format) {
				buf := &bytes.Buffer{}
				if err := png.Encode(buf, imgObj); err == nil {
					candidate := buf.Bytes()
					// 若缩放后 PNG 更小则采用；否则保留原始
					if len(candidate) < len(rawBytes) {
						processed = candidate
						outExt = ".png"
						outContentType = "image/png"
						log.Printf("[Media] 图片处理(透明PNG): 原始=%dB -> 输出(PNG)= %dB, 应用压缩", len(rawBytes), len(processed))
					} else {
						processed = rawBytes
						outExt = fileExt
						outContentType = contentType
						log.Printf("[Media] 图片处理(透明PNG): 缩放后不更小 原始=%dB, 候选=%dB, 保留原始", len(rawBytes), len(candidate))
					}
				} else {
					log.Printf("PNG编码失败，使用原始文件: %v", err)
				}
			} else {
				buf := &bytes.Buffer{}
				if err := jpeg.Encode(buf, imgObj, &jpeg.Options{Quality: 85}); err == nil {
					candidate := buf.Bytes()
					if len(candidate) < len(rawBytes) {
						processed = candidate
						outExt = ".jpg"
						outContentType = "image/jpeg"
						log.Printf("[Media] 图片处理(JPEG): 原始=%dB -> 输出(JPEG)= %dB, 应用压缩", len(rawBytes), len(processed))
					} else {
						processed = rawBytes
						outExt = fileExt
						outContentType = contentType
						log.Printf("[Media] 图片处理(JPEG): 压缩后更大 原始=%dB, 候选=%dB, 保留原始", len(rawBytes), len(candidate))
					}
				} else {
					log.Printf("JPEG编码失败，使用原始文件: %v", err)
				}
			}
		} else {
			log.Printf("图片解码失败，使用原始文件: %v", err)
		}
	}

	// 视频可选转码：若系统存在 ffmpeg，则转为 MP4(H.264/AAC)
	if isVideoExt(fileExt) {
		if ffmpegPath, ok := getFFmpegPath(); ok {
			log.Printf("[Media] 检测到 ffmpeg: %s，开始视频转码...", ffmpegPath)
			before := len(processed)
			out, err := transcodeToMP4With(ffmpegPath, processed)
			if err != nil {
				log.Printf("视频转码失败，使用原始文件: %v", err)
			} else {
				if len(out) < before {
					processed = out
					outExt = ".mp4"
					outContentType = "video/mp4"
					log.Printf("[Media] 视频转码采用: 原始=%dB -> 输出=%dB (更小)", before, len(processed))
				} else {
					log.Printf("[Media] 视频转码舍弃: 原始=%dB, 转码=%dB (不更小)，保留原始", before, len(out))
				}
			}
		} else {
			log.Printf("未检测到ffmpeg，跳过视频转码")
		}
	}

	// 生成输出文件名（基于处理后的扩展名）
	fileName := fmt.Sprintf("%s%s", generateUUID(), outExt)

	// 上传到存储服务（使用处理后字节）
	metadata, err := openAssetsService.UploadFile("survey-assets", fileName, originalFilename, outContentType, username, int64(len(processed)), bytes.NewReader(processed))
	if err != nil {
		return nil, fmt.Errorf("文件上传到存储服务失败: %w", err)
	}

	// 保存文件记录
	fileRecordID, err := s.repo.SaveFileRecord(surveyID, username, metadata.FileName, metadata.URL, metadata.FileSize, metadata.ContentType)
	if err != nil {
		// 回滚：删除已上传的文件
		_ = openAssetsService.DeleteFile(metadata.Bucket, metadata.FileName, username)
		return nil, fmt.Errorf("保存文件记录失败: %w", err)
	}

	return &MediaUploadResult{
		URL:      metadata.URL,
		Filename: metadata.FileName,
		Size:     metadata.FileSize,
		Type:     metadata.ContentType,
		RecordID: fileRecordID,
	}, nil
}

func (s *service) DeleteSurveyMedia(surveyID, fileID, username string, openAssetsService *assets.Service) (string, error) {
	// 查询文件信息
	fileName, err := s.repo.GetFileInfo(fileID, surveyID, username)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.New("文件不存在或无权限删除")
		}
		return "", fmt.Errorf("查询文件信息失败: %w", err)
	}

	// 从存储服务删除
	err = openAssetsService.DeleteFile("survey-assets", fileName, username)
	if err != nil {
		log.Printf("从OpenAssets删除文件失败 (可能文件已不存在): %v", err)
	}

	// 删除数据库记录
	err = s.repo.DeleteFileRecord(fileID, surveyID)
	if err != nil {
		return "", fmt.Errorf("删除文件记录失败: %w", err)
	}

	return fileName, nil
}

func (s *service) GetSurveyMediaFiles(surveyID, username string) ([]model.SurveyMediaFile, error) {
	// 检查权限
	owned, err := s.repo.CheckSurveyOwnership(surveyID, username)
	if err != nil || !owned {
		return nil, errors.New("无权访问此问卷的文件")
	}

	// 查询文件列表
	files, err := s.repo.ListSurveyMediaFiles(surveyID)
	if err != nil {
		return nil, fmt.Errorf("获取文件列表失败: %w", err)
	}

	// 过滤不存在的文件
	var validFiles []model.SurveyMediaFile
	var deletedIDs []int64

	for _, file := range files {
		if !isMediaFileExists(file.FileURL) {
			log.Printf("媒体文件不存在，已标记删除: %s (ID: %d)", file.FileURL, file.ID)
			deletedIDs = append(deletedIDs, file.ID)
			continue
		}
		validFiles = append(validFiles, file)
	}

	// 删除不存在的文件记录
	for _, id := range deletedIDs {
		if err := s.repo.DeleteFileRecordByID(id); err != nil {
			log.Printf("删除媒体文件记录失败 (ID: %d): %v", id, err)
		}
	}

	return validFiles, nil
}

// ===== 问卷背景相关 =====

func (s *service) UpdateSurveyBackground(surveyID int, desktopBg, mobileBg, username string) error {
	// 检查权限
	owned, err := s.repo.CheckSurveyOwnership(fmt.Sprintf("%d", surveyID), username)
	if err != nil {
		return fmt.Errorf("验证问卷所有权失败: %w", err)
	}
	if !owned {
		return errors.New("无权修改此问卷的背景")
	}

	now := time.Now().Format("2006-01-02 15:04:05")

	// 查询是否存在背景记录
	backgroundID, err := s.repo.GetBackgroundID(surveyID)
	if err == sql.ErrNoRows {
		// 插入新记录
		return s.repo.InsertBackground(surveyID, desktopBg, mobileBg, username, now)
	} else if err != nil {
		return fmt.Errorf("查询背景记录失败: %w", err)
	}

	// 更新现有记录
	if err := s.repo.UpdateBackground(backgroundID, desktopBg, mobileBg, now); err != nil {
		return fmt.Errorf("更新背景记录失败: %w", err)
	}

	// 更新问卷时间
	if err := s.repo.UpdateSurveyTime(surveyID, now); err != nil {
		log.Printf("更新问卷时间失败: %v", err)
	}

	return nil
}

func (s *service) GetSurveyBackground(surveyID int) (*BackgroundInfo, error) {
	desktopBg, mobileBg, err := s.repo.GetBackground(surveyID)
	if err == sql.ErrNoRows {
		return &BackgroundInfo{
			DesktopBackground: "",
			MobileBackground:  "",
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("获取背景记录失败: %w", err)
	}

	return &BackgroundInfo{
		DesktopBackground: desktopBg,
		MobileBackground:  mobileBg,
	}, nil
}

// ===== 用户图像相关 =====

func (s *service) UploadImage(username, originalFilename, contentType string, fileSize int64, file io.Reader, openAssetsService *assets.Service) (*ImageUploadResult, error) {
	// 生成文件名
	imageExt := strings.ToLower(filepath.Ext(originalFilename))
	imageName := fmt.Sprintf("%s%s", generateUUID(), imageExt)

	// 上传到存储服务
	metadata, err := openAssetsService.UploadFile("images", imageName, originalFilename, contentType, username, fileSize, file)
	if err != nil {
		return nil, fmt.Errorf("图像上传到存储服务失败: %w", err)
	}

	// 保存图像记录
	imageRecordID, err := s.repo.SaveImageRecord(username, metadata.FileName, metadata.URL, metadata.FileSize, metadata.ContentType)
	if err != nil {
		// 回滚：删除已上传的图像
		_ = openAssetsService.DeleteFile(metadata.Bucket, metadata.FileName, username)
		return nil, fmt.Errorf("保存图像记录失败: %w", err)
	}

	return &ImageUploadResult{
		ID:          imageRecordID,
		ImageName:   metadata.FileName,
		ImageURL:    metadata.URL,
		ImageSize:   metadata.FileSize,
		ContentType: metadata.ContentType,
		UploadTime:  metadata.UploadTime.Format("2006-01-02 15:04:05"),
		Owner:       username,
	}, nil
}

func (s *service) DeleteImage(imageID, username string, openAssetsService *assets.Service) (string, error) {
	// 查询图像信息
	imageName, err := s.repo.GetImageInfo(imageID, username)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", errors.New("图像不存在或无权限删除")
		}
		return "", fmt.Errorf("查询图像信息失败: %w", err)
	}

	// 从存储服务删除
	err = openAssetsService.DeleteFile("images", imageName, username)
	if err != nil {
		log.Printf("从OpenAssets删除图像失败: %v", err)
	}

	// 删除数据库记录
	err = s.repo.DeleteImageRecord(imageID, username)
	if err != nil {
		return "", fmt.Errorf("删除图像记录失败: %w", err)
	}

	return imageName, nil
}

func (s *service) BatchUploadImages(username string, files []FileUploadInfo, openAssetsService *assets.Service) ([]BatchUploadResult, int64, int, error) {
	var results []BatchUploadResult
	var totalSize int64
	var successCount int

	for _, fileInfo := range files {
		result := s.uploadSingleImage(username, fileInfo, openAssetsService)
		results = append(results, result)

		if result.Success {
			totalSize += result.ImageSize
			successCount++
		}
	}

	return results, totalSize, successCount, nil
}

func (s *service) uploadSingleImage(username string, fileInfo FileUploadInfo, openAssetsService *assets.Service) BatchUploadResult {
	// 检查文件大小
	if fileInfo.Size > 50*1024*1024 {
		return BatchUploadResult{
			FileName: fileInfo.Filename,
			Success:  false,
			Error:    "图像文件大小不能超过50MB",
		}
	}

	// 检查文件类型
	contentType := getContentTypeByExtension(fileInfo.Filename)
	if !openAssetsService.Config().AllowedTypes[contentType] {
		return BatchUploadResult{
			FileName: fileInfo.Filename,
			Success:  false,
			Error:    "不支持的图像文件类型: " + contentType,
		}
	}

	// 生成文件名
	imageExt := strings.ToLower(filepath.Ext(fileInfo.Filename))
	imageName := fmt.Sprintf("%s%s", generateUUID(), imageExt)

	// 上传到存储服务
	metadata, err := openAssetsService.UploadFile("images", imageName, fileInfo.Filename, contentType, username, fileInfo.Size, fileInfo.Reader)
	if err != nil {
		return BatchUploadResult{
			FileName: fileInfo.Filename,
			Success:  false,
			Error:    "上传到存储服务失败: " + err.Error(),
		}
	}

	// 保存图像记录
	imageRecordID, err := s.repo.SaveImageRecord(username, imageName, metadata.URL, fileInfo.Size, contentType)
	if err != nil {
		_ = openAssetsService.DeleteFile("images", imageName, username)
		return BatchUploadResult{
			FileName: fileInfo.Filename,
			Success:  false,
			Error:    "保存图像记录失败",
		}
	}

	return BatchUploadResult{
		FileName:    fileInfo.Filename,
		Success:     true,
		ImageName:   imageName,
		ImageURL:    metadata.URL,
		ImageSize:   fileInfo.Size,
		ContentType: contentType,
		RecordID:    imageRecordID,
	}
}

func (s *service) BatchDeleteImages(imageIDs []int64, username string, openAssetsService *assets.Service) ([]BatchDeleteResult, int, error) {
	var results []BatchDeleteResult
	var successCount int

	// 批量获取图像名称
	imageNames, err := s.repo.BatchGetImageNames(imageIDs, username)
	if err != nil {
		return nil, 0, fmt.Errorf("查询图像信息失败: %w", err)
	}

	for _, imageID := range imageIDs {
		imageName, exists := imageNames[imageID]
		if !exists {
			results = append(results, BatchDeleteResult{
				ImageID: imageID,
				Success: false,
				Error:   "图像不存在或无权限删除",
			})
			continue
		}

		// 从存储服务删除
		if err := openAssetsService.DeleteFile("images", imageName, username); err != nil {
			log.Printf("从OpenAssets删除图像失败: %v", err)
		}

		// 删除数据库记录
		if err := s.repo.DeleteImageRecord(fmt.Sprintf("%d", imageID), username); err != nil {
			results = append(results, BatchDeleteResult{
				ImageID: imageID,
				Success: false,
				Error:   "删除图像记录失败",
			})
			continue
		}

		successCount++
		results = append(results, BatchDeleteResult{
			ImageID:   imageID,
			Success:   true,
			ImageName: imageName,
		})
	}

	return results, successCount, nil
}

func (s *service) GetImages(username string, page, pageSize int) ([]model.ImageInfo, int, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	// 查询总数
	total, err := s.repo.CountImages(username, offset, pageSize)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("查询图像总数失败: %w", err)
	}

	// 查询列表
	images, err := s.repo.ListImages(username, offset, pageSize)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("查询图像列表失败: %w", err)
	}

	totalPages := (total + pageSize - 1) / pageSize
	return images, total, totalPages, nil
}

func (s *service) GetImage(imageID, username string) (*model.ImageInfo, error) {
	image, err := s.repo.GetImageDetail(imageID, username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("图像不存在或无权限访问")
		}
		return nil, fmt.Errorf("查询图像信息失败: %w", err)
	}
	return image, nil
}

func (s *service) GetUserImageStorage(username string) (*StorageInfo, error) {
	totalSize, totalCount, err := s.repo.GetUserImageStorage(username)
	if err != nil {
		return nil, fmt.Errorf("查询存储信息失败: %w", err)
	}

	maxStorage := int64(1024 * 1024 * 1024) // 1GB
	remainingSize := maxStorage - totalSize
	if remainingSize < 0 {
		remainingSize = 0
	}
	usagePercent := float64(totalSize) / float64(maxStorage) * 100

	return &StorageInfo{
		Username:      username,
		UsedSize:      totalSize,
		ImageCount:    totalCount,
		MaxSize:       maxStorage,
		RemainingSize: remainingSize,
		UsagePercent:  usagePercent,
	}, nil
}

// ===== 头像相关 =====

func (s *service) UploadAvatar(username string, file io.Reader, filename string, fileSize int64) (string, error) {
	// 验证文件大小
	if fileSize > 5*1024*1024 {
		return "", errors.New("头像文件大小不能超过5MB")
	}

	// 验证文件类型
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".jpg" && ext != ".jpeg" && ext != ".png" && ext != ".webp" {
		return "", errors.New("仅支持JPG, PNG, WEBP格式的头像")
	}

	// 生成文件名
	fileName := fmt.Sprintf("avatars/%s%s", generateUUID(), ext)
	filePath := filepath.Join("./uploads", fileName)

	// 创建目录
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return "", fmt.Errorf("创建头像目录失败: %w", err)
	}

	// 保存文件
	out, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("创建头像文件失败: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		return "", fmt.Errorf("保存头像文件失败: %w", err)
	}

	// 更新数据库
	avatarURL := fmt.Sprintf("/uploads/%s", fileName)
	if err := s.repo.UpdateAvatar(username, avatarURL); err != nil {
		return "", fmt.Errorf("更新头像URL失败: %w", err)
	}

	return avatarURL, nil
}

// ===== 工具函数 =====

func isMediaFileExists(url string) bool {
	if url == "" {
		return false
	}

	// 从URL中提取文件路径
	if !strings.HasPrefix(url, "/openassets/files/") {
		return true // 不是本地文件，假定存在
	}

	// 移除前缀获取相对路径
	relPath := strings.TrimPrefix(url, "/openassets/files/")

	// 构建完整路径
	fullPath := filepath.Join("assets_storage", relPath)

	// 检查文件是否存在
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return false
	}

	return true
}

func generateUUID() string {
	return uuid.NewString()
}

func getContentTypeByExtension(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	contentTypes := map[string]string{
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".gif":  "image/gif",
		".webp": "image/webp",
		".mp4":  "video/mp4",
		".mp3":  "audio/mpeg",
		".wav":  "audio/wav",
		".pdf":  "application/pdf",
	}

	if contentType, ok := contentTypes[ext]; ok {
		return contentType
	}
	return "application/octet-stream"
}
