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

	// 头像相关
	UploadAvatar(username string, file io.Reader, filename string, fileSize int64, openAssetsService *assets.Service) (string, error)
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

	// 读取上传内容到内存
	rawBytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("读取上传内容失败: %w", err)
	}

	// 推断扩展名
	fileExt := strings.ToLower(filepath.Ext(originalFilename))
	if fileExt == "" {
		if exts, _ := mime.ExtensionsByType(contentType); len(exts) > 0 {
			fileExt = exts[0]
		}
	}

	log.Printf("[Media] 接收上传: name=%s ext=%s type=%s size=%d", originalFilename, fileExt, contentType, len(rawBytes))

	// 生成文件名并立即上传原图（快速返回，不阻塞客户端）
	originalFileName := fmt.Sprintf("%s%s", generateUUID(), fileExt)
	metadata, err := openAssetsService.UploadFile("survey-assets", originalFileName, originalFilename, contentType, username, int64(len(rawBytes)), bytes.NewReader(rawBytes))
	if err != nil {
		return nil, fmt.Errorf("文件上传到存储服务失败: %w", err)
	}

	// 保存文件记录
	fileRecordID, err := s.repo.SaveFileRecord(surveyID, username, metadata.FileName, metadata.URL, metadata.FileSize, metadata.ContentType)
	if err != nil {
		_ = openAssetsService.DeleteFile(metadata.Bucket, metadata.FileName, username)
		return nil, fmt.Errorf("保存文件记录失败: %w", err)
	}

	result := &MediaUploadResult{
		URL:      metadata.URL,
		Filename: metadata.FileName,
		Size:     metadata.FileSize,
		Type:     metadata.ContentType,
		RecordID: fileRecordID,
	}

	// 后台异步压缩/转码，如果处理后更小则替换原文件
	go func(raw []byte, fileName, bucket, origURL string) {
		processed := raw
		outExt := fileExt
		outContentType := contentType

		// 图片压缩：最大边1920
		if isImageExt(fileExt) {
			if imgObj, format, err := image.Decode(bytes.NewReader(raw)); err == nil {
				type resizeResult struct {
					img  image.Image
					done bool
				}
				resultCh := make(chan resizeResult, 1)
				go func(srcImg image.Image) {
					res := resizeResult{done: false}
					defer func() {
						if r := recover(); r != nil {
							log.Printf("图片缩放panic，恢复: %v", r)
							res.img = srcImg
						}
						resultCh <- res
					}()
					maxSide := 1920
					w := srcImg.Bounds().Dx()
					h := srcImg.Bounds().Dy()
					if w > maxSide || h > maxSide {
						if w >= h {
							srcImg = imaging.Resize(srcImg, maxSide, 0, imaging.Lanczos)
						} else {
							srcImg = imaging.Resize(srcImg, 0, maxSide, imaging.Lanczos)
						}
					}
					res.img = srcImg
					res.done = true
				}(imgObj)

				select {
				case res := <-resultCh:
					if res.done {
						imgObj = res.img
					} else {
						imgObj = nil
					}
				case <-time.After(60 * time.Second):
					log.Printf("图片缩放超时，保留原文件")
					imgObj = nil
				}

				if imgObj != nil {
					if hasAlpha(format) {
						buf := &bytes.Buffer{}
						if err := png.Encode(buf, imgObj); err == nil {
							candidate := buf.Bytes()
							if len(candidate) < len(raw) {
								processed = candidate
								outExt = ".png"
								outContentType = "image/png"
							}
						}
					} else {
						buf := &bytes.Buffer{}
						if err := jpeg.Encode(buf, imgObj, &jpeg.Options{Quality: 85}); err == nil {
							candidate := buf.Bytes()
							if len(candidate) < len(raw) {
								processed = candidate
								outExt = ".jpg"
								outContentType = "image/jpeg"
							}
						}
					}
				}
			}
		}

		// 视频转码：若系统存在 ffmpeg
		if isVideoExt(fileExt) {
			if ffmpegPath, ok := getFFmpegPath(); ok {
				if out, err := transcodeToMP4With(ffmpegPath, processed); err == nil && len(out) < len(processed) {
					processed = out
					outExt = ".mp4"
					outContentType = "video/mp4"
				}
			}
		}

		// 如果处理后更小，替换原文件
		if len(processed) < len(raw) {
			newFileName := fmt.Sprintf("%s%s", generateUUID(), outExt)
			if meta, err := openAssetsService.UploadFile(bucket, newFileName, originalFilename, outContentType, username, int64(len(processed)), bytes.NewReader(processed)); err == nil {
				log.Printf("[Media] 后台压缩替换: %s -> %s (%dB -> %dB)", origURL, meta.URL, len(raw), len(processed))
				_ = s.repo.UpdateFileNameAndURL(fileRecordID, newFileName, meta.URL)
			} else {
				log.Printf("[Media] 后台压缩文件上传失败: %v", err)
			}
		}
	}(rawBytes, originalFileName, "survey-assets", metadata.URL)

	return result, nil
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

// ===== 头像相关 =====

func (s *service) UploadAvatar(username string, file io.Reader, filename string, fileSize int64, openAssetsService *assets.Service) (string, error) {
	if fileSize > 5*1024*1024 {
		return "", errors.New("头像文件大小不能超过5MB")
	}

	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".jpg" && ext != ".jpeg" && ext != ".png" && ext != ".webp" {
		return "", errors.New("仅支持JPG, PNG, WEBP格式的头像")
	}

	contentType := mime.TypeByExtension(ext)
	if contentType == "" {
		switch ext {
		case ".jpg", ".jpeg":
			contentType = "image/jpeg"
		case ".png":
			contentType = "image/png"
		case ".webp":
			contentType = "image/webp"
		}
	}

	fileName := fmt.Sprintf("%s%s", generateUUID(), ext)

	if openAssetsService != nil && openAssetsService.Config().Backend == "github" {
		data, err := io.ReadAll(file)
		if err != nil {
			return "", fmt.Errorf("读取头像数据失败: %w", err)
		}
		metadata, err := openAssetsService.UploadFile("user-avatars", fileName, fileName, contentType, username, int64(len(data)), bytes.NewReader(data))
		if err != nil {
			return "", fmt.Errorf("上传头像到图床失败: %w", err)
		}
		if err := s.repo.UpdateAvatar(username, metadata.URL); err != nil {
			return "", fmt.Errorf("更新头像URL失败: %w", err)
		}
		return metadata.URL, nil
	}

	filePath := filepath.Join("./assets_storage", "user-avatars", fileName)
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return "", fmt.Errorf("创建头像目录失败: %w", err)
	}
	out, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("创建头像文件失败: %w", err)
	}
	defer out.Close()
	if _, err := io.Copy(out, file); err != nil {
		return "", fmt.Errorf("保存头像文件失败: %w", err)
	}

	avatarURL := fmt.Sprintf("/openassets/files/user-avatars/%s", stripExt(fileName))
	if err := s.repo.UpdateAvatar(username, avatarURL); err != nil {
		return "", fmt.Errorf("更新头像URL失败: %w", err)
	}
	return avatarURL, nil
}

func stripExt(name string) string {
	ext := filepath.Ext(name)
	if ext == "" {
		return name
	}
	return strings.TrimSuffix(name, ext)
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
