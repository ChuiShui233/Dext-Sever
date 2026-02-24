package media

import (
	"Dext-Server/module/assets"
	"Dext-Server/utils"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// 依赖注入：默认使用真实实现
var mediaService Service = NewService(NewMediaRepository())
var openAssetsService *assets.Service

// SetOpenAssetsService 设置OpenAssets服务实例
func SetOpenAssetsService(service *assets.Service) {
	openAssetsService = service
}

// ===== 问卷媒体文件处理器 =====

// UploadSurveyMediaHandler 上传问卷媒体文件
func UploadSurveyMediaHandler(c *gin.Context) {
	surveyID := c.Param("surveyId")
	username := c.MustGet("username").(string)

	fileHeader, err := c.FormFile("file")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "未上传文件或文件格式错误")
		return
	}

	if fileHeader.Size > 100*1024*1024 { // 100MB
		utils.SendError(c, http.StatusBadRequest, "文件大小不能超过100MB")
		return
	}

	contentType := utils.GetContentTypeByExtension(fileHeader.Filename)
	if !openAssetsService.Config().AllowedTypes[contentType] {
		utils.SendError(c, http.StatusBadRequest, "不支持的文件类型")
		return
	}

	file, err := fileHeader.Open()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "无法打开上传的文件")
		return
	}
	defer file.Close()

	result, err := mediaService.UploadSurveyMedia(surveyID, username, fileHeader.Filename, contentType, fileHeader.Size, file, openAssetsService)
	if err != nil {
		log.Printf("上传问卷媒体失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"url":       result.URL,
		"publicUrl": result.URL, // 兼容前端期望的字段名
		"filename":  result.Filename,
		"size":      result.Size,
		"type":      result.Type,
		"recordId":  result.RecordID,
	})
}

// DeleteSurveyMediaFileHandler 删除问卷媒体文件
func DeleteSurveyMediaFileHandler(c *gin.Context) {
	surveyID := c.Param("surveyId")
	fileID := c.Param("fileId")
	username := c.MustGet("username").(string)

	fileName, err := mediaService.DeleteSurveyMedia(surveyID, fileID, username, openAssetsService)
	if err != nil {
		log.Printf("删除问卷媒体失败: %v", err)
		if strings.Contains(err.Error(), "不存在") || strings.Contains(err.Error(), "无权限") {
			log.Printf("拒绝连接: %v", err)
			c.AbortWithStatus(http.StatusNotFound)
		} else {
			utils.SendError(c, http.StatusInternalServerError, err.Error())
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "文件删除成功",
		"fileName": fileName,
	})
}

// GetSurveyMediaFilesHandler 获取问卷媒体文件列表
func GetSurveyMediaFilesHandler(c *gin.Context) {
	surveyID := c.Param("surveyId")
	username := c.MustGet("username").(string)

	files, err := mediaService.GetSurveyMediaFiles(surveyID, username)
	if err != nil {
		log.Printf("获取问卷媒体列表失败: %v", err)
		if strings.Contains(err.Error(), "无权") {
			utils.SendError(c, http.StatusForbidden, err.Error())
		} else {
			utils.SendError(c, http.StatusInternalServerError, err.Error())
		}
		return
	}

	// 转换为响应格式
	var result []gin.H
	for _, file := range files {
		result = append(result, gin.H{
			"id":          file.ID,
			"fileName":    file.FileName,
			"fileUrl":     file.FileURL,
			"fileSize":    file.FileSize,
			"contentType": file.ContentType,
			"uploadTime":  file.UploadTime,
		})
	}

	c.JSON(http.StatusOK, gin.H{"files": result, "count": len(result)})
}

// ===== 问卷背景处理器 =====

// UpdateSurveyBackgroundHandler 更新问卷背景
func UpdateSurveyBackgroundHandler(c *gin.Context) {
	surveyIDStr := c.Param("surveyId")
	surveyID, err := strconv.Atoi(surveyIDStr)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的问卷ID")
		return
	}
	username := c.MustGet("username").(string)

	var req struct {
		DesktopBackground string `json:"desktopBackground"`
		MobileBackground  string `json:"mobileBackground"`
	}

	// DecryptMiddleware已经处理了解密，直接解析JSON
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的背景数据")
		return
	}

	// 验证URL安全性
	if req.DesktopBackground != "" && !utils.IsSafeURL(req.DesktopBackground) {
		utils.SendError(c, http.StatusBadRequest, "桌面背景URL不安全")
		return
	}
	if req.MobileBackground != "" && !utils.IsSafeURL(req.MobileBackground) {
		utils.SendError(c, http.StatusBadRequest, "移动背景URL不安全")
		return
	}

	// 更新背景
	err = mediaService.UpdateSurveyBackground(surveyID, req.DesktopBackground, req.MobileBackground, username)
	if err != nil {
		log.Printf("更新问卷背景失败: %v", err)
		if strings.Contains(err.Error(), "无权") {
			utils.SendError(c, http.StatusForbidden, err.Error())
		} else {
			utils.SendError(c, http.StatusInternalServerError, err.Error())
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "背景更新成功"})
}

// GetSurveyBackgroundHandler 获取问卷背景
func GetSurveyBackgroundHandler(c *gin.Context) {
	surveyIDStr := c.Param("surveyId")
	surveyID, err := strconv.Atoi(surveyIDStr)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的问卷ID")
		return
	}

	background, err := mediaService.GetSurveyBackground(surveyID)
	if err != nil {
		log.Printf("获取问卷背景失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, "获取背景信息失败")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"desktopBackground": background.DesktopBackground,
		"mobileBackground":  background.MobileBackground,
	})
}

// ===== 用户图像处理器 =====

// UploadImageHandler 上传用户图像
func UploadImageHandler(c *gin.Context) {
	username := c.MustGet("username").(string)

	fileHeader, err := c.FormFile("image")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "未上传图像文件或文件格式错误")
		return
	}

	if fileHeader.Size > 50*1024*1024 { // 50MB
		utils.SendError(c, http.StatusBadRequest, "图像文件大小不能超过50MB")
		return
	}

	contentType := utils.GetContentTypeByExtension(fileHeader.Filename)
	if !openAssetsService.Config().AllowedTypes[contentType] {
		utils.SendError(c, http.StatusBadRequest, "不支持的图像文件类型: "+fileHeader.Filename)
		return
	}

	file, err := fileHeader.Open()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "无法打开上传的文件")
		return
	}
	defer file.Close()

	result, err := mediaService.UploadImage(username, fileHeader.Filename, contentType, fileHeader.Size, file, openAssetsService)
	if err != nil {
		log.Printf("上传图像失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":          result.ID,
		"imageName":   result.ImageName,
		"imageUrl":    result.ImageURL,
		"imageSize":   result.ImageSize,
		"contentType": result.ContentType,
		"uploadTime":  result.UploadTime,
		"owner":       result.Owner,
	})
}

// DeleteImageHandler 删除用户图像
func DeleteImageHandler(c *gin.Context) {
	imageID := c.Param("imageId")
	username := c.MustGet("username").(string)

	imageName, err := mediaService.DeleteImage(imageID, username, openAssetsService)
	if err != nil {
		log.Printf("删除图像失败: %v", err)
		if strings.Contains(err.Error(), "不存在") || strings.Contains(err.Error(), "无权限") {
			log.Printf("拒绝连接: %v", err)
			c.AbortWithStatus(http.StatusNotFound)
		} else {
			utils.SendError(c, http.StatusInternalServerError, err.Error())
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "图像删除成功",
		"imageName": imageName,
	})
}

// BatchUploadImagesHandler 批量上传图像
func BatchUploadImagesHandler(c *gin.Context) {
	username := c.MustGet("username").(string)

	form, err := c.MultipartForm()
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "获取上传表单失败")
		return
	}
	files := form.File["images"]
	if len(files) == 0 {
		utils.SendError(c, http.StatusBadRequest, "未上传任何图像文件")
		return
	}
	if len(files) > 10 {
		utils.SendError(c, http.StatusBadRequest, "一次最多只能上传10个图像文件")
		return
	}

	// 准备文件信息
	var fileInfos []FileUploadInfo
	for _, header := range files {
		file, err := header.Open()
		if err != nil {
			continue
		}
		fileInfos = append(fileInfos, FileUploadInfo{
			Filename: header.Filename,
			Size:     header.Size,
			Reader:   file,
		})
	}

	results, totalSize, successCount, err := mediaService.BatchUploadImages(username, fileInfos, openAssetsService)
	if err != nil {
		log.Printf("批量上传图像失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, err.Error())
		return
	}

	// 关闭所有文件
	for _, info := range fileInfos {
		if closer, ok := info.Reader.(interface{ Close() error }); ok {
			closer.Close()
		}
	}

	// 转换结果格式
	var responseResults []gin.H
	for _, result := range results {
		responseResults = append(responseResults, gin.H{
			"fileName":    result.FileName,
			"success":     result.Success,
			"error":       result.Error,
			"imageName":   result.ImageName,
			"imageUrl":    result.ImageURL,
			"imageSize":   result.ImageSize,
			"contentType": result.ContentType,
			"recordId":    result.RecordID,
		})
	}

	c.JSON(http.StatusOK, gin.H{"results": responseResults, "totalSize": totalSize, "successCount": successCount})
}

// BatchDeleteImagesHandler 批量删除图像
func BatchDeleteImagesHandler(c *gin.Context) {
	username := c.MustGet("username").(string)

	var request struct {
		ImageIDs []int64 `json:"imageIds" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的请求数据")
		return
	}
	if len(request.ImageIDs) == 0 {
		utils.SendError(c, http.StatusBadRequest, "未指定要删除的图像")
		return
	}
	if len(request.ImageIDs) > 50 {
		utils.SendError(c, http.StatusBadRequest, "一次最多只能删除50个图像")
		return
	}

	results, successCount, err := mediaService.BatchDeleteImages(request.ImageIDs, username, openAssetsService)
	if err != nil {
		log.Printf("批量删除图像失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, err.Error())
		return
	}

	// 转换结果格式
	var responseResults []gin.H
	for _, result := range results {
		responseResults = append(responseResults, gin.H{
			"imageId":   result.ImageID,
			"success":   result.Success,
			"error":     result.Error,
			"imageName": result.ImageName,
		})
	}

	c.JSON(http.StatusOK, gin.H{"results": responseResults, "successCount": successCount, "totalCount": len(request.ImageIDs)})
}

// GetImagesHandler 获取用户图像列表
func GetImagesHandler(c *gin.Context) {
	username := c.MustGet("username").(string)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "20"))

	images, total, totalPages, err := mediaService.GetImages(username, page, pageSize)
	if err != nil {
		log.Printf("获取图像列表失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"images":     images,
		"total":      total,
		"page":       page,
		"pageSize":   pageSize,
		"totalPages": totalPages,
	})
}

// GetImageHandler 获取单个图像信息
func GetImageHandler(c *gin.Context) {
	imageID := c.Param("imageId")
	username := c.MustGet("username").(string)

	image, err := mediaService.GetImage(imageID, username)
	if err != nil {
		log.Printf("获取图像信息失败: %v", err)
		if strings.Contains(err.Error(), "不存在") || strings.Contains(err.Error(), "无权限") {
			log.Printf("拒绝连接: %v", err)
			c.AbortWithStatus(http.StatusNotFound)
		} else {
			utils.SendError(c, http.StatusInternalServerError, err.Error())
		}
		return
	}

	c.JSON(http.StatusOK, image)
}

// GetUserImageStorageHandler 获取用户图像存储信息
func GetUserImageStorageHandler(c *gin.Context) {
	username := c.MustGet("username").(string)

	storage, err := mediaService.GetUserImageStorage(username)
	if err != nil {
		log.Printf("获取存储信息失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"username":      storage.Username,
		"usedSize":      storage.UsedSize,
		"imageCount":    storage.ImageCount,
		"maxSize":       storage.MaxSize,
		"remainingSize": storage.RemainingSize,
		"usagePercent":  storage.UsagePercent,
	})
}

// ===== 头像处理器 =====

// UploadAvatarHandler 上传用户头像
func UploadAvatarHandler(c *gin.Context) {
	username := c.MustGet("username").(string)
	file, err := c.FormFile("avatar")
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "未上传头像文件")
		return
	}

	openedFile, err := file.Open()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "无法打开上传的文件")
		return
	}
	defer openedFile.Close()

	avatarURL, err := mediaService.UploadAvatar(username, openedFile, file.Filename, file.Size)
	if err != nil {
		log.Printf("上传头像失败: %v", err)
		utils.SendError(c, http.StatusBadRequest, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "avatarUrl": avatarURL})
}

// ===== 辅助函数 =====

// GenerateUUID 生成UUID（用于service层）
func GenerateUUID() string {
	return uuid.NewString()
}
