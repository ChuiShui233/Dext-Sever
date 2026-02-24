package project

import (
	"Dext-Server/config"
	"Dext-Server/model"
	"Dext-Server/utils"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// 依赖注入：默认使用真实实现；也可在测试中替换
var projectService Service = NewService(NewProjectRepository())

// GET /api/project/projects?query=&page=1&pageSize=10
// 获取项目列表，支持按项目名称模糊搜索，分页
func GetProjectsHandler(c *gin.Context) {
	username := c.MustGet("username").(string)
	query := strings.TrimSpace(c.DefaultQuery("query", ""))
	pageStr := c.Query("page")
	pageSizeStr := c.Query("pageSize")

	// 不传分页参数则返回全部
	if pageStr == "" && pageSizeStr == "" {
		items, err := projectService.ListAll(username, query)
		if err != nil {
			utils.SendError(c, http.StatusInternalServerError, "获取项目列表失败", err)
			return
		}
		c.JSON(http.StatusOK, items)
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))
	items, total, totalPages, err := projectService.List(username, query, page, pageSize)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "获取项目列表失败", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"items":      items,
		"total":      total,
		"page":       page,
		"pageSize":   pageSize,
		"totalPages": totalPages,
	})
}

// 创建项目
func CreateProjectHandler(c *gin.Context) {
	var project model.Project
	if err := c.ShouldBindJSON(&project); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的项目数据", err)
		return
	}

	if utils.ContainsDangerousChars(project.ProjectName) {
		utils.SendError(c, http.StatusBadRequest, "项目名称包含不允许的字符", nil)
		return
	}

	if utils.ContainsDangerousChars(project.ProjectDescription) {
		utils.SendError(c, http.StatusBadRequest, "项目描述包含不允许的字符", nil)
		return
	}

	if utils.ContainsURL(project.ProjectName) || utils.ContainsURL(project.ProjectDescription) {
		urls := append(utils.ExtractURLs(project.ProjectName), utils.ExtractURLs(project.ProjectDescription)...)
		for _, url := range urls {
			if !utils.IsSafeURL(url) {
				utils.SendError(c, http.StatusForbidden, "项目信息包含不安全的URL", nil)
				return
			}
		}
	}

	if len(project.ProjectName) < 1 || len(project.ProjectName) > 100 {
		utils.SendError(c, http.StatusBadRequest, "项目名称长度必须在1-100个字符之间", nil)
		return
	}

	if len(project.ProjectDescription) > 1000 {
		utils.SendError(c, http.StatusBadRequest, "项目描述不能超过1000个字符", nil)
		return
	}

	project.ProjectName = utils.SanitizeInput(project.ProjectName)
	project.ProjectDescription = utils.SanitizeInput(project.ProjectDescription)

	username := c.MustGet("username").(string)
	userID := c.MustGet("user_id").(string)
	created, err := projectService.Create(&project, username, userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "创建项目失败", err)
		return
	}
	c.JSON(http.StatusCreated, created)
}

// 更新项目
func UpdateProjectHandler(c *gin.Context) {
	var project model.Project
	if err := c.ShouldBindJSON(&project); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的项目数据", err)
		return
	}

	project.ProjectName = utils.SanitizeInput(project.ProjectName)
	project.ProjectDescription = utils.SanitizeInput(project.ProjectDescription)

	if len(project.ProjectName) < 1 || len(project.ProjectName) > 100 {
		utils.SendError(c, http.StatusBadRequest, "项目名称长度必须在1-100个字符之间", nil)
		return
	}

	if len(project.ProjectDescription) > 1000 {
		utils.SendError(c, http.StatusBadRequest, "项目描述不能超过1000个字符", nil)
		return
	}

	username := c.MustGet("username").(string)
	updated, err := projectService.Update(&project, username)
	if err != nil {
		// service 内部已做权限校验
		utils.SendError(c, http.StatusForbidden, err.Error(), nil)
		return
	}
	c.JSON(http.StatusOK, updated)
}

// 删除单个项目
func DeleteProjectHandler(c *gin.Context) {
	db := config.DB
	id := c.Param("id")
	username := c.MustGet("username").(string)

	projectID, err := strconv.Atoi(id)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的项目ID", err)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}
	defer tx.Rollback()

	if err := projectService.DeleteBatch(tx, []int{projectID}, username); err != nil {
		utils.SendError(c, http.StatusForbidden, err.Error(), nil)
		return
	}

	if err = tx.Commit(); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "项目删除成功"})
}

// 批量删除项目
func BatchDeleteProjectsHandler(c *gin.Context) {
	db := config.DB
	username := c.MustGet("username").(string)

	var request struct {
		ProjectIDs []int `json:"projectIds" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的请求数据", err)
		return
	}

	if len(request.ProjectIDs) == 0 {
		utils.SendError(c, http.StatusBadRequest, "未指定要删除的项目", nil)
		return
	}

	if len(request.ProjectIDs) > 100 {
		utils.SendError(c, http.StatusBadRequest, "一次最多只能删除100个项目", nil)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}
	defer tx.Rollback()

	if err := projectService.DeleteBatch(tx, request.ProjectIDs, username); err != nil {
		utils.SendError(c, http.StatusForbidden, err.Error(), nil)
		return
	}

	if err := tx.Commit(); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      fmt.Sprintf("成功删除 %d 个项目", len(request.ProjectIDs)),
		"deletedCount": len(request.ProjectIDs),
	})
}
