package clean

import (
	"Dext-Server/config"
	"Dext-Server/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

var cleaner *Cleaner

// InitCleaner 初始化清理器
func InitCleaner() {
	cleaner = NewCleaner(config.DB)
}

// CleanupHandler 清理处理器
func CleanupHandler(c *gin.Context) {
	// 检查权限（只有管理员可以执行清理）
	userRole := c.GetInt("userRole")

	if userRole < 1 { // 只有管理员可以执行清理
		utils.SendError(c, http.StatusForbidden, "权限不足，只有管理员可以执行清理操作")
		return
	}

	// 执行清理
	startTime := time.Now()

	if err := cleaner.CleanUnusedFiles(); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "清理失败: "+err.Error())
		return
	}

	duration := time.Since(startTime)

	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"message":   "清理完成",
		"duration":  duration.String(),
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// GetFileBindingsHandler 获取文件绑定关系
func GetFileBindingsHandler(c *gin.Context) {
	// 检查权限（只有管理员可以查询绑定关系）
	userRole := c.GetInt("userRole")

	if userRole < 1 { // 只有管理员可以查询绑定关系
		utils.SendError(c, http.StatusForbidden, "权限不足，只有管理员可以查询绑定关系")
		return
	}

	fileName := c.Param("fileName")
	if fileName == "" {
		utils.SendError(c, http.StatusBadRequest, "文件名不能为空")
		return
	}

	// 查询文件绑定关系
	bindings, err := cleaner.GetFileBindings(fileName)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "查询绑定关系失败: "+err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    bindings,
	})
}
