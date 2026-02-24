package utils

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

// SendError 支持可选 err 参数
func SendError(c *gin.Context, code int, msg string, errs ...error) {
	var err error
	if len(errs) > 0 {
		err = errs[0]
	}

	if err != nil {
		LogError(msg, err) // 记录错误日志
	} else {
		LogError(msg, nil)
	}

	c.JSON(code, gin.H{
		"error":   msg,
		"status":  code,
		"success": false,
	})
	c.Abort()
}

// 错误日志记录函数
func LogError(context string, err error) {
	if err != nil {
		log.Printf("[ERROR] %s: %v", context, err)
	} else {
		log.Printf("[ERROR] %s", context)
	}

	// 在生产环境中，可以考虑将错误发送到日志服务
	if os.Getenv("ENV") == "production" {
		// TODO: 日志上报逻辑（Sentry、阿里云日志、钉钉告警）
	}
}

// 便捷方法：系统内部错误
func InternalError(c *gin.Context, err error) {
	SendError(c, http.StatusInternalServerError, "系统错误", err)
}
