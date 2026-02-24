package utils

import (
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/mojocn/base64Captcha"
)

// ========== 验证码相关 ========== //
var captchaStore = base64Captcha.DefaultMemStore

// 读取验证码难度
func GetCaptchaLevel() int {
	level := 2 // 默认难度
	if v := os.Getenv("CAPTCHA_LEVEL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			level = n
		}
	}
	return level
}

// 获取验证码图片接口
func GetCaptchaHandler(c *gin.Context) {
	level := GetCaptchaLevel()
	driver := base64Captcha.NewDriverString(
		60,           // 高度
		154,          // 宽度
		level,        // 噪点数量
		level,        // 干扰线数量
		4,            // 长度
		"1234567890", // 字符集
		nil,          // 背景色
		nil,          // 字体存储
		nil,          // 字体
	)
	captcha := base64Captcha.NewCaptcha(driver, captchaStore)
	id, b64s, _, err := captcha.Generate()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 0, "msg": "验证码生成失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 1, "data": b64s, "captchaId": id, "msg": "success"})
}

// 校验验证码接口
func VerifyCaptchaHandler(c *gin.Context) {
	var req struct {
		CaptchaId    string `json:"captchaId"`
		CaptchaValue string `json:"captchaValue"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 0, "msg": "参数错误"})
		return
	}
	if captchaStore.Verify(req.CaptchaId, req.CaptchaValue, true) {
		c.JSON(http.StatusOK, gin.H{"code": 1, "msg": "ok"})
	} else {
		c.JSON(http.StatusOK, gin.H{"code": 0, "msg": "验证码错误"})
	}
}

func Verify(captchaId, captchaValue string) bool {
	return captchaStore.Verify(captchaId, captchaValue, true)
}
