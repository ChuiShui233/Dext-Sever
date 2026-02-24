package email

import (
	"Dext-Server/config"
	"Dext-Server/utils"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

var emailService *EmailService

// InitEmailService 初始化邮件服务
func InitEmailService(db *sql.DB) {
	emailService = NewEmailService(db)
	if emailService.IsConfigured() {
		emailService.StartCleanupRoutine()
	}
}

// SendVerificationCodeHandler 发送验证码（注册/重置密码，无需登录）
func SendVerificationCodeHandler(c *gin.Context) {
	if emailService == nil || !emailService.IsConfigured() {
		utils.SendError(c, http.StatusServiceUnavailable, "邮件服务未配置")
		return
	}

	var req struct {
		Email        string `json:"email" binding:"required,email"`
		Purpose      string `json:"purpose" binding:"required"`
		CaptchaId    string `json:"captchaId" binding:"required"`
		CaptchaValue string `json:"captchaValue" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.LogError("请求绑定失败", err)
		utils.SendError(c, http.StatusBadRequest, "无效的请求格式")
		return
	}

	// 验证图形验证码
	if !utils.Verify(req.CaptchaId, req.CaptchaValue) {
		utils.LogError("验证码验证失败", fmt.Errorf("captchaId: %s, captchaValue: %s", req.CaptchaId, req.CaptchaValue))
		utils.SendError(c, http.StatusBadRequest, "验证码错误")
		return
	}

	// 验证purpose参数（仅支持注册和重置密码）
	purpose := VerificationPurpose(req.Purpose)
	if purpose != PurposeRegister && purpose != PurposeResetPassword {
		utils.SendError(c, http.StatusBadRequest, "无效的验证目的")
		return
	}

	// 标准化邮箱地址
	email := strings.ToLower(strings.TrimSpace(req.Email))

	// 根据不同目的进行额外验证
	db := config.DB
	var userID string

	switch purpose {
	case PurposeRegister:
		// 注册：检查邮箱是否已被使用
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", email).Scan(&count)
		if err != nil {
			utils.SendError(c, http.StatusInternalServerError, "系统错误")
			return
		}
		if count > 0 {
			utils.SendError(c, http.StatusBadRequest, "该邮箱已被注册")
			return
		}

	case PurposeResetPassword:
		// 重置密码：检查邮箱是否存在，获取用户名
		var username string
		err := db.QueryRow("SELECT id, username FROM users WHERE email = ?", email).Scan(&userID, &username)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Printf("拒绝连接: 邮箱 %s 未注册", email)
				c.AbortWithStatus(http.StatusNotFound)
				return
			}
			utils.SendError(c, http.StatusInternalServerError, "系统错误")
			return
		}
		// 发送验证码，传递用户名
		_, err = emailService.SendVerificationCode(email, purpose, userID, username)
		if err != nil {
			utils.SendError(c, http.StatusInternalServerError, err.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"message": "验证码已发送到您的邮箱",
			"email":   email,
		})
		return

	}

	// 注册场景：发送验证码（无用户名）
	_, err := emailService.SendVerificationCode(email, purpose, userID, "")
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "验证码已发送到您的邮箱",
		"email":   email,
	})
}

// SendChangeEmailCodeHandler 发送更换邮箱验证码（需要登录）
func SendChangeEmailCodeHandler(c *gin.Context) {
	if emailService == nil || !emailService.IsConfigured() {
		utils.SendError(c, http.StatusServiceUnavailable, "邮件服务未配置")
		return
	}

	var req struct {
		Email        string `json:"email"`
		Purpose      string `json:"purpose"`
		CaptchaId    string `json:"captchaId"`
		CaptchaValue string `json:"captchaValue"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.LogError("请求绑定失败", err)
		utils.SendError(c, http.StatusBadRequest, "无效的请求格式")
		return
	}

	// 如果提供了图形验证码，则验证
	if req.CaptchaId != "" && req.CaptchaValue != "" {
		if !utils.Verify(req.CaptchaId, req.CaptchaValue) {
			utils.LogError("验证码验证失败", fmt.Errorf("captchaId: %s, captchaValue: %s", req.CaptchaId, req.CaptchaValue))
			utils.SendError(c, http.StatusBadRequest, "验证码错误")
			return
		}
	}

	// 获取当前用户
	username, exists := c.Get("username")
	if !exists {
		utils.SendError(c, http.StatusUnauthorized, "请先登录")
		return
	}

	// 获取用户ID和当前邮箱
	db := config.DB
	var userID string
	var currentEmail sql.NullString
	err := db.QueryRow("SELECT id, email FROM users WHERE username = ?", username).Scan(&userID, &currentEmail)
	if err != nil {
		utils.LogError("查询用户信息失败", err)
		utils.SendError(c, http.StatusInternalServerError, "系统错误")
		return
	}

	// 根据用途处理不同逻辑
	var email string
	var purpose VerificationPurpose

	if req.Purpose == "reset_password" {
		// 修改密码：使用当前用户邮箱
		if !currentEmail.Valid || currentEmail.String == "" {
			utils.SendError(c, http.StatusBadRequest, "用户未绑定邮箱")
			return
		}
		email = currentEmail.String
		purpose = PurposeResetPassword
	} else {
		// 更换邮箱：使用新邮箱地址
		if req.Email == "" {
			utils.SendError(c, http.StatusBadRequest, "请提供新邮箱地址")
			return
		}
		email = strings.ToLower(strings.TrimSpace(req.Email))
		purpose = PurposeChangeEmail

		// 检查新邮箱是否已被使用
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ? AND id != ?", email, userID).Scan(&count)
		if err != nil {
			utils.LogError("检查邮箱是否已被使用失败", err)
			utils.SendError(c, http.StatusInternalServerError, "系统错误")
			return
		}
		if count > 0 {
			utils.SendError(c, http.StatusBadRequest, "该邮箱已被使用")
			return
		}
	}

	// 发送验证码
	usernameStr := username.(string)
	_, err = emailService.SendVerificationCode(email, purpose, userID, usernameStr)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "验证码已发送到您的邮箱",
		"email":   email,
	})
}

// VerifyEmailCodeHandler 验证邮箱验证码
func VerifyEmailCodeHandler(c *gin.Context) {
	if emailService == nil {
		utils.SendError(c, http.StatusServiceUnavailable, "邮件服务未配置")
		return
	}

	var req struct {
		Email   string `json:"email" binding:"required,email"`
		Code    string `json:"code" binding:"required,len=6"`
		Purpose string `json:"purpose" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的请求格式")
		return
	}

	// 验证purpose参数
	purpose := VerificationPurpose(req.Purpose)
	if purpose != PurposeRegister && purpose != PurposeResetPassword && purpose != PurposeChangeEmail {
		utils.SendError(c, http.StatusBadRequest, "无效的验证目的")
		return
	}

	// 标准化邮箱地址
	email := strings.ToLower(strings.TrimSpace(req.Email))

	// 验证验证码
	valid, err := emailService.VerifyCode(email, req.Code, purpose)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, err.Error())
		return
	}

	if !valid {
		utils.SendError(c, http.StatusBadRequest, "验证码验证失败")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "验证成功",
		"email":    email,
		"verified": true,
	})
}

// GetEmailService 获取邮件服务实例（供其他模块使用）
func GetEmailService() *EmailService {
	return emailService
}
