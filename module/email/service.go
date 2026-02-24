package email

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log"
	"math/big"
	"net/smtp"
	"os"
	"time"

	"github.com/resend/resend-go/v2"
)

// VerificationPurpose 验证目的类型
type VerificationPurpose string

const (
	PurposeRegister      VerificationPurpose = "register"
	PurposeResetPassword VerificationPurpose = "reset_password"
	PurposeChangeEmail   VerificationPurpose = "change_email"
)

// EmailProvider 邮件提供商类型
type EmailProvider string

const (
	ProviderSMTP   EmailProvider = "smtp"
	ProviderResend EmailProvider = "resend"
)

// EmailService 邮件服务
type EmailService struct {
	db       *sql.DB
	provider EmailProvider
	// SMTP配置
	smtpHost  string
	smtpPort  string
	smtpUser  string
	smtpPass  string
	fromName  string
	fromEmail string
	// Resend配置
	resendClient  *resend.Client
	resendFrom    string
	resendReplyTo string
	codeExpiry    time.Duration
}

// NewEmailService 创建邮件服务实例
func NewEmailService(db *sql.DB) *EmailService {
	provider := EmailProvider(getEnvOrDefault("EMAIL_PROVIDER", "smtp"))

	service := &EmailService{
		db:         db,
		provider:   provider,
		codeExpiry: 10 * time.Minute, // 验证码10分钟有效期
	}

	// 根据提供商初始化配置
	switch provider {
	case ProviderSMTP:
		service.smtpHost = os.Getenv("SMTP_HOST")
		service.smtpPort = os.Getenv("SMTP_PORT")
		service.smtpUser = os.Getenv("SMTP_USER")
		service.smtpPass = os.Getenv("SMTP_PASS")
		service.fromName = getEnvOrDefault("SMTP_FROM_NAME", "Dext")
		service.fromEmail = getEnvOrDefault("SMTP_FROM_EMAIL", os.Getenv("SMTP_USER"))
	case ProviderResend:
		apiKey := os.Getenv("RESEND_API_KEY")
		if apiKey != "" {
			service.resendClient = resend.NewClient(apiKey)
		}
		service.resendFrom = getEnvOrDefault("RESEND_FROM_EMAIL", "Dext <onboarding@resend.dev>")
		service.resendReplyTo = getEnvOrDefault("RESEND_REPLY_TO", "onboarding@resend.dev")
	default:
		log.Printf("未知的邮件提供商: %s，使用默认SMTP", provider)
		service.provider = ProviderSMTP
	}

	return service
}

// IsConfigured 检查邮件服务是否已配置
func (s *EmailService) IsConfigured() bool {
	switch s.provider {
	case ProviderSMTP:
		return s.smtpHost != "" && s.smtpPort != "" && s.smtpUser != "" && s.smtpPass != ""
	case ProviderResend:
		return s.resendClient != nil && s.resendFrom != ""
	default:
		return false
	}
}

// GenerateCode 生成6位数字验证码
func (s *EmailService) GenerateCode() (string, error) {
	const digits = "0123456789"
	code := make([]byte, 6)
	for i := range code {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		code[i] = digits[num.Int64()]
	}
	return string(code), nil
}

// SendVerificationCode 发送验证码邮件
func (s *EmailService) SendVerificationCode(email string, purpose VerificationPurpose, userID string, username string) (string, error) {
	if !s.IsConfigured() {
		return "", fmt.Errorf("邮件服务未配置")
	}

	// 生成验证码
	code, err := s.GenerateCode()
	if err != nil {
		return "", fmt.Errorf("生成验证码失败: %v", err)
	}

	// 检查是否有1分钟内发送的验证码
	var existingCode string
	var createdAt time.Time
	err = s.db.QueryRow(`
		SELECT code, created_at FROM email_verifications 
		WHERE email = ? AND purpose = ? AND verified = FALSE 
		ORDER BY created_at DESC LIMIT 1
	`, email, purpose).Scan(&existingCode, &createdAt)

	if err == nil {
		// 检查是否在1分钟内发送过
		elapsedTime := time.Since(createdAt)
		log.Printf("发现未验证的验证码，已过去时间: %v", elapsedTime)
		if elapsedTime < 1*time.Minute {
			remainingTime := 1*time.Minute - elapsedTime
			log.Printf("1分钟内已发送验证码，还需等待: %v", remainingTime)
			return "", fmt.Errorf("验证码已发送，请稍后再试")
		}
	}

	// 发送成功前，先清除该邮箱和目的的所有未验证记录
	_, err = s.db.Exec(`
		DELETE FROM email_verifications 
		WHERE email = ? AND purpose = ? AND verified = FALSE
	`, email, purpose)
	if err != nil {
		log.Printf("清除旧验证码记录失败: %v", err)
	}

	// 存储验证码到数据库
	expiresAt := time.Now().Add(s.codeExpiry)
	var result sql.Result
	if userID != "" {
		result, err = s.db.Exec(`
			INSERT INTO email_verifications (email, code, purpose, user_id, expires_at)
			VALUES (?, ?, ?, ?, ?)
		`, email, code, purpose, userID, expiresAt)
	} else {
		result, err = s.db.Exec(`
			INSERT INTO email_verifications (email, code, purpose, expires_at)
			VALUES (?, ?, ?, ?)
		`, email, code, purpose, expiresAt)
	}

	if err != nil {
		return "", fmt.Errorf("存储验证码失败: %v", err)
	}

	// 获取插入的ID
	verificationID, _ := result.LastInsertId()
	log.Printf("验证码已生成: ID=%d, Email=%s, Purpose=%s", verificationID, email, purpose)

	// 发送邮件
	subject, body := s.buildEmailContent(code, purpose, username)
	err = s.sendEmail(email, subject, body)
	if err != nil {
		// 发送失败时删除刚插入的验证码记录
		s.db.Exec("DELETE FROM email_verifications WHERE id = ?", verificationID)
		return "", fmt.Errorf("发送邮件失败: %v", err)
	}

	log.Printf("邮件发送成功: Email=%s, Purpose=%s, Provider=%s", email, purpose, s.provider)

	return code, nil
}

// VerifyCode 验证验证码
func (s *EmailService) VerifyCode(email string, code string, purpose VerificationPurpose) (bool, error) {
	var id int64
	var verified bool
	var expiresAt time.Time

	err := s.db.QueryRow(`
		SELECT id, verified, expires_at FROM email_verifications
		WHERE email = ? AND code = ? AND purpose = ?
		ORDER BY created_at DESC LIMIT 1
	`, email, code, purpose).Scan(&id, &verified, &expiresAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return false, fmt.Errorf("验证码不存在或已过期")
		}
		return false, err
	}

	// 检查是否已验证
	if verified {
		return false, fmt.Errorf("验证码已使用")
	}

	// 检查是否过期
	if time.Now().After(expiresAt) {
		return false, fmt.Errorf("验证码已过期")
	}

	// 标记为已验证
	_, err = s.db.Exec(`
		UPDATE email_verifications 
		SET verified = TRUE, verified_at = NOW()
		WHERE id = ?
	`, id)

	if err != nil {
		return false, fmt.Errorf("更新验证状态失败: %v", err)
	}

	return true, nil
}

// MarkEmailVerified 标记用户邮箱为已验证
func (s *EmailService) MarkEmailVerified(userID string) error {
	_, err := s.db.Exec(`
		UPDATE users 
		SET email_verified = TRUE, email_verified_at = NOW()
		WHERE id = ?
	`, userID)
	return err
}

// CleanupExpiredCodes 清理过期的验证码（定时任务）
func (s *EmailService) CleanupExpiredCodes() error {
	result, err := s.db.Exec(`
		DELETE FROM email_verifications 
		WHERE expires_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)
	`)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows > 0 {
		log.Printf("清理过期验证码: %d 条", rows)
	}
	return nil
}

// buildEmailContent 构建邮件内容
func (s *EmailService) buildEmailContent(code string, purpose VerificationPurpose, username string) (string, string) {
	// 如果没有用户名，使用默认称呼
	if username == "" {
		username = "用户"
	}
	var subject, body string

	switch purpose {
	case PurposeRegister:
		subject = "Dext - 注册验证码"
		body = fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #f8f9fa; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; border-bottom: 3px solid #667eea; }
        .header h1 { margin: 0; font-size: 28px; font-weight: 600; color: #333; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .code { font-size: 32px; font-weight: bold; color: #667eea; text-align: center; padding: 20px; background: white; border-radius: 8px; letter-spacing: 5px; margin: 20px 0; }
        .footer { text-align: center; color: #999; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>欢迎注册 Dext</h1>
        </div>
        <div class="content">
            <p>%s 您好！</p>
            <p>感谢您注册 Dext 问卷系统。您的验证码是：</p>
            <div class="code">%s</div>
            <p>验证码有效期为 <strong>10分钟</strong>，请尽快完成验证。</p>
            <p>如果这不是您本人的操作，请忽略此邮件。</p>
        </div>
        <div class="footer">
            <p>此邮件由系统自动发送，请勿回复。</p>
            <p>&copy; 2025 Dext. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
`, username, code)

	case PurposeResetPassword:
		subject = "Dext - 重置密码验证码"
		body = fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #f8f9fa; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; border-bottom: 3px solid #f5576c; }
        .header h1 { margin: 0; font-size: 28px; font-weight: 600; color: #333; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .code { font-size: 32px; font-weight: bold; color: #f5576c; text-align: center; padding: 20px; background: white; border-radius: 8px; letter-spacing: 5px; margin: 20px 0; }
        .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .footer { text-align: center; color: #999; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>重置密码</h1>
        </div>
        <div class="content">
            <p>%s 您好！</p>
            <p>您正在重置 Dext 账户密码。您的验证码是：</p>
            <div class="code">%s</div>
            <p>验证码有效期为 <strong>10分钟</strong>，请尽快完成验证。</p>
            <div class="warning">
                <strong>⚠️ 安全提示：</strong>如果这不是您本人的操作，说明您的账户可能存在安全风险，请立即登录并修改密码。
            </div>
        </div>
        <div class="footer">
            <p>此邮件由系统自动发送，请勿回复。</p>
            <p>&copy; 2025 Dext. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
`, username, code)

	case PurposeChangeEmail:
		subject = "Dext - 更换邮箱验证码"
		body = fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #f8f9fa; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; border-bottom: 3px solid #4facfe; }
        .header h1 { margin: 0; font-size: 28px; font-weight: 600; color: #333; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .code { font-size: 32px; font-weight: bold; color: #4facfe; text-align: center; padding: 20px; background: white; border-radius: 8px; letter-spacing: 5px; margin: 20px 0; }
        .footer { text-align: center; color: #999; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>更换邮箱</h1>
        </div>
        <div class="content">
            <p>%s 您好！</p>
            <p>您正在更换 Dext 账户绑定的邮箱地址。您的验证码是：</p>
            <div class="code">%s</div>
            <p>验证码有效期为 <strong>10分钟</strong>，请尽快完成验证。</p>
            <p>如果这不是您本人的操作，请忽略此邮件。</p>
        </div>
        <div class="footer">
            <p>此邮件由系统自动发送，请勿回复。</p>
            <p>&copy; 2025 Dext. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
`, username, code)
	}

	return subject, body
}

// sendEmail 发送邮件
func (s *EmailService) sendEmail(to, subject, body string) error {
	switch s.provider {
	case ProviderSMTP:
		return s.sendEmailWithSMTP(to, subject, body)
	case ProviderResend:
		return s.sendEmailWithResend(to, subject, body)
	default:
		return fmt.Errorf("不支持的邮件提供商: %s", s.provider)
	}
}

// sendEmailWithSMTP 使用SMTP发送邮件
func (s *EmailService) sendEmailWithSMTP(to, subject, body string) error {
	// 构建邮件头
	from := fmt.Sprintf("%s <%s>", s.fromName, s.fromEmail)
	headers := make(map[string]string)
	headers["From"] = from
	headers["To"] = to
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"

	// 组装邮件内容
	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body

	// SMTP认证
	auth := smtp.PlainAuth("", s.smtpUser, s.smtpPass, s.smtpHost)

	// 连接到SMTP服务器
	addr := fmt.Sprintf("%s:%s", s.smtpHost, s.smtpPort)

	// 如果是SSL端口（465），使用TLS连接
	if s.smtpPort == "465" {
		return s.sendEmailWithTLS(addr, auth, s.fromEmail, []string{to}, []byte(message))
	}

	// 否则使用STARTTLS
	return smtp.SendMail(addr, auth, s.fromEmail, []string{to}, []byte(message))
}

// sendEmailWithResend 使用Resend发送邮件
func (s *EmailService) sendEmailWithResend(to, subject, body string) error {
	if s.resendClient == nil {
		return fmt.Errorf("Resend客户端未初始化")
	}

	ctx := context.Background()
	params := &resend.SendEmailRequest{
		From:    s.resendFrom,
		To:      []string{to},
		Subject: subject,
		Html:    body,
	}

	// 如果配置了回复地址，添加到请求中
	if s.resendReplyTo != "" {
		params.ReplyTo = s.resendReplyTo
	}

	sent, err := s.resendClient.Emails.SendWithContext(ctx, params)
	if err != nil {
		return fmt.Errorf("resend发送失败: %v", err)
	}

	log.Printf("邮件通过Resend发送成功: ID=%s, To=%s", sent.Id, to)
	return nil
}

// sendEmailWithTLS 使用TLS发送邮件（用于465端口）
func (s *EmailService) sendEmailWithTLS(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	// 创建TLS配置
	tlsConfig := &tls.Config{
		ServerName: s.smtpHost,
	}

	// 连接到SMTP服务器
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	// 创建SMTP客户端
	client, err := smtp.NewClient(conn, s.smtpHost)
	if err != nil {
		return err
	}
	defer client.Close()

	// 认证
	if auth != nil {
		if err = client.Auth(auth); err != nil {
			return err
		}
	}

	// 设置发件人
	if err = client.Mail(from); err != nil {
		return err
	}

	// 设置收件人
	for _, addr := range to {
		if err = client.Rcpt(addr); err != nil {
			return err
		}
	}

	// 发送邮件内容
	w, err := client.Data()
	if err != nil {
		return err
	}

	_, err = w.Write(msg)
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}

	return client.Quit()
}

// getEnvOrDefault 获取环境变量或返回默认值
func getEnvOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// StartCleanupRoutine 启动定时清理任务
func (s *EmailService) StartCleanupRoutine() {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			if err := s.CleanupExpiredCodes(); err != nil {
				log.Printf("清理过期验证码失败: %v", err)
			}
		}
	}()
	log.Println("邮箱验证码清理服务已启动")
}
