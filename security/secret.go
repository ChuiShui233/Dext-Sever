package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/joho/godotenv"
)

type JWTSecret struct {
	Secret    string    `json:"secret"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

const (
	JWTSecretFile     = "jwt_secrets.txt"
	SecretLength      = 64
	JWTSecretLifetime = 24 * time.Hour * 30 // 30天
	MinValidSecrets   = 2
)

// 密钥轮换器
var rotationMutex sync.Mutex

// 启动密钥轮换服务
func StartSecretRotation() {
	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		for range ticker.C {
			if err := RotateSecrets(); err != nil {
				log.Printf("密钥轮换失败: %v", err)
			}
		}
	}()
}

// 轮换密钥
func RotateSecrets() error {
	rotationMutex.Lock()
	defer rotationMutex.Unlock()

	secrets, err := loadSecrets()
	if err != nil {
		return fmt.Errorf("加载密钥失败: %v", err)
	}

	// 生成新密钥
	newSecret, err := generateNewSecret()
	if err != nil {
		return fmt.Errorf("生成新密钥失败: %v", err)
	}

	// 添加新密钥到列表开头
	secrets = append([]*JWTSecret{newSecret}, secrets...)

	// 清理过期密钥
	now := time.Now()
	validSecrets := make([]*JWTSecret, 0)
	for _, secret := range secrets {
		if secret.ExpiresAt.After(now) {
			validSecrets = append(validSecrets, secret)
		}
	}

	// 确保至少保留MinValidSecrets个密钥
	if len(validSecrets) < MinValidSecrets {
		for i := len(validSecrets); i < MinValidSecrets; i++ {
			secret, err := generateNewSecret()
			if err != nil {
				return fmt.Errorf("生成补充密钥失败: %v", err)
			}
			validSecrets = append(validSecrets, secret)
		}
	}

	// 写入文件
	return writeSecretsToFile(validSecrets)
}

// 加载所有JWT密钥
func LoadSecrets() ([]*JWTSecret, error) {
	// 加载环境变量
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	data, err := ioutil.ReadFile(JWTSecretFile)
	if err != nil {
		if os.IsNotExist(err) {
			// 文件不存在，创建新文件并生成初始密钥
			return InitializeSecretFile()
		}
		return nil, fmt.Errorf("读取密钥文件失败: %v", err)
	}

	// 解析密钥文件
	var secrets []*JWTSecret
	lines := strings.Split(string(data), "\n")
	now := time.Now()

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 解析密钥信息
		parts := strings.Split(line, "|")
		if len(parts) != 3 {
			log.Printf("警告: 跳过无效的密钥行: %s", line)
			continue
		}

		secret := parts[0]
		createdAt, err := time.Parse(time.RFC3339, parts[1])
		if err != nil {
			log.Printf("警告: 跳过无效的创建时间: %s", parts[1])
			continue
		}

		expiresAt, err := time.Parse(time.RFC3339, parts[2])
		if err != nil {
			log.Printf("警告: 跳过无效的过期时间: %s", parts[2])
			continue
		}

		// 只保留未过期的密钥
		if expiresAt.After(now) {
			secrets = append(secrets, &JWTSecret{
				Secret:    secret,
				CreatedAt: createdAt,
				ExpiresAt: expiresAt,
			})
		}
	}

	// 如果没有有效密钥，生成新密钥
	if len(secrets) == 0 {
		return InitializeSecretFile()
	}

	return secrets, nil
}

func loadSecrets() ([]*JWTSecret, error) {
	return LoadSecrets()
}

// 初始化密钥文件
func InitializeSecretFile() ([]*JWTSecret, error) {
	// 生成两个初始密钥
	secrets := make([]*JWTSecret, 0, MinValidSecrets)
	for i := 0; i < MinValidSecrets; i++ {
		secret, err := generateNewSecret()
		if err != nil {
			return nil, fmt.Errorf("生成初始密钥失败: %v", err)
		}
		secrets = append(secrets, secret)
	}

	// 写入文件
	if err := writeSecretsToFile(secrets); err != nil {
		return nil, fmt.Errorf("写入初始密钥失败: %v", err)
	}

	return secrets, nil
}

// 写入密钥到文件
func writeSecretsToFile(secrets []*JWTSecret) error {
	var lines []string
	for _, secret := range secrets {
		line := fmt.Sprintf("%s|%s|%s",
			secret.Secret,
			secret.CreatedAt.Format(time.RFC3339),
			secret.ExpiresAt.Format(time.RFC3339))
		lines = append(lines, line)
	}

	data := []byte(strings.Join(lines, "\n"))
	return ioutil.WriteFile(JWTSecretFile, data, 0600)
}

// 生成新的JWT密钥
func generateNewSecret() (*JWTSecret, error) {
	// 使用加密安全的随机数生成器
	randomBytes := make([]byte, SecretLength)
	if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
		return nil, fmt.Errorf("生成随机数失败: %v", err)
	}

	// 使用SHA-256进行混合
	hash := sha256.New()
	hash.Write(randomBytes)
	hash.Write([]byte(time.Now().String()))

	// 生成最终密钥
	secret := base64.URLEncoding.EncodeToString(hash.Sum(nil))

	// 确保密钥长度
	if len(secret) < SecretLength {
		secret = secret + secret[:SecretLength-len(secret)]
	}
	secret = secret[:SecretLength]

	// 验证密钥复杂度
	if !validateSecretComplexity(secret) {
		return nil, fmt.Errorf("生成的密钥不符合复杂度要求")
	}

	now := time.Now()
	return &JWTSecret{
		Secret:    secret,
		CreatedAt: now,
		ExpiresAt: now.Add(JWTSecretLifetime),
	}, nil
}

// 验证密钥复杂度
func validateSecretComplexity(secret string) bool {
	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, c := range secret {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsNumber(c):
			hasNumber = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasNumber && hasSpecial
}
