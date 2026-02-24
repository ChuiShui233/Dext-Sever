package security

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// 获取token过期时间配置
func GetTokenExpiration() time.Duration {
	if envExpiration := os.Getenv("JWT_EXPIRATION"); envExpiration != "" {
		if duration, err := time.ParseDuration(envExpiration); err == nil {
			if duration < 5*time.Minute {
				duration = 5 * time.Minute
			}
			if duration > 30*24*time.Hour {
				duration = 30 * 24 * time.Hour
			}
			return duration
		}
		log.Printf("无法解析JWT_EXPIRATION: %s", envExpiration)
	}
	return 1 * time.Hour
}

// 生成JWT令牌
func GenerateToken(username string) (string, time.Time, error) {
	return GenerateTokenWithExpiration(username, GetTokenExpiration())
}

// 生成JWT令牌 - 指定过期时间
func GenerateTokenWithExpiration(username string, expiration time.Duration) (string, time.Time, error) {
	secrets, err := LoadSecrets() // <-- 从 secret.go 提供
	if err != nil {
		return "", time.Time{}, fmt.Errorf("加载密钥失败: %v", err)
	}

	if len(secrets) == 0 {
		return "", time.Time{}, fmt.Errorf("没有可用的密钥")
	}

	secret := secrets[0]
	now := time.Now()
	expires := now.Add(expiration)

	claims := jwt.RegisteredClaims{
		Subject:   username,
		ExpiresAt: jwt.NewNumericDate(expires),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Issuer:    "auth-server",
		ID:        uuid.New().String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret.Secret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("签名失败: %v", err)
	}

	log.Printf("为用户 %s 生成令牌，过期时间: %s", username, expires.Format("2006-01-02 15:04:05"))

	return tokenString, expires, nil
}

// 刷新令牌
func RefreshToken(tokenString string) (string, time.Time, error) {
	secrets, err := LoadSecrets()
	if err != nil {
		return "", time.Time{}, err
	}

	if len(secrets) == 0 {
		return "", time.Time{}, fmt.Errorf("没有可用的密钥")
	}

	for _, secret := range secrets {
		claims := &jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("不支持的签名算法: %v", token.Header["alg"])
			}
			return []byte(secret.Secret), nil
		})

		if err == nil && token.Valid {
			if claims.ExpiresAt.Before(time.Now()) {
				return "", time.Time{}, fmt.Errorf("令牌已过期")
			}
			if claims.Subject == "" {
				return "", time.Time{}, fmt.Errorf("令牌缺少Subject声明")
			}
			return GenerateToken(claims.Subject)
		}
	}
	return "", time.Time{}, fmt.Errorf("令牌验证失败")
}

// GenerateJWT 生成JWT令牌（OAuth使用）
func GenerateJWT(userID, username string) (string, time.Time, error) {
	return GenerateTokenWithExpiration(userID, GetTokenExpiration())
}

// GenerateRandomString 生成指定长度的随机字符串
func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		// 如果加密随机数生成失败，使用UUID作为备选
		return uuid.New().String()[:length]
	}
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b)
}

// ParseTokenClaims 解析JWT并返回标准声明（包含Subject与ID/JTI）
func ParseTokenClaims(tokenString string) (*jwt.RegisteredClaims, error) {
	secrets, err := LoadSecrets()
	if err != nil {
		return nil, fmt.Errorf("加载密钥失败: %v", err)
	}
	if len(secrets) == 0 {
		return nil, fmt.Errorf("没有可用的密钥")
	}

	var lastErr error
	for _, secret := range secrets {
		claims := &jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("不支持的签名算法: %v", token.Header["alg"])
			}
			return []byte(secret.Secret), nil
		})
		if err == nil && token.Valid {
			return claims, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("令牌验证失败")
}
