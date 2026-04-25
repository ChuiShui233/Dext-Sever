package config

import (
	"Dext-Server/security"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

var RedisClient *redis.Client

func InitRedis() error {
	RedisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // Redis 服务器地址
		Password: "",               // 没有密码
		DB:       0,                // 使用默认数据库
	})

	ctx := context.Background()
	_, err := RedisClient.Ping(ctx).Result()
	return err
}

// 添加到Redis黑名单
func AddToBlacklist(token string) error {
	ctx := context.Background()
	rawToken := strings.TrimSpace(token)
	if strings.HasPrefix(strings.ToLower(rawToken), "bearer ") {
		rawToken = strings.TrimSpace(rawToken[7:])
	}
	if rawToken == "" {
		return nil
	}

	// 保留原有 Redis 黑名单逻辑（兼容已有行为）
	if RedisClient != nil {
		_ = RedisClient.Set(ctx, rawToken, "blacklisted", 0).Err()
	}

	// 同步写入数据库 jwt_blacklist，供会话中间件统一校验
	if DB == nil {
		return nil
	}

	claims, err := security.ParseTokenClaims(rawToken)
	if err != nil {
		return nil
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	userID := ""
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}
	if claims.Subject != "" {
		userID = claims.Subject
	}

	tokenHashRaw := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(tokenHashRaw[:])
	_, dbErr := DB.Exec(`
		INSERT INTO jwt_blacklist (token_hash, user_id, expires_at, reason)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE revoked_at = NOW(), reason = VALUES(reason), expires_at = VALUES(expires_at)
	`, tokenHash, userID, expiresAt, "manual_logout")
	return dbErr
}
