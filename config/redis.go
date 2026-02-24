package config

import (
	"context"

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
	err := RedisClient.Set(ctx, token, "blacklisted", 0).Err()
	return err
}
