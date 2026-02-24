package utils

import (
	"fmt"
	mrand "math/rand"
	"strings"
	"time"

	"github.com/google/uuid"
)

func GenerateRandomUID(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[r.Intn(len(charset))]
	}
	return string(b)
}

func GenerateCustomUserID() string {
	// 生成一个 UUID
	id := uuid.New().String()
	// 移除 UUID 中的破折号
	id = strings.ReplaceAll(id, "-", "")

	// 确保长度足够，如果不足则重复或截断
	if len(id) < 14 {
		for len(id) < 14 {
			id += uuid.New().String() // 拼接新的 UUID 直到长度足够
		}
	}
	id = id[:14] // 截取前14位

	// 格式化为 XXX_XXXXXXXXXXX
	return fmt.Sprintf("%s_%s", id[:3], id[3:])
}
