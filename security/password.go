package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id 参数配置
const (
	// 时间成本（迭代次数）
	ArgonTime = 1
	// 内存成本（KB）
	ArgonMemory = 64 * 1024
	// 并行度
	ArgonThreads = 4
	// 密钥长度
	ArgonKeyLen = 32
	// 盐长度
	ArgonSaltLen = 16
)

// PasswordConfig 密码配置结构
type PasswordConfig struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

// DefaultPasswordConfig 默认密码配置
var DefaultPasswordConfig = &PasswordConfig{
	Time:    ArgonTime,
	Memory:  ArgonMemory,
	Threads: ArgonThreads,
	KeyLen:  ArgonKeyLen,
	SaltLen: ArgonSaltLen,
}

// GenerateSalt 生成随机盐
func GenerateSalt(length uint32) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("生成盐失败: %v", err)
	}
	return salt, nil
}

// HashPassword 使用Argon2id哈希密码
// 格式: $argon2id$v=19$m=65536,t=1,p=4$salt$hash
func HashPassword(password string, pepper string) (string, error) {
	return HashPasswordWithConfig(password, pepper, DefaultPasswordConfig)
}

// HashPasswordWithConfig 使用自定义配置哈希密码
func HashPasswordWithConfig(password string, pepper string, config *PasswordConfig) (string, error) {
	// 生成随机盐
	salt, err := GenerateSalt(config.SaltLen)
	if err != nil {
		return "", err
	}

	// 组合密码：password + salt + pepper
	combined := password + string(salt) + pepper

	// 使用Argon2id生成哈希
	hash := argon2.IDKey([]byte(combined), salt, config.Time, config.Memory, config.Threads, config.KeyLen)

	// 编码为base64
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)

	// 格式化为标准格式
	encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		config.Memory, config.Time, config.Threads, saltB64, hashB64)

	return encoded, nil
}

// VerifyPassword 验证密码
func VerifyPassword(password string, pepper string, encodedHash string) (bool, error) {
	// 解析哈希字符串
	config, salt, hash, err := parseEncodedHash(encodedHash)
	if err != nil {
		return false, err
	}

	// 组合密码：password + salt + pepper
	combined := password + string(salt) + pepper

	// 使用相同参数生成哈希
	otherHash := argon2.IDKey([]byte(combined), salt, config.Time, config.Memory, config.Threads, config.KeyLen)

	// 使用constant time比较防止时序攻击
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}

// parseEncodedHash 解析编码的哈希字符串
func parseEncodedHash(encodedHash string) (*PasswordConfig, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, fmt.Errorf("无效的哈希格式")
	}

	if parts[1] != "argon2id" {
		return nil, nil, nil, fmt.Errorf("不支持的哈希算法: %s", parts[1])
	}

	if parts[2] != "v=19" {
		return nil, nil, nil, fmt.Errorf("不支持的Argon2版本: %s", parts[2])
	}

	// 解析参数
	var memory, time uint32
	var threads uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("解析参数失败: %v", err)
	}

	// 解码盐
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("解码盐失败: %v", err)
	}

	// 解码哈希
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("解码哈希失败: %v", err)
	}

	config := &PasswordConfig{
		Time:    time,
		Memory:  memory,
		Threads: threads,
		KeyLen:  uint32(len(hash)),
		SaltLen: uint32(len(salt)),
	}

	return config, salt, hash, nil
}

// GetPepper 获取pepper值（从环境变量或配置文件）
func GetPepper() string {
	// 这里应该从安全的地方获取pepper，比如环境变量或配置文件
	// 为了演示，这里使用一个固定值，实际应用中应该使用随机生成的值
	return "your-secret-pepper-key-change-this-in-production"
}

// IsArgon2Hash 检查是否为Argon2哈希
func IsArgon2Hash(hash string) bool {
	return strings.HasPrefix(hash, "$argon2id$")
}
