package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// SessionKey 会话密钥结构
type SessionKey struct {
	Key []byte `json:"key"`
	IV  []byte `json:"iv"`
}

// GenerateSessionKey 生成AES会话密钥
func GenerateSessionKey() (*SessionKey, error) {
	// 生成32字节的AES-256密钥
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("生成会话密钥失败: %v", err)
	}

	// 生成16字节的IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("生成IV失败: %v", err)
	}

	return &SessionKey{
		Key: key,
		IV:  iv,
	}, nil
}

// EncryptWithSessionKey 使用会话密钥加密数据
func EncryptWithSessionKey(data []byte, sessionKey *SessionKey) ([]byte, error) {
	block, err := aes.NewCipher(sessionKey.Key)
	if err != nil {
		return nil, fmt.Errorf("创建AES cipher失败: %v", err)
	}

	// 使用CFB模式
	stream := cipher.NewCFBEncrypter(block, sessionKey.IV)
	encrypted := make([]byte, len(data))
	stream.XORKeyStream(encrypted, data)

	// 将IV和加密数据组合
	result := make([]byte, aes.BlockSize+len(encrypted))
	copy(result[:aes.BlockSize], sessionKey.IV)
	copy(result[aes.BlockSize:], encrypted)

	return result, nil
}

// DecryptWithSessionKey 使用会话密钥解密数据
func DecryptWithSessionKey(encryptedData []byte, sessionKey *SessionKey) ([]byte, error) {
	if len(encryptedData) < aes.BlockSize {
		return nil, fmt.Errorf("加密数据长度不足")
	}

	block, err := aes.NewCipher(sessionKey.Key)
	if err != nil {
		return nil, fmt.Errorf("创建AES cipher失败: %v", err)
	}

	// 提取IV和加密数据
	iv := encryptedData[:aes.BlockSize]
	encrypted := encryptedData[aes.BlockSize:]

	// 使用CFB模式解密
	stream := cipher.NewCFBDecrypter(block, iv)
	decrypted := make([]byte, len(encrypted))
	stream.XORKeyStream(decrypted, encrypted)

	return decrypted, nil
}

// EncryptWithSessionKeyGCM 使用GCM模式加密（更安全）
func EncryptWithSessionKeyGCM(data []byte, sessionKey *SessionKey) ([]byte, error) {
	block, err := aes.NewCipher(sessionKey.Key)
	if err != nil {
		return nil, fmt.Errorf("创建AES cipher失败: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM失败: %v", err)
	}

	// 生成随机nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("生成nonce失败: %v", err)
	}

	// 加密并添加认证标签
	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

// DecryptWithSessionKeyGCM 使用GCM模式解密
func DecryptWithSessionKeyGCM(encryptedData []byte, sessionKey *SessionKey) ([]byte, error) {
	block, err := aes.NewCipher(sessionKey.Key)
	if err != nil {
		return nil, fmt.Errorf("创建AES cipher失败: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM失败: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("加密数据长度不足")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %v", err)
	}

	return decrypted, nil
}

// SessionKeyToBase64 将会话密钥编码为Base64
func SessionKeyToBase64(sessionKey *SessionKey) string {
	combined := append(sessionKey.Key, sessionKey.IV...)
	return base64.StdEncoding.EncodeToString(combined)
}

// SessionKeyFromBase64 从Base64解码会话密钥
func SessionKeyFromBase64(encoded string) (*SessionKey, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("Base64解码失败: %v", err)
	}

	if len(data) != 32+aes.BlockSize {
		return nil, fmt.Errorf("会话密钥长度不正确")
	}

	return &SessionKey{
		Key: data[:32],
		IV:  data[32:],
	}, nil
}
