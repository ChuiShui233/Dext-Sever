package security

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// XChaChaKeyPair 用于 X25519 密钥交换的密钥对
type XChaChaKeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

// GenerateXChaChaKeyPair 生成 X25519 密钥对
func GenerateXChaChaKeyPair() (*XChaChaKeyPair, error) {
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, fmt.Errorf("生成私钥失败: %v", err)
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("生成公钥失败: %v", err)
	}

	return &XChaChaKeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// DeriveSharedSecret 通过 ECDH 派生共享密钥
func DeriveSharedSecret(privateKey, remotePublicKey []byte) ([]byte, error) {
	if len(privateKey) != curve25519.ScalarSize {
		return nil, fmt.Errorf("私钥长度不正确: %d", len(privateKey))
	}
	if len(remotePublicKey) != curve25519.PointSize {
		return nil, fmt.Errorf("公钥长度不正确: %d", len(remotePublicKey))
	}

	sharedSecret, err := curve25519.X25519(privateKey, remotePublicKey)
	if err != nil {
		return nil, fmt.Errorf("派生共享密钥失败: %v", err)
	}

	// 直接使用 32 字节作为加密密钥（XChaCha20 需要 32 字节密钥）
	return sharedSecret, nil
}

// EncryptPacket 使用 XChaCha20-Poly1305 加密数据包
// 返回格式: [Nonce Part A (12B)] + [Nonce Part B (12B)] + [Ciphertext] + [Tag (16B)]
func EncryptPacket(sessionKey []byte, plaintext []byte) ([]byte, error) {
	if len(sessionKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("会话密钥长度不正确: %d，需要 %d", len(sessionKey), chacha20poly1305.KeySize)
	}

	aead, err := chacha20poly1305.NewX(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("创建 XChaCha20-Poly1305 实例失败: %v", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("生成 nonce 失败: %v", err)
	}

	// XChaCha20 Nonce (24B) = [Part A (12B)] + [Part B (12B)]
	noncePartA := nonce[:12]
	noncePartB := nonce[12:24]

	// 加密数据
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// 提取认证标签（最后 16 字节）
	tag := ciphertext[len(ciphertext)-16:]
	actualCiphertext := ciphertext[:len(ciphertext)-16]

	// 组装数据包: [Nonce Part A (12B)] + [Nonce Part B (12B)] + [Ciphertext] + [Tag (16B)]
	packet := make([]byte, 0, 12+12+len(actualCiphertext)+16)
	packet = append(packet, noncePartA...)
	packet = append(packet, noncePartB...)
	packet = append(packet, actualCiphertext...)
	packet = append(packet, tag...)

	return packet, nil
}

// DecryptPacket 使用 XChaCha20-Poly1305 解密数据包
func DecryptPacket(sessionKey []byte, encryptedPacket []byte) ([]byte, error) {
	if len(sessionKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("会话密钥长度不正确: %d，需要 %d", len(sessionKey), chacha20poly1305.KeySize)
	}

	const aesIVLength = 12
	const aesTagLength = 16
	const hiddenNonceLength = 12

	if len(encryptedPacket) < aesIVLength+aesTagLength+hiddenNonceLength {
		return nil, fmt.Errorf("数据包长度太短: %d", len(encryptedPacket))
	}

	// 解析数据包结构
	noncePartA := encryptedPacket[0:aesIVLength]
	tagBytes := encryptedPacket[len(encryptedPacket)-aesTagLength:]
	bodySection := encryptedPacket[aesIVLength : len(encryptedPacket)-aesTagLength]
	noncePartB := bodySection[0:hiddenNonceLength]
	actualCiphertext := bodySection[hiddenNonceLength:]

	// 重组完整的 nonce
	fullNonce := make([]byte, 24)
	copy(fullNonce[0:12], noncePartA)
	copy(fullNonce[12:24], noncePartB)

	// 重组密文（包含标签）
	ciphertextWithTag := make([]byte, len(actualCiphertext)+16)
	copy(ciphertextWithTag, actualCiphertext)
	copy(ciphertextWithTag[len(actualCiphertext):], tagBytes)

	aead, err := chacha20poly1305.NewX(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("创建 XChaCha20-Poly1305 实例失败: %v", err)
	}

	// 解密数据
	plaintext, err := aead.Open(nil, fullNonce, ciphertextWithTag, nil)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %v", err)
	}

	return plaintext, nil
}

// min 辅助函数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetXChaChaPublicKey 获取 X25519 公钥（Base64 编码）
// 这个函数应该返回服务器的固定公钥，或者从配置中读取
func GetXChaChaPublicKey() (string, error) {
	// TODO: 从配置文件或环境变量中读取公钥
	// 这里暂时生成一个临时密钥对（实际应该使用固定的密钥对）
	keyPair, err := GenerateXChaChaKeyPair()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(keyPair.PublicKey), nil
}

// ServerKeyPair 服务器密钥对（应该在启动时生成并保存）
var serverKeyPair *XChaChaKeyPair

// InitServerKeyPair 初始化服务器密钥对
func InitServerKeyPair() error {
	var err error
	serverKeyPair, err = GenerateXChaChaKeyPair()
	if err != nil {
		return fmt.Errorf("初始化服务器密钥对失败: %v", err)
	}
	return nil
}

// GetServerPublicKey 获取服务器公钥（Base64 编码）
func GetServerPublicKey() string {
	if serverKeyPair == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(serverKeyPair.PublicKey)
}

// DecryptXChaChaRequest 解密 XChaCha 加密的请求
// 返回解密后的数据和客户端临时公钥（用于响应加密）
func DecryptXChaChaRequest(encryptedPayload map[string]interface{}) ([]byte, []byte, error) {
	// 解析请求体中的 ephemeralPublicKey 和 packet
	ephemeralPublicKeyStr, ok := encryptedPayload["ephemeralPublicKey"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("缺少 ephemeralPublicKey 字段")
	}

	packetStr, ok := encryptedPayload["packet"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("缺少 packet 字段")
	}

	// Base64 解码
	remoteEphemeralKey, err := base64.StdEncoding.DecodeString(ephemeralPublicKeyStr)
	if err != nil {
		return nil, nil, fmt.Errorf("解码 ephemeralPublicKey 失败: %v", err)
	}

	encryptedPacket, err := base64.StdEncoding.DecodeString(packetStr)
	if err != nil {
		return nil, nil, fmt.Errorf("解码 packet 失败: %v", err)
	}

	// 使用服务器私钥和客户端公钥派生会话密钥
	if serverKeyPair == nil {
		return nil, nil, fmt.Errorf("服务器密钥对未初始化")
	}

	sessionKey, err := DeriveSharedSecret(serverKeyPair.PrivateKey, remoteEphemeralKey)
	if err != nil {
		return nil, nil, fmt.Errorf("派生会话密钥失败: %v", err)
	}

	// 添加调试信息
	log.Printf("解密请求: sessionKey长度=%d, packet长度=%d, remoteEphemeralKey长度=%d", 
		len(sessionKey), len(encryptedPacket), len(remoteEphemeralKey))
	log.Printf("服务器私钥前8字节: %x", serverKeyPair.PrivateKey[:min(8, len(serverKeyPair.PrivateKey))])
	log.Printf("服务器公钥前8字节: %x", serverKeyPair.PublicKey[:min(8, len(serverKeyPair.PublicKey))])
	log.Printf("客户端临时公钥前8字节: %x", remoteEphemeralKey[:min(8, len(remoteEphemeralKey))])
	if len(sessionKey) > 0 {
		log.Printf("派生出的sessionKey前8字节: %x", sessionKey[:min(8, len(sessionKey))])
	}
	if len(encryptedPacket) >= 24 {
		log.Printf("packet前24字节(nonce): %x", encryptedPacket[:24])
	}

	// 解密数据包
	plaintext, err := DecryptPacket(sessionKey, encryptedPacket)
	if err != nil {
		log.Printf("解密失败详情: sessionKey长度=%d, packet长度=%d, 错误=%v", len(sessionKey), len(encryptedPacket), err)
		// 打印数据包的前几个字节用于调试
		if len(encryptedPacket) > 0 {
			log.Printf("数据包前32字节: %x", encryptedPacket[:min(32, len(encryptedPacket))])
		}
		return nil, nil, fmt.Errorf("解密数据包失败: %v", err)
	}

	return plaintext, remoteEphemeralKey, nil
}

// EncryptXChaChaResponse 加密响应数据
// clientEphemeralPublicKey 是客户端在请求中发送的临时公钥
func EncryptXChaChaResponse(plaintext []byte, clientEphemeralPublicKey []byte) (map[string]interface{}, error) {
	if serverKeyPair == nil {
		return nil, fmt.Errorf("服务器密钥对未初始化")
	}

	// 生成服务器临时密钥对用于响应
	serverEphemeralKeyPair, err := GenerateXChaChaKeyPair()
	if err != nil {
		return nil, fmt.Errorf("生成服务器临时密钥对失败: %v", err)
	}

	// 使用服务器临时私钥和客户端临时公钥派生响应会话密钥
	responseSessionKey, err := DeriveSharedSecret(serverEphemeralKeyPair.PrivateKey, clientEphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("派生响应会话密钥失败: %v", err)
	}

	// 加密数据包
	encryptedPacket, err := EncryptPacket(responseSessionKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("加密数据包失败: %v", err)
	}

	return map[string]interface{}{
		"ephemeralPublicKey": base64.StdEncoding.EncodeToString(serverEphemeralKeyPair.PublicKey),
		"packet":             base64.StdEncoding.EncodeToString(encryptedPacket),
	}, nil
}

