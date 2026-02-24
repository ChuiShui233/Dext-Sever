package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

// 全局私钥变量
var PrivateKey *rsa.PrivateKey

// InitPrivateKey 初始化RSA私钥
func InitPrivateKey() error {
	keyBytes, err := ioutil.ReadFile("private_key.pem")
	if err != nil {
		return fmt.Errorf("读取私钥文件失败: %v", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") {
		return fmt.Errorf("无效的PEM私钥")
	}

	// 尝试解析 PKCS#1
	PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// 尝试解析 PKCS#8
		keyInterface, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return fmt.Errorf("解析私钥失败: %v / %v", err, err2)
		}
		var ok bool
		PrivateKey, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("私钥类型错误")
		}
	}

	log.Printf("私钥初始化成功，大小: %d bits", PrivateKey.Size()*8)
	return nil
}

// DecryptData 使用RSA解密数据
func DecryptData(encryptedData []byte) ([]byte, error) {
	if PrivateKey == nil {
		return nil, fmt.Errorf("私钥未初始化")
	}

	blockSize := PrivateKey.Size()
	decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, PrivateKey, encryptedData)
	if err != nil {
		// 分块解密
		var allDecryptedData []byte
		var decryptError error
		for i := 0; i < len(encryptedData); i += blockSize {
			end := i + blockSize
			if end > len(encryptedData) {
				end = len(encryptedData)
			}
			block := encryptedData[i:end]

			decryptedBlock, err := rsa.DecryptPKCS1v15(rand.Reader, PrivateKey, block)
			if err != nil {
				decryptedBlock, err = rsa.DecryptOAEP(
					sha256.New(),
					rand.Reader,
					PrivateKey,
					block,
					nil,
				)
				if err != nil {
					decryptError = err
					break
				}
			}
			allDecryptedData = append(allDecryptedData, decryptedBlock...)
		}
		if decryptError != nil {
			return nil, fmt.Errorf("解密失败: %v", decryptError)
		}
		decryptedData = allDecryptedData
	}

	if len(decryptedData) == 0 {
		return nil, fmt.Errorf("解密后数据为空")
	}

	return decryptedData, nil
}

// DecryptSessionKey 解密RSA加密的会话密钥
func DecryptSessionKey(encryptedSessionKey string) ([]byte, error) {
	if PrivateKey == nil {
		return nil, fmt.Errorf("私钥未初始化")
	}

	// Base64解码
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedSessionKey)
	if err != nil {
		return nil, fmt.Errorf("Base64解码失败: %v", err)
	}

	// RSA解密
	decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, PrivateKey, encryptedData)
	if err != nil {
		// 尝试OAEP解密
		decryptedData, err = rsa.DecryptOAEP(
			sha256.New(),
			rand.Reader,
			PrivateKey,
			encryptedData,
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("RSA解密失败: %v", err)
		}
	}

	return decryptedData, nil
}
