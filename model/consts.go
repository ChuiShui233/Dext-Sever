// 由自动模块化脚本生成 o((>ω< ))o
package model

import "time"

const (
	ErrCodeSuccess        = 0
	ErrCodeParamError     = 40000
	ErrCodeNoLogin        = 40100
	ErrCodeNoAuth         = 40101
	ErrCodeAccountSame    = 40102
	ErrCodeTooManyRequest = 42900
	ErrCodeParamNull      = 40001
	ErrCodeSystemError    = 50000
	ErrCodeOperationError = 50001
)

const (
	JWTSecretFile     = "jwt_secrets.txt"   // 密钥文件名
	JWTSecretLifetime = 30 * 24 * time.Hour // 密钥有效期30天
	MinValidSecrets   = 2                   // 最少保留的有效密钥数
	SecretLength      = 64                  // 密钥长度
)

const (
	ErrCodeInvalidRequest  = 400
	ErrCodeUnauthorized    = 401
	ErrCodeForbidden       = 403
	ErrCodeNotFound        = 404
	ErrCodeInternalError   = 500
)
