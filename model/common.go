// 由自动模块化脚本生成 o((>ω< ))o
package model

import (
	"time"

	"golang.org/x/time/rate"
)

type BaseResponse struct {
	Code        int         `json:"code"`
	Data        interface{} `json:"data"`
	Message     string      `json:"message"`
	Description string      `json:"description,omitempty"`
}

type AuthResponse struct {
	Token           string    `json:"token"`
	Expires         time.Time `json:"expires"`
	RefreshToken    string    `json:"refresh_token,omitempty"`
	RefreshExpires  time.Time `json:"refresh_expires,omitempty"`
}

type ModifyUserRequest struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	UserRole   int    `json:"userRole"`
	AvatarURL  string `json:"avatarUrl"`
	UserStatus int    `json:"userStatus"`
	Email      string `json:"email"`
	Phone      string `json:"phone"`
	Gender     int    `json:"gender"`
}

type IpLimiter struct {
	Limiter    *rate.Limiter
	LastActive time.Time
}

type JWTSecret struct {
	Secret    string    // 密钥内容
	CreatedAt time.Time // 创建时间
	ExpiresAt time.Time // 过期时间
}

type AppError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

type ImageInfo struct {
	ID          int64  `json:"id"`
	ImageName   string `json:"imageName"`
	ImageURL    string `json:"imageUrl"`
	ImageSize   int64  `json:"imageSize"`
	ContentType string `json:"contentType"`
	UploadTime  string `json:"uploadTime"`
	Owner       string `json:"owner"`
}

type SurveyMediaFile struct {
	ID          int64  `json:"id"`
	FileName    string `json:"fileName"`
	FileURL     string `json:"fileUrl"`
	FileSize    int64  `json:"fileSize"`
	ContentType string `json:"contentType"`
	UploadTime  string `json:"uploadTime"`
}
