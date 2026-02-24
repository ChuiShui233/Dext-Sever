// 由自动模块化脚本生成 o((>ω< ))o
package model

type User struct {
	ID          string  `json:"id"`                 // 用户ID
	Username    string  `json:"username"`           // 昵称
	Password    string  `json:"password,omitempty"` // 密码（注册时使用）
	UserAccount string  `json:"userAccount"`        // 登录账号
	AvatarURL   *string `json:"avatarUrl"`          // 头像(可选)
	Gender      int     `json:"gender"`             // 性别 0-男 1-女
	Email       string  `json:"email"`              // 邮箱
	UserStatus  int     `json:"userStatus"`         // 用户状态 0-正常
	UserRole    int     `json:"userRole"`           // 用户角色 0-普通用户
	CreatedAt   string  `json:"createdAt"`          // 创建时间
	UpdatedAt   string  `json:"updatedAt"`          // 更新时间
	IsDelete    int     `json:"isDelete"`           // 逻辑删除 0-未删除
}

type UserRegisterRequest struct {
	UserAccount   string `json:"userAccount"`
	Password      string `json:"password" binding:"required"`
	CheckPassword string `json:"checkPassword"`
	Username      string `json:"username" binding:"required"`
	Email         string `json:"email"`
	EmailCode     string `json:"emailCode"` // 邮箱验证码
	CaptchaId     string `json:"captchaId"`
	CaptchaValue  string `json:"captchaValue"`
}

type UserLoginRequest struct {
	UserAccount  string `json:"userAccount" binding:"required"`
	Password     string `json:"password" binding:"required"`
	CaptchaId    string `json:"captchaId"`
	CaptchaValue string `json:"captchaValue"`
	Expiration   string `json:"expiration"` // 可选的自定义过期时间
}

type UserUpdateRequest struct {
	NewUsername string `json:"newUsername" binding:"required,min=2,max=12"`
}

type UserImage struct {
	ID          int64  `json:"id"`
	Owner       string `json:"owner"`
	ImageName   string `json:"imageName"`
	ImageURL    string `json:"imageUrl"`
	ImageSize   int64  `json:"imageSize"`
	ContentType string `json:"contentType"`
	UploadTime  string `json:"uploadTime"`
}
