package oauth

import (
	"os"
)

// OAuth配置结构
type Config struct {
	GoogleClientID     string
	GoogleClientSecret string
	GitHubClientID     string
	GitHubClientSecret string
	MicrosoftClientID  string
	MicrosoftClientSecret string
}

// 从环境变量加载OAuth配置
func LoadConfig() *Config {
	return &Config{
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GitHubClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		MicrosoftClientID:  os.Getenv("MICROSOFT_CLIENT_ID"),
		MicrosoftClientSecret: os.Getenv("MICROSOFT_CLIENT_SECRET"),
	}
}

// 验证配置是否完整
func (c *Config) IsValid() bool {
	return c.GoogleClientID != "" && c.GoogleClientSecret != "" &&
		   c.GitHubClientID != "" && c.GitHubClientSecret != "" &&
		   c.MicrosoftClientID != "" && c.MicrosoftClientSecret != ""
}
