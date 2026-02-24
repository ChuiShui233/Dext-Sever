package oauth

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

// 平台回调配置
var platformCallbacks = map[string]string{
	"web":     "https://dext.wucode.xyz/oauth_callback.html",
	"desktop": "dext://oauth/callback",
	"mobile":  "https://dext.wucode.xyz/oauth_callback.html",
	"dev":     "http://localhost:3000/oauth_callback.html",
}

// OAuthCallbackProxy 处理OAuth回调并代理到不同平台
// 路由格式: /api/auth/oauth/callback/:platform
// 例如: /api/auth/oauth/callback/desktop?code=xxx&state=yyy
func OAuthCallbackProxy(c *gin.Context) {
	platform := c.Param("platform")

	// 验证平台参数是否为空
	if platform == "" {
		log.Printf("拒绝连接: 平台参数为空")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// 验证平台参数是否支持
	targetURL, ok := platformCallbacks[platform]
	if !ok {
		log.Printf("拒绝连接: 未知的平台参数 %s", platform)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// 验证目标URL是否配置
	if targetURL == "" {
		log.Printf("拒绝连接: 平台 %s 的目标URL未配置", platform)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// 获取所有查询参数（OAuth提供商返回的code, state等）
	queryParams := c.Request.URL.Query()

	// 检查是否有必要的参数
	code := queryParams.Get("code")
	errorParam := queryParams.Get("error")
	if code == "" && errorParam == "" {
		log.Printf("拒绝连接: OAuth回调缺少必要参数")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// 检查state参数（防止CSRF攻击）
	state := queryParams.Get("state")
	if state == "" {
		log.Printf("拒绝连接: 缺少state参数，可能CSRF攻击")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// 构建目标URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		log.Printf("拒绝连接: 解析目标URL失败 %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// 将所有查询参数附加到目标URL
	parsedURL.RawQuery = queryParams.Encode()
	redirectURL := parsedURL.String()

	// 验证最终URL
	if redirectURL == "" {
		log.Printf("拒绝连接: 构建的重定向URL为空")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	log.Printf("OAuth回调代理: 平台=%s, 目标=%s", platform, redirectURL)

	// 对于自定义协议（dext://），返回HTML页面进行客户端重定向
	if platform == "desktop" {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, generateDesktopRedirectHTML(redirectURL))
		return
	}

	// 对于HTTP(S)协议，使用服务器端302重定向
	c.Redirect(http.StatusFound, redirectURL)
}

// generateDesktopRedirectHTML 生成用于桌面端重定向的HTML页面
func generateDesktopRedirectHTML(redirectURL string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>OAuth授权完成</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
            background-color: #ffffff;
            color: #1a1a1a;
        }
        h1 {
            font-size: 20px;
            font-weight: 500;
            margin: 0 0 8px 0;
        }
        p {
            font-size: 14px;
            color: #666;
            margin: 0;
        }
    </style>
</head>
<body>
    <h1>授权成功</h1>
    <p>正在返回应用...</p>
    <script>
        // 立即尝试打开自定义协议
        window.location.href = "%s";
        
        // 2秒后关闭窗口（如果浏览器允许）
        setTimeout(function() {
            window.close();
        }, 2000);
    </script>
</body>
</html>`, redirectURL)
}

// GetOAuthCallbackURL 获取特定平台的OAuth回调URL
// provider: oauth提供商 (google, github, microsoft)
// platform: 目标平台 (web, desktop, mobile, dev)
func GetOAuthCallbackURL(provider, platform string) string {
	baseURL := "https://wucode.xyz:11222/api/auth/oauth/callback"
	return fmt.Sprintf("%s/%s", baseURL, platform)
}
