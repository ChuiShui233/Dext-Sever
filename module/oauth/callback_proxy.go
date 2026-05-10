package oauth

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

// 平台回调配置
var platformCallbacks = map[string]string{
	"web":     "https://qs.chuishui.top/oauth_callback",
	"desktop": "dext://oauth/callback",
	"mobile":  "https://qs.chuishui.top/oauth_callback",
	"dev":     "http://localhost:3000/oauth_callback",
}

// OAuthCallbackProxy 处理OAuth回调并代理到不同平台
// 路由格式: /api/auth/oauth/callback/:platform
// 例如: /api/auth/oauth/callback/desktop?code=xxx&state=yyy
func OAuthCallbackProxy(c *gin.Context) {
	platform := c.Param("platform")

	// 验证平台参数是否为空
	if platform == "" {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// 验证平台参数是否支持
	targetURL, ok := platformCallbacks[platform]
	if !ok {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// 验证目标URL是否配置
	if targetURL == "" {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// 获取所有查询参数（OAuth提供商返回的code, state等）
	queryParams := c.Request.URL.Query()

	// 检查是否有必要的参数
	code := queryParams.Get("code")
	errorParam := queryParams.Get("error")
	if code == "" && errorParam == "" {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// 检查state参数（防止CSRF攻击）- 移动端不需要state，因为使用自定义scheme直接回调
	state := queryParams.Get("state")
	if platform != "mobile" && state == "" {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// 构建目标URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// 将所有查询参数附加到目标URL
	parsedURL.RawQuery = queryParams.Encode()
	redirectURL := parsedURL.String()

	// 验证最终URL
	if redirectURL == "" {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// 对于桌面平台，使用HTML页面进行重定向
	if platform == "desktop" {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, generateDesktopRedirectHTML(redirectURL))
		return
	}

	// 对于移动端平台，使用HTML页面让WebView提取参数，然后重定向到自定义scheme
	if platform == "mobile" {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, generateMobileRedirectHTML())
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

// generateMobileRedirectHTML 生成用于移动端WebView重定向的HTML页面
func generateMobileRedirectHTML() string {
	return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>OAuth授权完成</title>
</head>
<body>
    <h1>授权成功</h1>
    <p>正在返回应用...</p>
    <script>
        // 从当前URL获取OAuth参数
        var url = window.location.href;
        var params = {};
        var queryString = url.split('?')[1];
        if (queryString) {
            var pairs = queryString.split('&');
            for (var i = 0; i < pairs.length; i++) {
                var pair = pairs[i].split('=');
                params[decodeURIComponent(pair[0])] = decodeURIComponent(pair[1] || '');
            }
        }

        // 构建dext://回调URL
        var callbackUrl = 'dext://oauth/callback';
        if (Object.keys(params).length > 0) {
            var queryParts = [];
            for (var key in params) {
                queryParts.push(encodeURIComponent(key) + '=' + encodeURIComponent(params[key]));
            }
            callbackUrl += '?' + queryParts.join('&');
        }

        // 使用iframe尝试打开自定义scheme
        var iframe = document.createElement('iframe');
        iframe.src = callbackUrl;
        iframe.style.display = 'none';
        document.body.appendChild(iframe);

        // 同时尝试window.location作为后备
        setTimeout(function() {
            window.location.href = callbackUrl;
        }, 100);
    </script>
</body>
</html>`
}

// GetOAuthCallbackURL 获取特定平台的OAuth回调URL
// provider: oauth提供商 (google, github, microsoft)
// platform: 目标平台 (web, desktop, mobile, dev)
func GetOAuthCallbackURL(provider, platform string) string {
	baseURL := "https://server.chuishui.top:11222/api/auth/oauth/callback"
	return fmt.Sprintf("%s/%s", baseURL, platform)
}
