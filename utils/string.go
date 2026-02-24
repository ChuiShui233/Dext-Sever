package utils

import (
	"fmt"
	"html"
	"path/filepath"
	"regexp"
	"strings"
)

// 检查字符串是否包含危险字符
func ContainsDangerousChars(s string) bool {
	// 检查是否包含HTML标签
	htmlTagRegex := regexp.MustCompile(`<[^>]*>`)
	if htmlTagRegex.MatchString(s) {
		return true
	}

	// 检查是否包含JavaScript协议（包括各种编码形式）
	jsProtocols := []string{
		"javascript:", "data:", "vbscript:", "file:", "about:", "blob:",
		"&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:",           // javascript: 的 HTML 实体编码
		"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:",              // javascript: 的十进制编码
		"%6A%61%76%61%73%63%72%69%70%74:",                                         // javascript: 的 URL 编码
		"\\u006A\\u0061\\u0076\\u0061\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074:", // javascript: 的 Unicode 转义
		"&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:",           // 小写形式
		"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:",              // 小写形式
		"%6a%61%76%61%73%63%72%69%70%74:",                                         // 小写形式
	}

	for _, protocol := range jsProtocols {
		if strings.Contains(strings.ToLower(s), protocol) {
			return true
		}
	}

	// 检查是否包含其他危险字符
	dangerousChars := []string{
		"&#x3C;", "&#x3E;", // HTML 实体编码的尖括号
		"&#60;", "&#62;", // 十进制 HTML 实体编码的尖括号
		"&lt;", "&gt;", // 命名的 HTML 实体
		"\\u003C", "\\u003E", // Unicode 转义
		"%3C", "%3E", // URL 编码
		"\\x3C", "\\x3E", // 十六进制转义
		"\\074", "\\076", // 八进制转义
		"&#x3c;", "&#x3e;", // 小写形式
		"&#60;", "&#62;", // 小写形式
		"\\u003c", "\\u003e", // 小写形式
		"%3c", "%3e", // 小写形式
		"\\x3c", "\\x3e", // 小写形式
		"\\074", "\\076", // 小写形式
	}

	// 检查原始字符串
	for _, char := range dangerousChars {
		if strings.Contains(strings.ToLower(s), char) {
			return true
		}
	}

	// 检查HTML解码后的字符串
	decoded := html.UnescapeString(s)
	if decoded != s {
		// 如果解码后的字符串与原始字符串不同，再次检查
		for _, char := range dangerousChars {
			if strings.Contains(strings.ToLower(decoded), char) {
				return true
			}
		}
	}

	// 检查是否包含事件处理器
	eventHandlers := []string{
		"onload", "onerror", "onclick", "onmouseover", "onmouseout",
		"onkeydown", "onkeyup", "onkeypress", "onsubmit", "onchange",
		"onfocus", "onblur", "onresize", "onscroll", "onunload",
	}

	for _, handler := range eventHandlers {
		if strings.Contains(strings.ToLower(s), handler) {
			return true
		}
	}

	return false
}

// 检查字符串是否包含URL
func ContainsURL(s string) bool {
	urlRegex := regexp.MustCompile(`(?i)(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]*[-A-Za-z0-9+&@#/%=~_|]`)
	return urlRegex.MatchString(s)
}

// 从字符串中提取所有URL
func ExtractURLs(s string) []string {
	urlRegex := regexp.MustCompile(`(?i)(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]*[-A-Za-z0-9+&@#/%=~_|]`)
	return urlRegex.FindAllString(s, -1)
}

// 根据文件扩展名获取MIME类型
func GetContentTypeByExtension(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	// 扩展名到MIME类型的映射
	mimeTypes := map[string]string{
		".jpeg": "image/jpeg",
		".jpg":  "image/jpeg",
		".png":  "image/png",
		".gif":  "image/gif",
		".webp": "image/webp",
		".bmp":  "image/bmp",
		".tiff": "image/tiff",
		".svg":  "image/svg+xml",
		".ico":  "image/ico",
		".heic": "image/heic",
		".heif": "image/heif",
		".avif": "image/avif",
		".jxl":  "image/jxl",
		".mp4":  "video/mp4",
		".webm": "video/webm",
		".avi":  "video/avi",
		".mov":  "video/quicktime",
		".wmv":  "video/x-ms-wmv",
		".flv":  "video/x-flv",
		".mkv":  "video/x-matroska",
		".3gp":  "video/3gpp",
		".mp3":  "audio/mpeg",
		".mpeg": "audio/mpeg",
		".wav":  "audio/wav",
		".ogg":  "audio/ogg",
		".aac":  "audio/aac",
		".flac": "audio/flac",
		".wma":  "audio/x-ms-wma",
	}
	if mime, ok := mimeTypes[ext]; ok {
		return mime
	}
	return "application/octet-stream" // 如果找不到则返回默认二进制流类型
}

// 安全过滤函数
func SanitizeInput(input string) string {
	// 先解码 HTML 实体
	decoded := html.UnescapeString(input)

	// 移除所有 HTML 标签和属性
	re := regexp.MustCompile(`<[^>]*>`)
	cleaned := re.ReplaceAllString(decoded, "")

	// 移除所有 JavaScript 事件处理器
	eventHandlers := []string{
		"onload", "onerror", "onclick", "onmouseover", "onmouseout",
		"onkeydown", "onkeyup", "onkeypress", "onsubmit", "onchange",
		"onfocus", "onblur", "onresize", "onscroll", "onunload",
	}
	for _, handler := range eventHandlers {
		pattern := fmt.Sprintf(`%s\s*=\s*["'][^"']*["']`, handler)
		re := regexp.MustCompile(pattern)
		cleaned = re.ReplaceAllString(cleaned, "")
	}

	// 移除危险协议（包括各种编码形式）
	dangerousProtocols := []string{
		"javascript:", "data:", "vbscript:", "file:", "about:", "blob:",
		"&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:",           // javascript: 的 HTML 实体编码
		"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:",              // javascript: 的十进制编码
		"%6A%61%76%61%73%63%72%69%70%74:",                                         // javascript: 的 URL 编码
		"\\u006A\\u0061\\u0076\\u0061\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074:", // javascript: 的 Unicode 转义
		"&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:",           // 小写形式
		"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:",              // 小写形式
		"%6a%61%76%61%73%63%72%69%70%74:",                                         // 小写形式
	}

	for _, protocol := range dangerousProtocols {
		cleaned = strings.ReplaceAll(strings.ToLower(cleaned), protocol, "")
	}

	// 移除其他可能的 XSS 向量
	xssVectors := []string{
		"&#x3C;", "&#x3E;", // HTML 实体编码的尖括号
		"&#60;", "&#62;", // 十进制 HTML 实体编码的尖括号
		"&lt;", "&gt;", // 命名的 HTML 实体
		"\\u003C", "\\u003E", // Unicode 转义
		"%3C", "%3E", // URL 编码
		"\\x3C", "\\x3E", // 十六进制转义
		"\\074", "\\076", // 八进制转义
		"&#x3c;", "&#x3e;", // 小写形式
		"&#60;", "&#62;", // 小写形式
		"\\u003c", "\\u003e", // 小写形式
		"%3c", "%3e", // 小写形式
		"\\x3c", "\\x3e", // 小写形式
		"\\074", "\\076", // 小写形式
		"expression(", "eval(", "setTimeout(", "setInterval(", // JavaScript 函数
		"document.cookie", "document.write", "window.location", // DOM 操作
		"<script", "</script>", // 脚本标签
		"<img", "<svg", "<iframe", "<frame", // 危险标签
		"src=", "href=", // 危险属性
	}

	for _, vector := range xssVectors {
		cleaned = strings.ReplaceAll(strings.ToLower(cleaned), vector, "")
	}

	// 转义 HTML 特殊字符
	escaped := html.EscapeString(cleaned)

	// 移除多余的空格
	escaped = strings.TrimSpace(escaped)

	return escaped
}
