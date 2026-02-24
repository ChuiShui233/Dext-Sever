package utils

import (
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// 验证URL是否安全
func IsSafeURL(urlStr string) bool {
    // 允许同源相对资源路径（无协议主机），例如由服务端返回的 OpenAssets 相对URL
    if strings.HasPrefix(urlStr, "/openassets/files/") {
        // 严格路径校验，防止 ../ 与重复分隔符
        if strings.Contains(urlStr, "..") || strings.Contains(urlStr, "//") {
            return false
        }
        return true
    }

    // 解析URL
    parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	// 读取环境变量
	env := os.Getenv("ENV")
	if env == "dev" {
		// 开发环境允许本地地址
		host := parsedURL.Hostname()
		if host == "127.0.0.1" || host == "localhost" || host == "0.0.0.0" || host == "::1" {
			return true
		}
	}

	// 检查协议
	allowedSchemes := map[string]bool{
		"http":  true,
		"https": true,
	}
	if !allowedSchemes[parsedURL.Scheme] {
		return false
	}

	// 检查主机名
	host := parsedURL.Hostname()
	if host == "" {
		return false
	}

	// 检查是否是IP地址
	ip := net.ParseIP(host)
	if ip != nil {
		// 检查是否是私有IP地址
		if ip.IsPrivate() || ip.IsLoopback() {
			return true
		}
		// 检查是否是特殊IP地址
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return false
		}
		// 检查是否是保留IP地址
		if ip.IsUnspecified() || ip.IsMulticast() {
			return false
		}
		// 检查是否是文档IP地址
		if ip.Equal(net.ParseIP("192.0.2.0")) || ip.Equal(net.ParseIP("198.51.100.0")) || ip.Equal(net.ParseIP("203.0.113.0")) {
			return false
		}
		// // 检查是否是本地IP地址
		// if ip.Equal(net.ParseIP("127.0.0.1")) || ip.Equal(net.ParseIP("::1")) {
		// 	return false
		// }
	}

	// 检查是否是本地主机名
	localhostNames := []string{
		"localhost",
		"127.0.0.1",
		"::1",
		"0.0.0.0",
		"[::]",
		"local",
	}
	for _, name := range localhostNames {
		if strings.EqualFold(host, name) {
			return false
		}
	}

	// 检查是否是内部域名
	internalDomains := []string{
		".local",
		".internal",
		".intranet",
		".corp",
		".home",
		".lan",
		".localdomain",
		".test",
		".example",
		".invalid",
		".localhost",
		".local",
		".internal",
		".private",
		".home",
		".lan",
		".workgroup",
		".localdomain",
		".arpa",
		".invalid",
		".test",
		".example",
	}
	for _, domain := range internalDomains {
		if strings.HasSuffix(strings.ToLower(host), domain) {
			return false
		}
	}

	// 检查端口
	if parsedURL.Port() != "" {
		port, err := strconv.Atoi(parsedURL.Port())
		if err != nil || port < 1 || port > 65535 {
			return false
		}
		// 检查是否是常用内部服务端口
		internalPorts := []int{
			20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 11222,
		}
		for _, p := range internalPorts {
			if port == p {
				return false
			}
		}
	}

	// 检查路径
	path := parsedURL.Path
	if strings.Contains(path, "..") || strings.Contains(path, "//") {
		return false
	}

	// 检查查询参数
	query := parsedURL.RawQuery
	if strings.Contains(query, "..") || strings.Contains(query, "//") {
		return false
	}

	// 检查是否是云服务元数据URL
	metadataPaths := []string{
		"/latest/meta-data/",
		"/metadata/",
		"/computeMetadata/",
		"/instance/",
		"/cloud/",
		"/aws/",
		"/azure/",
		"/gcp/",
		"/aliyun/",
		"/tencent/",
	}
	for _, path := range metadataPaths {
		if strings.HasPrefix(strings.ToLower(parsedURL.Path), path) {
			return false
		}
	}

	return true
}
