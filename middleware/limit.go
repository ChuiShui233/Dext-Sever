package middleware

import (
	"Dext-Server/model"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// 全局 IP 限流器表
var (
	IpLimiters = struct {
		sync.RWMutex
		m map[string]*model.IpLimiter
	}{
		m: make(map[string]*model.IpLimiter),
	}
)

// 定时清理长时间不用的 limiter
func cleanupLimiters() {
	for {
		time.Sleep(1 * time.Hour)
		IpLimiters.Lock()
		now := time.Now()
		for ip, limiter := range IpLimiters.m {
			if now.Sub(limiter.LastActive) > 2*time.Hour {
				delete(IpLimiters.m, ip)
			}
		}
		IpLimiters.Unlock()
	}
}

// Gin 中间件：限流
func RateLimitMiddleware() gin.HandlerFunc {
	go cleanupLimiters()

	return func(c *gin.Context) {

		ip := c.ClientIP()

		IpLimiters.Lock()
		limiter, exists := IpLimiters.m[ip]
		if !exists {
			limiter = &model.IpLimiter{
				Limiter:    rate.NewLimiter(rate.Limit(109), 190), // 每秒 109 请求，突发 190
				LastActive: time.Now(),
			}
			IpLimiters.m[ip] = limiter
		}
		limiter.LastActive = time.Now()
		IpLimiters.Unlock()

		if !limiter.Limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "请求过于频繁，请稍后再试",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
