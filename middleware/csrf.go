package middleware

import (
	"crypto/subtle"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// CSRFMiddleware provides CSRF protection for cookie-authenticated requests.
//
// It is intentionally configurable to avoid breaking existing clients:
// - CSRF_MODE=off     : disabled (default in non-production)
// - CSRF_MODE=log     : log failures but allow (default in production)
// - CSRF_MODE=enforce : block on failures
//
// Only applies to unsafe methods AND when an access_token cookie is present.
// Header name: X-CSRF-Token, Cookie name: csrf_token.
func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet ||
			c.Request.Method == http.MethodHead ||
			c.Request.Method == http.MethodOptions ||
			c.Request.Method == http.MethodTrace {
			c.Next()
			return
		}

		mode := strings.ToLower(strings.TrimSpace(os.Getenv("CSRF_MODE")))
		if mode == "" {
			if os.Getenv("ENV") == "production" {
				mode = "log"
			} else {
				mode = "off"
			}
		}
		if mode == "off" {
			c.Next()
			return
		}

		// Only protect cookie-authenticated traffic
		if _, err := c.Cookie("access_token"); err != nil {
			c.Next()
			return
		}

		origin := strings.TrimSpace(c.Request.Header.Get("Origin"))
		if origin == "" {
			origin = originFromReferer(c.Request.Referer())
		}

		allowedOrigin := origin != "" && IsOriginAllowed(origin)
		cookieToken, _ := c.Cookie("csrf_token")
		headerToken := strings.TrimSpace(c.GetHeader("X-CSRF-Token"))
		validToken := cookieToken != "" &&
			headerToken != "" &&
			subtle.ConstantTimeCompare([]byte(cookieToken), []byte(headerToken)) == 1

		// In log mode, we only log but allow; in enforce mode we reject.
		if !allowedOrigin || !validToken {
			if mode == "log" {
				log.Printf("[SECURITY] CSRF check failed (mode=log): method=%s path=%s origin=%q allowedOrigin=%v hasCookieToken=%v hasHeaderToken=%v",
					c.Request.Method, c.Request.URL.Path, origin, allowedOrigin, cookieToken != "", headerToken != "")
				c.Next()
				return
			}
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		c.Next()
	}
}

func originFromReferer(referer string) string {
	if referer == "" {
		return ""
	}
	u, err := url.Parse(referer)
	if err != nil {
		return ""
	}
	if u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
