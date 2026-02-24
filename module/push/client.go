package push

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Client 个推客户端
type Client struct {
	appID       string
	appKey      string
	appSecret   string
	masterSecret string
	token       string
	tokenExpire int64
	mu          sync.RWMutex
	httpClient  *http.Client
}

// NewClient 创建个推客户端
func NewClient(appID, appKey, appSecret, masterSecret string) *Client {
	return &Client{
		appID:        appID,
		appKey:       appKey,
		appSecret:    appSecret,
		masterSecret: masterSecret,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// AuthRequest 鉴权请求
type AuthRequest struct {
	Sign      string `json:"sign"`
	Timestamp string `json:"timestamp"`
	AppKey    string `json:"appkey"`
}

// AuthResponse 鉴权响应
type AuthResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Token      string `json:"token"`
		ExpireTime string `json:"expire_time"`
	} `json:"data"`
}

// getToken 获取token
func (c *Client) getToken() (string, error) {
	c.mu.RLock()
	now := time.Now().UnixMilli()
	// 如果token存在且未过期（提前30分钟刷新）
	if c.token != "" && c.tokenExpire > now+TokenRefreshBefore {
		token := c.token
		c.mu.RUnlock()
		return token, nil
	}
	c.mu.RUnlock()

	// 需要获取新token
	c.mu.Lock()
	defer c.mu.Unlock()

	// 双重检查
	now = time.Now().UnixMilli()
	if c.token != "" && c.tokenExpire > now+TokenRefreshBefore {
		return c.token, nil
	}

	// 生成签名
	timestamp := fmt.Sprintf("%d", now)
	signStr := c.appKey + timestamp + c.masterSecret
	h := sha256.New()
	h.Write([]byte(signStr))
	sign := hex.EncodeToString(h.Sum(nil))

	// 构造请求
	authReq := AuthRequest{
		Sign:      sign,
		Timestamp: timestamp,
		AppKey:    c.appKey,
	}

	reqBody, err := json.Marshal(authReq)
	if err != nil {
		return "", fmt.Errorf("marshal auth request failed: %w", err)
	}

	url := fmt.Sprintf("%s/%s/%s", BaseURL, c.appID, PathAuth)
	req, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("create auth request failed: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read auth response failed: %w", err)
	}

	var authResp AuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return "", fmt.Errorf("unmarshal auth response failed: %w", err)
	}

	if authResp.Code != 0 {
		return "", fmt.Errorf("auth failed: code=%d, msg=%s", authResp.Code, authResp.Msg)
	}

	c.token = authResp.Data.Token
	// 设置过期时间（当前时间 + 1天 - 30分钟缓冲）
	c.tokenExpire = now + TokenExpireDuration

	return c.token, nil
}

// CommonResponse 通用响应
type CommonResponse struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data,omitempty"`
}

// doRequest 执行HTTP请求
func (c *Client) doRequest(method, path string, body interface{}) (*CommonResponse, error) {
	token, err := c.getToken()
	if err != nil {
		return nil, fmt.Errorf("get token failed: %w", err)
	}

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body failed: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	url := fmt.Sprintf("%s/%s%s", BaseURL, c.appID, path)
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("token", token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response failed: %w", err)
	}

	var commonResp CommonResponse
	if err := json.Unmarshal(respBody, &commonResp); err != nil {
		return nil, fmt.Errorf("unmarshal response failed: %w", err)
	}

	if commonResp.Code != 0 {
		return &commonResp, fmt.Errorf("api error: code=%d, msg=%s", commonResp.Code, commonResp.Msg)
	}

	return &commonResp, nil
}
