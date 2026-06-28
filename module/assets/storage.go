package assets

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"
)

// StorageBackend 抽象文件存储层。local 与 github 两个实现共享同一个本地缓存目录；
// github 实现额外通过 GitHub Contents API 上传/删除，通过 jsDelivr CDN 下载。
type StorageBackend interface {
	// Put 将 fileData 写入存储，返回写入字节数。
	Put(bucket, filename string, fileData io.Reader) (int64, error)
	// Get 确保文件在本地可用并返回本地绝对路径。
	// github 后端在缓存未命中时从 CDN 拉取并回填本地缓存。
	Get(bucket, filename string) (string, error)
	// Delete 从存储中删除文件（github 后端同时删除远端）。
	Delete(bucket, filename string) error
	// Stat 检查文件是否存在于本地缓存。
	Stat(bucket, filename string) (bool, error)
	// LocalPath 返回本地缓存绝对路径（不保证文件存在）。
	LocalPath(bucket, filename string) (string, error)
	// DiskAuthoritative 返回 true 表示本地磁盘是权威存储（local），
	// 返回 false 表示本地磁盘仅是缓存（github）。
	DiskAuthoritative() bool
}

// ---------- 共享路径解析 ----------

func backendResolvePath(storagePath, bucket, filename string) (string, error) {
	if !isSafeBucketName(bucket) {
		return "", fmt.Errorf("invalid bucket")
	}
	if !isSafeFileName(filename) {
		return "", fmt.Errorf("invalid filename")
	}
	baseAbs, err := filepath.Abs(storagePath)
	if err != nil {
		return "", fmt.Errorf("resolve storage path failed: %w", err)
	}
	targetAbs, err := filepath.Abs(filepath.Join(baseAbs, bucket, filename))
	if err != nil {
		return "", fmt.Errorf("resolve file path failed: %w", err)
	}
	prefix := baseAbs + string(os.PathSeparator)
	if targetAbs != baseAbs && !strings.HasPrefix(targetAbs, prefix) {
		return "", fmt.Errorf("path escapes storage root")
	}
	return targetAbs, nil
}

// ---------- 本地存储后端 ----------

type localStorage struct {
	storagePath string
}

func newLocalStorage(storagePath string) *localStorage {
	return &localStorage{storagePath: storagePath}
}

func (l *localStorage) LocalPath(bucket, filename string) (string, error) {
	return backendResolvePath(l.storagePath, bucket, filename)
}

func (l *localStorage) Put(bucket, filename string, fileData io.Reader) (int64, error) {
	filePath, err := l.LocalPath(bucket, filename)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return 0, fmt.Errorf("create bucket dir failed: %w", err)
	}
	dst, err := os.Create(filePath)
	if err != nil {
		return 0, fmt.Errorf("create file failed: %w", err)
	}
	defer dst.Close()
	written, err := io.Copy(dst, fileData)
	if err != nil {
		os.Remove(filePath)
		return 0, fmt.Errorf("write file failed: %w", err)
	}
	return written, nil
}

func (l *localStorage) Get(bucket, filename string) (string, error) {
	filePath, err := l.LocalPath(bucket, filename)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return "", fmt.Errorf("file not found")
	}
	return filePath, nil
}

func (l *localStorage) Delete(bucket, filename string) error {
	filePath, err := l.LocalPath(bucket, filename)
	if err != nil {
		return err
	}
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete file failed: %w", err)
	}
	return nil
}

func (l *localStorage) Stat(bucket, filename string) (bool, error) {
	filePath, err := l.LocalPath(bucket, filename)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(filePath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (l *localStorage) DiskAuthoritative() bool { return true }

// ---------- GitHub 存储后端 ----------

// GitHubConfig 是 GitHub 图床的配置。
type GitHubConfig struct {
	Token       string // GitHub Personal Access Token（需 repo 权限）
	Owner       string // GitHub 用户名
	Repo        string // 仓库名
	Branch      string // 分支名（默认 main）
	CDNDomain   string // jsDelivr CDN 域名（默认 cdn.jsdelivr.net）
	StoragePath string // 本地缓存目录（与 Config.StoragePath 相同）
}

type githubStorage struct {
	cfg     GitHubConfig
	local   *localStorage
	sfGroup singleflight.Group
	http    *http.Client
}

func newGitHubStorage(cfg GitHubConfig) (*githubStorage, error) {
	if cfg.Token == "" || cfg.Owner == "" || cfg.Repo == "" {
		return nil, fmt.Errorf("GitHub 配置不完整: 需要 token/owner/repo")
	}
	if cfg.Branch == "" {
		cfg.Branch = "main"
	}
	if cfg.CDNDomain == "" {
		cfg.CDNDomain = "cdn.jsdelivr.net"
	}
	if cfg.StoragePath == "" {
		return nil, fmt.Errorf("StoragePath 不能为空")
	}
	return &githubStorage{
		cfg:   cfg,
		local: newLocalStorage(cfg.StoragePath),
		http:  &http.Client{Timeout: 120 * time.Second},
	}, nil
}

func (g *githubStorage) LocalPath(bucket, filename string) (string, error) {
	return g.local.LocalPath(bucket, filename)
}

func (g *githubStorage) DiskAuthoritative() bool { return false }

// Put 先写入本地缓存，再异步推送到 GitHub。
func (g *githubStorage) Put(bucket, filename string, fileData io.Reader) (int64, error) {
	written, err := g.local.Put(bucket, filename, fileData)
	if err != nil {
		return 0, err
	}
	// 异步推送，不阻塞上传响应
	go g.pushToGitHub(bucket, filename)
	return written, nil
}

// Get 优先读本地缓存；缓存未命中时从 jsDelivr CDN 拉取并回填。
// 使用 singleflight 确保同一文件的并发请求只触发一次远端拉取。
func (g *githubStorage) Get(bucket, filename string) (string, error) {
	filePath, err := g.local.LocalPath(bucket, filename)
	if err != nil {
		return "", err
	}
	// 快速路径：本地缓存命中
	if exists, _ := g.local.Stat(bucket, filename); exists {
		return filePath, nil
	}

	// 缓存未命中：通过 singleflight 去重并发拉取
	sfKey := bucket + "/" + filename
	_, err, _ = g.sfGroup.Do(sfKey, func() (interface{}, error) {
		// 双重检查：拿到锁后再次确认
		if exists, _ := g.local.Stat(bucket, filename); exists {
			return nil, nil
		}
		if shouldLog() {
			log.Printf("[GitHubStorage] 缓存未命中，从 CDN 拉取: %s/%s", bucket, filename)
		}
		cdnURL := fmt.Sprintf("https://%s/gh/%s/%s@%s/%s/%s",
			g.cfg.CDNDomain, g.cfg.Owner, g.cfg.Repo, g.cfg.Branch, bucket, filename)
		resp, err := g.http.Get(cdnURL)
		if err != nil {
			return nil, fmt.Errorf("CDN 拉取失败: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("CDN 返回 %d", resp.StatusCode)
		}
		if _, err := g.local.Put(bucket, filename, resp.Body); err != nil {
			return nil, fmt.Errorf("写入本地缓存失败: %w", err)
		}
		if shouldLog() {
			log.Printf("[GitHubStorage] 已从 CDN 缓存: %s/%s", bucket, filename)
		}
		return nil, nil
	})
	if err != nil {
		return "", err
	}
	return filePath, nil
}

// Delete 先从 GitHub 删除（需要 sha），再删除本地缓存。
func (g *githubStorage) Delete(bucket, filename string) error {
	path := fmt.Sprintf("%s/%s", bucket, filename)
	if sha := g.getFileSHA(path); sha != "" {
		g.deleteFromGitHub(path, sha)
	}
	return g.local.Delete(bucket, filename)
}

func (g *githubStorage) Stat(bucket, filename string) (bool, error) {
	return g.local.Stat(bucket, filename)
}

// ---------- GitHub Contents API 调用 ----------

func (g *githubStorage) pushToGitHub(bucket, filename string) {
	filePath, err := g.local.LocalPath(bucket, filename)
	if err != nil {
		log.Printf("[GitHubStorage] 解析路径失败: %v", err)
		return
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("[GitHubStorage] 读取本地文件失败: %v", err)
		return
	}

	path := fmt.Sprintf("%s/%s", bucket, filename)
	sha := g.getFileSHA(path)

	content := base64.StdEncoding.EncodeToString(data)
	body := map[string]interface{}{
		"message": fmt.Sprintf("upload %s", path),
		"content": content,
		"branch":  g.cfg.Branch,
	}
	if sha != "" {
		body["sha"] = sha
	}
	bodyJSON, _ := json.Marshal(body)

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", g.cfg.Owner, g.cfg.Repo, path)
	req, err := http.NewRequest("PUT", url, bytes.NewReader(bodyJSON))
	if err != nil {
		log.Printf("[GitHubStorage] 创建请求失败: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+g.cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.http.Do(req)
	if err != nil {
		log.Printf("[GitHubStorage] 推送失败: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("[GitHubStorage] 推送失败: HTTP %d: %s", resp.StatusCode, string(respBody))
		return
	}
	if shouldLog() {
		log.Printf("[GitHubStorage] 已推送到 GitHub: %s", path)
	}
}

func (g *githubStorage) getFileSHA(path string) string {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s?ref=%s",
		g.cfg.Owner, g.cfg.Repo, path, g.cfg.Branch)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+g.cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := g.http.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}
	if sha, ok := result["sha"].(string); ok {
		return sha
	}
	return ""
}

func (g *githubStorage) deleteFromGitHub(path, sha string) {
	body := map[string]interface{}{
		"message": fmt.Sprintf("delete %s", path),
		"sha":     sha,
		"branch":  g.cfg.Branch,
	}
	bodyJSON, _ := json.Marshal(body)
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", g.cfg.Owner, g.cfg.Repo, path)
	req, err := http.NewRequest("DELETE", url, bytes.NewReader(bodyJSON))
	if err != nil {
		log.Printf("[GitHubStorage] 创建删除请求失败: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+g.cfg.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.http.Do(req)
	if err != nil {
		log.Printf("[GitHubStorage] 删除失败: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("[GitHubStorage] 删除失败: HTTP %d: %s", resp.StatusCode, string(respBody))
		return
	}
	if shouldLog() {
		log.Printf("[GitHubStorage] 已从 GitHub 删除: %s", path)
	}
}
