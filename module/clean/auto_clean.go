package clean

import (
	"Dext-Server/config"
	"database/sql"
	"log"
	"time"
)

// AutoCleaner 自动清理器
type AutoCleaner struct {
	cleaner     *Cleaner
	interval    time.Duration
	enabled     bool
	lastCleanup time.Time
}

// NewAutoCleaner 创建自动清理器
func NewAutoCleaner(db *sql.DB, interval time.Duration, enabled bool) *AutoCleaner {
	return &AutoCleaner{
		cleaner:  NewCleaner(db),
		interval: interval,
		enabled:  enabled,
	}
}

// Start 启动自动清理
func (a *AutoCleaner) Start() {
	if !a.enabled {
		log.Printf("[AutoCleaner] 自动清理功能已禁用")
		return
	}

	log.Printf("[AutoCleaner] 启动自动清理，间隔: %v", a.interval)

	// 立即执行一次清理
	a.runCleanup()

	// 启动定时器
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()

	// 使用for range遍历ticker通道
	for range ticker.C {
		a.runCleanup()
	}
}

// runCleanup 执行清理
func (a *AutoCleaner) runCleanup() {
	log.Printf("[AutoCleaner] 开始自动清理")

	startTime := time.Now()

	if err := a.cleaner.RunFullCleanup(); err != nil {
		log.Printf("[AutoCleaner] 自动清理失败: %v", err)
	} else {
		a.lastCleanup = time.Now()
		duration := time.Since(startTime)
		log.Printf("[AutoCleaner] 自动清理完成，耗时: %v", duration)
	}
}

// GetStatus 获取状态
func (a *AutoCleaner) GetStatus() map[string]interface{} {
	return map[string]interface{}{
		"enabled":     a.enabled,
		"interval":    a.interval.String(),
		"lastCleanup": a.lastCleanup.Format(time.RFC3339),
		"nextCleanup": a.lastCleanup.Add(a.interval).Format(time.RFC3339),
	}
}

// StartAutoCleanupOnBoot 系统启动时启动自动清理
func StartAutoCleanupOnBoot() {
	// 默认配置：每天执行一次清理
	interval := 24 * time.Hour
	enabled := true // 可以根据配置文件调整

	autoCleaner := NewAutoCleaner(config.DB, interval, enabled)

	// 在后台启动自动清理
	go autoCleaner.Start()
}
