package push

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"
)

// generateRequestID 生成请求ID（10-32位）
func generateRequestID() string {
	// 使用时间戳 + 随机数生成唯一ID
	timestamp := time.Now().UnixNano()
	random := rand.Int63()
	return fmt.Sprintf("req_%d_%d", timestamp, random)
}

// parsePushResponse 解析推送响应
func parsePushResponse(resp *CommonResponse) (*PushResponse, error) {
	var result PushResponse
	
	// 尝试解析data字段
	if len(resp.Data) > 0 {
		var data map[string]interface{}
		if err := json.Unmarshal(resp.Data, &data); err != nil {
			return nil, fmt.Errorf("unmarshal response data failed: %w", err)
		}
		
		// 提取taskid
		if taskID, ok := data["taskid"].(string); ok {
			result.TaskID = taskID
		}
		
		result.Details = data
	}
	
	return &result, nil
}

// DefaultSettings 创建默认推送设置
func DefaultSettings() *Settings {
	ttl := int64(DefaultTTL)
	return &Settings{
		TTL: &ttl,
		Strategy: &Strategy{
			Default: 1,
		},
	}
}

// ScheduledSettings 创建定时推送设置
func ScheduledSettings(scheduleTime time.Time, ttl int64) *Settings {
	scheduleMillis := scheduleTime.UnixMilli()
	if ttl == 0 {
		ttl = DefaultTTL
	}
	return &Settings{
		TTL:          &ttl,
		ScheduleTime: &scheduleMillis,
		Strategy: &Strategy{
			Default: 1,
		},
	}
}

// SpeedLimitSettings 创建限速推送设置
func SpeedLimitSettings(speed int, ttl int64) *Settings {
	if ttl == 0 {
		ttl = DefaultTTL
	}
	return &Settings{
		TTL:   &ttl,
		Speed: &speed,
		Strategy: &Strategy{
			Default: 1,
		},
	}
}
