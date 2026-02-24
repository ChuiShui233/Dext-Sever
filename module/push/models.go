package push

// Notification 通知消息
type Notification struct {
	Title     string `json:"title"`                // 通知标题
	Body      string `json:"body"`                 // 通知内容
	ClickType string `json:"click_type"`           // 点击类型
	URL       string `json:"url,omitempty"`        // 点击URL
	Intent    string `json:"intent,omitempty"`     // Intent
	Payload   string `json:"payload,omitempty"`    // 自定义内容
	Logo      string `json:"logo,omitempty"`       // 通知图标
	LogoURL   string `json:"logo_url,omitempty"`   // 通知图标URL
}

// PushMessage 推送消息
type PushMessage struct {
	Notification *Notification `json:"notification,omitempty"` // 通知消息
}

// Settings 推送设置
type Settings struct {
	TTL          *int64    `json:"ttl,omitempty"`           // 消息离线时间（毫秒）
	Strategy     *Strategy `json:"strategy,omitempty"`      // 厂商通道策略
	Speed        *int      `json:"speed,omitempty"`         // 定速推送（条/秒）
	ScheduleTime *int64    `json:"schedule_time,omitempty"` // 定时推送时间（毫秒时间戳）
}

// Strategy 厂商通道策略
type Strategy struct {
	Default int `json:"default"` // 1-表示该消息在用户在线时推送个推通道，用户离线时推送厂商通道
}

// Audience 推送目标
type Audience struct {
	CID               []string `json:"cid,omitempty"`                 // CID数组
	Alias             []string `json:"alias,omitempty"`               // 别名数组
	Tag               []Tag    `json:"tag,omitempty"`                 // 标签数组
	FastCustomTag     string   `json:"fast_custom_tag,omitempty"`     // 快速标签
	SmartCrowdTaskID  string   `json:"smart_crowd_task_id,omitempty"` // 文案圈人任务ID
	CrowdID           string   `json:"crowd_id,omitempty"`            // 用户群ID
}

// Tag 标签
type Tag struct {
	Key     string   `json:"key"`      // 查询条件(phone_type/region/custom_tag/portrait)
	Values  []string `json:"values"`   // 查询条件值列表
	OptType string   `json:"opt_type"` // or/and/not
}

// SinglePushRequest 单推请求
type SinglePushRequest struct {
	RequestID   string       `json:"request_id"`          // 请求唯一标识号
	GroupName   string       `json:"group_name,omitempty"` // 任务组名
	Settings    *Settings    `json:"settings,omitempty"`   // 推送设置
	Audience    *Audience    `json:"audience"`             // 推送目标
	PushMessage *PushMessage `json:"push_message"`         // 推送消息
}

// BatchSinglePushRequest 批量单推请求
type BatchSinglePushRequest struct {
	IsAsync bool                 `json:"is_async"`          // 是否异步推送
	MsgList []*SinglePushRequest `json:"msg_list"`          // 消息列表
}

// ListMessageRequest 创建批量推消息请求
type ListMessageRequest struct {
	GroupName   string       `json:"group_name,omitempty"` // 任务组名
	Settings    *Settings    `json:"settings,omitempty"`   // 推送设置
	PushMessage *PushMessage `json:"push_message"`         // 推送消息
}

// ListMessageResponse 创建批量推消息响应
type ListMessageResponse struct {
	TaskID string `json:"taskid"` // 任务ID
}

// ListPushRequest 批量推请求
type ListPushRequest struct {
	Audience        *Audience `json:"audience"`                   // 推送目标
	TaskID          string    `json:"taskid"`                     // 任务ID
	IsAsync         bool      `json:"is_async"`                   // 是否异步推送
	NeedAliasDetail bool      `json:"need_alias_detail,omitempty"` // 是否返回别名详情
}

// AppPushRequest 群推请求
type AppPushRequest struct {
	RequestID   string       `json:"request_id"`           // 请求唯一标识号
	GroupName   string       `json:"group_name,omitempty"` // 任务组名
	Settings    *Settings    `json:"settings,omitempty"`   // 推送设置
	Audience    interface{}  `json:"audience"`             // 推送目标 (string "all" 或 *Audience)
	PushMessage *PushMessage `json:"push_message"`         // 推送消息
}

// PushResponse 推送响应
type PushResponse struct {
	TaskID string `json:"taskid,omitempty"` // 任务ID
	// data字段的具体结构根据不同接口有所不同，这里用map接收
	Details map[string]interface{} `json:"-"` // 详细信息
}
