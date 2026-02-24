package push

const (
	// 个推API基础地址
	BaseURL = "https://restapi.getui.com/v2"
	
	// API路径
	PathAuth           = "/auth"                         // 获取token
	PathPushSingleCid  = "/push/single/cid"             // CID单推
	PathPushSingleAlias = "/push/single/alias"          // 别名单推
	PathPushBatchCid   = "/push/single/batch/cid"       // CID批量单推
	PathPushBatchAlias = "/push/single/batch/alias"     // 别名批量单推
	PathPushListMsg    = "/push/list/message"           // 创建批量推消息
	PathPushListCid    = "/push/list/cid"               // 执行CID批量推
	PathPushListAlias  = "/push/list/alias"             // 执行别名批量推
	PathPushAll        = "/push/all"                    // 群推所有用户
	PathPushTag        = "/push/tag"                    // 按条件筛选推送
	PathPushFastTag    = "/push/fast_custom_tag"        // 标签快速推送
	PathTaskStop       = "/task"                        // 停止任务
	PathTaskSchedule   = "/task/schedule"               // 定时任务管理
	PathTaskDetail     = "/task/detail"                 // 查询消息明细
	
	// Token过期时间（毫秒），官方为1天，提前30分钟刷新
	TokenExpireDuration = 24 * 60 * 60 * 1000          // 1天
	TokenRefreshBefore  = 30 * 60 * 1000               // 提前30分钟
	
	// 默认消息离线时间（毫秒）
	DefaultTTL = 2 * 60 * 60 * 1000                    // 2小时
	
	// 推送状态
	StatusSuccessedOffline = "successed_offline"        // 离线下发
	StatusSuccessedOnline  = "successed_online"         // 在线下发
	StatusSuccessedIgnore  = "successed_ignore"         // 不活跃用户不下发
)

// 点击类型
const (
	ClickTypeIntent    = "intent"    // 打开应用内特定页面
	ClickTypeURL       = "url"       // 打开网页
	ClickTypePayload   = "payload"   // 自定义消息内容
	ClickTypeStartApp  = "startapp"  // 打开应用首页
	ClickTypeNone      = "none"      // 不做任何操作
)
