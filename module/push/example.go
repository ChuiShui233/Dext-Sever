package push

import (
	"fmt"
	"log"
	"time"
)

// ExamplePushSingleByCID 单推示例（通过CID）
func ExamplePushSingleByCID() {
	client := NewClient(
		"your_app_id",
		"your_app_key",
		"your_app_secret",
		"your_master_secret",
	)

	resp, err := client.PushSingleByCID(
		"user_cid_123",
		"消息标题",
		"消息内容",
		ClickTypeURL,
		"https://wucode.xyz",
	)
	if err != nil {
		log.Printf("推送失败: %v", err)
		return
	}

	log.Printf("推送成功, TaskID: %s", resp.TaskID)
}

// ExamplePushSingleByAlias 单推示例（通过别名）
func ExamplePushSingleByAlias() {
	client := NewClient(
		"your_app_id",
		"your_app_key",
		"your_app_secret",
		"your_master_secret",
	)

	// 别名通常绑定为用户ID
	resp, err := client.PushSingleByAlias(
		"user_id_456",
		"消息标题",
		"消息内容",
		ClickTypeStartApp,
		"",
	)
	if err != nil {
		log.Printf("推送失败: %v", err)
		return
	}

	log.Printf("推送成功, TaskID: %s", resp.TaskID)
}

// ExampleBatchPush 批量推示例
func ExampleBatchPush() {
	client := NewClient(
		"your_app_id",
		"your_app_key",
		"your_app_secret",
		"your_master_secret",
	)

	// 方式1: 批量单推（每个用户消息内容不同）
	messages := []*SinglePushRequest{
		{
			Audience: &Audience{CID: []string{"cid1"}},
			PushMessage: &PushMessage{
				Notification: &Notification{
					Title:     "用户1专属消息",
					Body:      "您有新的订单",
					ClickType: ClickTypeURL,
					URL:       "https://wucode.xyz/order/123",
				},
			},
		},
		{
			Audience: &Audience{CID: []string{"cid2"}},
			PushMessage: &PushMessage{
				Notification: &Notification{
					Title:     "用户2专属消息",
					Body:      "您的问卷已完成",
					ClickType: ClickTypeURL,
					URL:       "https://wucode.xyz/survey/456",
				},
			},
		},
	}

	resp, err := client.PushBatchByCID(messages, true) // true表示异步
	if err != nil {
		log.Printf("批量推送失败: %v", err)
		return
	}

	log.Printf("批量推送成功, TaskID: %s", resp.TaskID)

	// 方式2: 批量推（所有用户消息内容相同）
	// 第一步：创建消息模板
	taskID, err := client.CreateListMessage(
		"统一消息标题",
		"统一消息内容",
		ClickTypeURL,
		"https://wucode.xyz",
		DefaultSettings(),
	)
	if err != nil {
		log.Printf("创建消息失败: %v", err)
		return
	}

	// 第二步：使用模板推送给多个用户
	cids := []string{"cid1", "cid2", "cid3", "cid4", "cid5"}
	resp2, err := client.PushListByCID(taskID, cids, false) // false表示同步
	if err != nil {
		log.Printf("批量推送失败: %v", err)
		return
	}

	log.Printf("批量推送成功: %+v", resp2.Details)
}

// ExampleScheduledPush 定时推送示例
func ExampleScheduledPush() {
	client := NewClient(
		"your_app_id",
		"your_app_key",
		"your_app_secret",
		"your_master_secret",
	)

	// 定时在1小时后推送
	scheduleTime := time.Now().Add(1 * time.Hour)
	settings := ScheduledSettings(scheduleTime, DefaultTTL)

	resp, err := client.PushToAll(
		"定时消息标题",
		"这是一条定时推送的消息",
		ClickTypeURL,
		"https://wucode.xyz",
		settings,
	)
	if err != nil {
		log.Printf("定时推送失败: %v", err)
		return
	}

	log.Printf("定时推送任务创建成功, TaskID: %s", resp.TaskID)

	// 可以查询定时任务状态
	taskResp, err := client.GetScheduleTask(resp.TaskID)
	if err != nil {
		log.Printf("查询定时任务失败: %v", err)
		return
	}

	log.Printf("定时任务状态: %+v", taskResp)

	// 如果需要取消定时任务
	// err = client.DeleteScheduleTask(resp.TaskID)
}

// ExamplePushByTag 按条件推送示例
func ExamplePushByTag() {
	client := NewClient(
		"your_app_id",
		"your_app_key",
		"your_app_secret",
		"your_master_secret",
	)

	// 推送给所有Android用户，且在北京的用户
	tags := []Tag{
		{
			Key:     "phone_type",
			Values:  []string{"android"},
			OptType: "or",
		},
		{
			Key:     "region",
			Values:  []string{"11000000"}, // 北京地区代码
			OptType: "and",
		},
	}

	resp, err := client.PushByTag(
		tags,
		"地区定向消息",
		"您所在地区的专属活动",
		ClickTypeURL,
		"https://wucode.xyz/event",
		DefaultSettings(),
	)
	if err != nil {
		log.Printf("按条件推送失败: %v", err)
		return
	}

	log.Printf("按条件推送成功, TaskID: %s", resp.TaskID)
}

// ExampleSpeedLimitPush 限速推送示例
func ExampleSpeedLimitPush() {
	client := NewClient(
		"your_app_id",
		"your_app_key",
		"your_app_secret",
		"your_master_secret",
	)

	// 以每秒100条的速度推送
	settings := SpeedLimitSettings(100, DefaultTTL)

	resp, err := client.PushToAll(
		"限速推送消息",
		"这是一条限速推送的消息",
		ClickTypeStartApp,
		"",
		settings,
	)
	if err != nil {
		log.Printf("限速推送失败: %v", err)
		return
	}

	log.Printf("限速推送成功, TaskID: %s", resp.TaskID)
}

// ExampleIntegration 实际业务集成示例
func ExampleIntegration() {
	// 1. 初始化客户端（通常在应用启动时初始化一次）
	pushClient := NewClient(
		"cy0d7CICux7YKvteM5cy87",
		"your_app_key",
		"your_app_secret",
		"your_master_secret",
	)

	// 2. 用户登录后，前端会通过个推SDK获取CID并上报给后端
	// 后端将CID与用户ID关联存储到数据库
	userID := "user123"
	cid := "received_cid_from_client"
	_ = saveCIDToDatabase(userID, cid)

	// 3. 业务事件触发推送
	// 例如：问卷审核通过后通知用户
	surveyName := "客户满意度调查"
	go func() {
		// 从数据库获取用户的CID
		userCID, err := getCIDFromDatabase(userID)
		if err != nil {
			log.Printf("获取用户CID失败: %v", err)
			return
		}

		// 发送推送
		_, err = pushClient.PushSingleByCID(
			userCID,
			"问卷审核通过",
			fmt.Sprintf("您的问卷《%s》已通过审核", surveyName),
			ClickTypeURL,
			"https://wucode.xyz/?id=survey123",
		)
		if err != nil {
			log.Printf("推送失败: %v", err)
			return
		}

		log.Printf("推送成功发送给用户: %s", userID)
	}()
}

// 模拟数据库操作
func saveCIDToDatabase(_, _ string) error {
	// 实际实现中应该保存到数据库
	// UPDATE users SET push_cid = ? WHERE user_id = ?
	return nil
}

func getCIDFromDatabase(_ string) (string, error) {
	// 实际实现中应该从数据库查询
	// SELECT push_cid FROM users WHERE user_id = ?
	return "mock_cid", nil
}
