package push

import (
	"encoding/json"
	"fmt"
)

// PushSingleByCID 通过CID单推
func (c *Client) PushSingleByCID(cid, title, body, clickType, url string) (*PushResponse, error) {
	req := &SinglePushRequest{
		RequestID: generateRequestID(),
		Audience: &Audience{
			CID: []string{cid},
		},
		PushMessage: &PushMessage{
			Notification: &Notification{
				Title:     title,
				Body:      body,
				ClickType: clickType,
				URL:       url,
			},
		},
	}

	resp, err := c.doRequest("POST", PathPushSingleCid, req)
	if err != nil {
		return nil, err
	}

	return parsePushResponse(resp)
}

// PushSingleByAlias 通过别名单推
func (c *Client) PushSingleByAlias(alias, title, body, clickType, url string) (*PushResponse, error) {
	req := &SinglePushRequest{
		RequestID: generateRequestID(),
		Audience: &Audience{
			Alias: []string{alias},
		},
		PushMessage: &PushMessage{
			Notification: &Notification{
				Title:     title,
				Body:      body,
				ClickType: clickType,
				URL:       url,
			},
		},
	}

	resp, err := c.doRequest("POST", PathPushSingleAlias, req)
	if err != nil {
		return nil, err
	}

	return parsePushResponse(resp)
}

// PushBatchByCID 批量CID单推
func (c *Client) PushBatchByCID(messages []*SinglePushRequest, async bool) (*PushResponse, error) {
	// 设置RequestID
	for _, msg := range messages {
		if msg.RequestID == "" {
			msg.RequestID = generateRequestID()
		}
	}

	req := &BatchSinglePushRequest{
		IsAsync: async,
		MsgList: messages,
	}

	resp, err := c.doRequest("POST", PathPushBatchCid, req)
	if err != nil {
		return nil, err
	}

	return parsePushResponse(resp)
}

// PushBatchByAlias 批量别名单推
func (c *Client) PushBatchByAlias(messages []*SinglePushRequest, async bool) (*PushResponse, error) {
	// 设置RequestID
	for _, msg := range messages {
		if msg.RequestID == "" {
			msg.RequestID = generateRequestID()
		}
	}

	req := &BatchSinglePushRequest{
		IsAsync: async,
		MsgList: messages,
	}

	resp, err := c.doRequest("POST", PathPushBatchAlias, req)
	if err != nil {
		return nil, err
	}

	return parsePushResponse(resp)
}

// CreateListMessage 创建批量推消息
func (c *Client) CreateListMessage(title, body, clickType, url string, settings *Settings) (string, error) {
	req := &ListMessageRequest{
		Settings: settings,
		PushMessage: &PushMessage{
			Notification: &Notification{
				Title:     title,
				Body:      body,
				ClickType: clickType,
				URL:       url,
			},
		},
	}

	resp, err := c.doRequest("POST", PathPushListMsg, req)
	if err != nil {
		return "", err
	}

	var msgResp ListMessageResponse
	if err := json.Unmarshal(resp.Data, &msgResp); err != nil {
		return "", fmt.Errorf("unmarshal response failed: %w", err)
	}

	return msgResp.TaskID, nil
}

// PushListByCID 批量推-CID列表
func (c *Client) PushListByCID(taskID string, cids []string, async bool) (*PushResponse, error) {
	req := &ListPushRequest{
		TaskID:  taskID,
		IsAsync: async,
		Audience: &Audience{
			CID: cids,
		},
	}

	resp, err := c.doRequest("POST", PathPushListCid, req)
	if err != nil {
		return nil, err
	}

	return parsePushResponse(resp)
}

// PushListByAlias 批量推-别名列表
func (c *Client) PushListByAlias(taskID string, aliases []string, async bool, needDetail bool) (*PushResponse, error) {
	req := &ListPushRequest{
		TaskID:          taskID,
		IsAsync:         async,
		NeedAliasDetail: needDetail,
		Audience: &Audience{
			Alias: aliases,
		},
	}

	resp, err := c.doRequest("POST", PathPushListAlias, req)
	if err != nil {
		return nil, err
	}

	return parsePushResponse(resp)
}

// PushToAll 群推所有用户
func (c *Client) PushToAll(title, body, clickType, url string, settings *Settings) (*PushResponse, error) {
	req := &AppPushRequest{
		RequestID: generateRequestID(),
		Audience:  "all",
		Settings:  settings,
		PushMessage: &PushMessage{
			Notification: &Notification{
				Title:     title,
				Body:      body,
				ClickType: clickType,
				URL:       url,
			},
		},
	}

	resp, err := c.doRequest("POST", PathPushAll, req)
	if err != nil {
		return nil, err
	}

	return parsePushResponse(resp)
}

// PushByTag 按条件筛选用户推送
func (c *Client) PushByTag(tags []Tag, title, body, clickType, url string, settings *Settings) (*PushResponse, error) {
	req := &AppPushRequest{
		RequestID: generateRequestID(),
		Audience: &Audience{
			Tag: tags,
		},
		Settings: settings,
		PushMessage: &PushMessage{
			Notification: &Notification{
				Title:     title,
				Body:      body,
				ClickType: clickType,
				URL:       url,
			},
		},
	}

	resp, err := c.doRequest("POST", PathPushTag, req)
	if err != nil {
		return nil, err
	}

	return parsePushResponse(resp)
}

// PushByFastTag 使用标签快速推送
func (c *Client) PushByFastTag(tag, title, body, clickType, url string, settings *Settings) (*PushResponse, error) {
	req := &AppPushRequest{
		RequestID: generateRequestID(),
		Audience: &Audience{
			FastCustomTag: tag,
		},
		Settings: settings,
		PushMessage: &PushMessage{
			Notification: &Notification{
				Title:     title,
				Body:      body,
				ClickType: clickType,
				URL:       url,
			},
		},
	}

	resp, err := c.doRequest("POST", PathPushFastTag, req)
	if err != nil {
		return nil, err
	}

	return parsePushResponse(resp)
}

// StopTask 停止推送任务
func (c *Client) StopTask(taskID string) error {
	path := fmt.Sprintf("%s/%s", PathTaskStop, taskID)
	_, err := c.doRequest("DELETE", path, nil)
	return err
}

// GetScheduleTask 查询定时任务
func (c *Client) GetScheduleTask(taskID string) (*CommonResponse, error) {
	path := fmt.Sprintf("%s/%s", PathTaskSchedule, taskID)
	return c.doRequest("GET", path, nil)
}

// DeleteScheduleTask 删除定时任务
func (c *Client) DeleteScheduleTask(taskID string) error {
	path := fmt.Sprintf("%s/%s", PathTaskSchedule, taskID)
	_, err := c.doRequest("DELETE", path, nil)
	return err
}

// GetTaskDetail 查询消息明细
func (c *Client) GetTaskDetail(cid, taskID string) (*CommonResponse, error) {
	path := fmt.Sprintf("%s/%s/%s", PathTaskDetail, cid, taskID)
	return c.doRequest("GET", path, nil)
}
