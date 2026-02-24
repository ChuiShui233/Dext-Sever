// 由自动模块化脚本生成 o((>ω< ))o
package model

import "time"

type SurveyStats struct {
	SurveyID       int       `json:"surveyId"`
	SurveyName     string    `json:"surveyName"`
	ViewCount      int       `json:"viewCount"`
	SubmitCount    int       `json:"submitCount"`
	SubmittedUsers []string  `json:"submittedUsers"`
	LastViewTime   time.Time `json:"lastViewTime"`
	LastSubmitTime time.Time `json:"lastSubmitTime"`
}

type Survey struct {
	ID              int     `json:"id"`
	SurveyUID       string  `json:"surveyUid,omitempty"`
	SurveyName      string  `json:"surveyName" binding:"required"`
	Description     string  `json:"description,omitempty"`
	SurveyType      int     `json:"surveyType"`             // 问卷类型 0-正常问卷 1-限时问卷 2-限次问卷 3-面向群众
	SurveyStatus    int     `json:"surveyStatus"`           // 问卷状态，0-未发布，1-发布进行中，2-已完成且结束，3-已超时未完成
	TotalTimes      int     `json:"totalTimes"`             // 一共能够完成几次
	PerUserLimit    *int    `json:"per_user_limit,omitempty"` // 单用户提交次数限制（NULL/空表示不限）
	NowTimes        int     `json:"nowTimes"`               // 现在完成了几次
	ProjectID       int     `json:"project_id"`
	Deadline        *string `json:"deadline,omitempty"`
	AutoSubmit      bool    `json:"auto_submit"`            // 选完自动提交
	AllowAnonymous  bool    `json:"allow_anonymous"`        // 允许匿名提交
	CanFinishTime   string  `json:"canFinishTime"`   // 能完成的时间（分钟）
	CanFinishUserID string  `json:"canFinishUserId"` // 能完成的用户id
	FinishUserID    string  `json:"finishUserId"`    // 完成问卷用户的id
	URL             string  `json:"url"`             // 查看问卷的详细地址
	AIStatistic     string  `json:"aiStatistic"`     // ai总结
	AIStatus        string  `json:"aiStatus"`        // ai生成状态
	CreateTime      string  `json:"createTime,omitempty"`
	UpdateTime      string  `json:"updateTime,omitempty"`
	DeleteTime      string  `json:"deleteTime,omitempty"`
	IsDelete        int     `json:"isDelete"` // 逻辑删除
}

type SurveyBackground struct {
	ID                int       `json:"id"`
	SurveyID          int       `json:"surveyId"`
	DesktopBackground string    `json:"desktopBackground"`
	MobileBackground  string    `json:"mobileBackground"`
	CreatedBy         string    `json:"createdBy"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

type SurveyAssetFile struct {
	ID          int64  `json:"id"`
	SurveyID    string `json:"surveyId"`
	Username    string `json:"username"`
	FileName    string `json:"fileName"`
	FileURL     string `json:"fileUrl"`
	FileSize    int64  `json:"fileSize"`
	ContentType string `json:"contentType"`
	UploadTime  string `json:"uploadTime"`
}

type SurveyView struct {
	ID       int64  `json:"id"`
	SurveyID string `json:"surveyId"`
	ViewerIP string `json:"viewerIp"`
	ViewTime string `json:"viewTime"`
}

type SurveySubmission struct {
	ID         int64  `json:"id"`
	SurveyID   string `json:"surveyId"`
	UserID     string `json:"userId"`
	SubmitTime string `json:"submitTime"`
}

type SurveyStat struct {
	ID             int64  `json:"id"`
	SurveyID       string `json:"surveyId"`
	ViewCount      int    `json:"viewCount"`
	SubmitCount    int    `json:"submitCount"`
	LastViewTime   string `json:"lastViewTime"`
	LastSubmitTime string `json:"lastSubmitTime"`
}
