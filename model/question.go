// 由自动模块化脚本生成 o((>ω< ))o
package model

type Question struct {
	ID                  int         `json:"id"`
	SurveyID            int         `json:"surveyId"`
	QuestionType        int         `json:"questionType"`        // 类型 0-单选，1-多选
	QuestionDescription string      `json:"questionDescription"` // 问题描述
	Title               string      `json:"title"`               // 添加title字段以兼容前端
	Options             []Option    `json:"options"`
	Order               int         `json:"order"`
	Required            bool        `json:"required"`
	MediaURLs           []string    `json:"mediaURLs"`
	JumpLogic           map[int]int `json:"jumpLogic"`
	TotalTimes          int         `json:"totalTimes"` // 一共被回答的次数，用于统计
	Ans                 string      `json:"ans"`        // 用户的答案
	RatingConfig        *RatingConfig `json:"ratingConfig,omitempty"` // 评级题配置（question_type=3）
	ImageScale          float64     `json:"imageScale"`             // 图片显示比例 (0.5-2.0)
}

// RatingConfig 用于将评级题（原滑块题）的可视与区间配置结构化返回给前端
type RatingConfig struct {
    Min       float64 `json:"min"`
    Max       float64 `json:"max"`
    Initial   float64 `json:"initial"`
    MinLabel  string  `json:"minLabel"`
    MidLabel  string  `json:"midLabel"`
    MaxLabel  string  `json:"maxLabel"`
    Style     string  `json:"style"`     // star 或 crumb
    Icon      string  `json:"icon"`      // star/favorite/circle/heart_broken
    AllowHalf bool    `json:"allowHalf"`
    Stars     int     `json:"stars"`     // 1-10
    Labels    map[string]string `json:"labels,omitempty"` // 自定义分值标签映射，key 如 "2.5"
}

type Option struct {
	ID                     int    `json:"id"`
	QuestionID             int    `json:"questionId"`
	OptionText             string `json:"optionText"`  // 选项描述
	Text                   string `json:"text"`        // 选项文本（兼容前端）
	Description            string `json:"description"` // 选项描述（兼容Java端）
	Destination            *int   `json:"destination,omitempty"` // 用于题目的跳转（指针类型以支持 null 和 -1）
	Order                  int    `json:"order"`
	MediaURL               string `json:"mediaURL"`
	MediaUrl               string `json:"mediaUrl"`   // 媒体URL（兼容前端字段名）
	CustomInputPlaceholder string `json:"customInputPlaceholder,omitempty"` // 自定义填写选项的占位符
	IsChoose               int    `json:"isChoose"`   // 0-未选，1-已选
	TotalTimes             int    `json:"totalTimes"` // 选择的次数，用于分析
}
