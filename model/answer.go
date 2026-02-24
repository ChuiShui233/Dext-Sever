// 由自动模块化脚本生成 o((>ω< ))o
package model

type Answer struct {
	ID          int            `json:"id"`
	SurveyID    int            `json:"surveyId"`
	UserID      string         `json:"userId"` // UserID 从 int 改为 string
	UserAccount string         `json:"userAccount"`
	CreateTime  string         `json:"createTime"`
	IsDelete    int            `json:"isDelete"` // 逻辑删除 0-未删除
	DeletedAt   *string        `json:"deletedAt"` // 删除时间
	Questions   []AnswerDetail `json:"questions"`
}

type AnswerDetail struct {
	ID              int      `json:"id"`
	AnswerID        int      `json:"answerId"`
	QuestionID      int      `json:"questionId"`
	SelectedOptions []int    `json:"indices,omitempty"`      // 对应前端的 indices 字段
	Texts           []string `json:"answer,omitempty"`       // 对应前端的 answer 字段
	SelectChoices   string   `json:"selectChoices,omitempty"` // 选择的选项（字符串形式）
}
