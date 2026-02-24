// 由自动模块化脚本生成 o((>ω< ))o
package model

type Project struct {
	ID                 int    `json:"id"`
	ProjectName        string `json:"projectName" binding:"required"`
	ProjectDescription string `json:"projectDescription"`
	UserID             string `json:"userId"` // UserID 从 int 改为 string
	CreateBy           string `json:"createBy"`
	CreateTime         string `json:"createTime"`
	UpdateTime         string `json:"updateTime"`
	UpdateBy           string `json:"updateBy"`
}
