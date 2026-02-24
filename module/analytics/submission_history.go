package analytics

import (
	"Dext-Server/config"
	"Dext-Server/utils"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type SubmissionHistoryItem struct {
	AnswerID     int64  `json:"answerId"`
	SurveyID     int    `json:"surveyId"`
	SurveyName   string `json:"surveyName"`
	Description  string `json:"description"`
	SurveyType   int    `json:"surveyType"`
	SurveyStatus int    `json:"surveyStatus"`
	Creator      string `json:"creator"`
	SubmitTime   string `json:"submitTime"`
}

// GET /api/survey/submissions/history?query=&type=&page=1&pageSize=20
// 查询当前登录用户“自己提交”的问卷记录，支持按问卷名称模糊、问卷类型过滤，分页
func GetSubmissionHistoryHandler(c *gin.Context) {
	db := config.DB
	userID := c.MustGet("user_id").(string)

	query := strings.TrimSpace(c.DefaultQuery("query", ""))
	typeStr := strings.TrimSpace(c.DefaultQuery("type", ""))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "20"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	// 构建WHERE条件（限定为当前用户自己的提交）
	where := []string{"a.user_id = ?", "a.is_delete = 0"}
	args := []interface{}{userID}
	if query != "" {
		where = append(where, "s.survey_name LIKE ?")
		args = append(args, "%"+query+"%")
	}
	if typeStr != "" {
		if t, err := strconv.Atoi(typeStr); err == nil {
			where = append(where, "s.survey_type = ?")
			args = append(args, t)
		}
	}
	whereSQL := strings.Join(where, " AND ")

	// 总数
	countSQL := `
        SELECT COUNT(*)
        FROM answers a
        JOIN surveys s ON a.survey_id = s.id
        WHERE ` + whereSQL + `
    `
	var total int
	if err := db.QueryRow(countSQL, args...).Scan(&total); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "统计提交记录失败")
		return
	}

	// 列表
	listSQL := `
        SELECT a.id, s.id, s.survey_name, s.description, s.survey_type, s.survey_status, p.create_by AS creator, DATE_FORMAT(a.create_time, '%Y-%m-%d %H:%i:%s')
        FROM answers a
        JOIN surveys s ON a.survey_id = s.id
        JOIN projects p ON s.project_id = p.id
        WHERE ` + whereSQL + `
        ORDER BY a.create_time DESC
        LIMIT ? OFFSET ?
    `
	argsList := append([]interface{}{}, args...)
	argsList = append(argsList, pageSize, offset)

	rows, err := db.Query(listSQL, argsList...)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "查询提交记录失败")
		return
	}
	defer rows.Close()

	var items []SubmissionHistoryItem
	for rows.Next() {
		var it SubmissionHistoryItem
		if err := rows.Scan(&it.AnswerID, &it.SurveyID, &it.SurveyName, &it.Description, &it.SurveyType, &it.SurveyStatus, &it.Creator, &it.SubmitTime); err != nil {
			utils.SendError(c, http.StatusInternalServerError, "读取提交记录失败")
			return
		}
		items = append(items, it)
	}

	c.JSON(http.StatusOK, gin.H{
		"items":      items,
		"total":      total,
		"page":       page,
		"pageSize":   pageSize,
		"totalPages": (total + pageSize - 1) / pageSize,
	})
}

// DELETE /api/survey/submissions/history/:id
// 逻辑删除提交记录
func DeleteSubmissionHistoryHandler(c *gin.Context) {
	db := config.DB
	userID := c.MustGet("user_id").(string)
	answerID := c.Param("id")

	// 检查记录是否存在且属于当前用户
	var exists int
	err := db.QueryRow("SELECT COUNT(*) FROM answers WHERE id = ? AND user_id = ? AND is_delete = 0", answerID, userID).Scan(&exists)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "系统错误", err)
		return
	}
	if exists == 0 {
		utils.SendError(c, http.StatusNotFound, "记录不存在或无权删除", nil)
		return
	}

	// 逻辑删除
	_, err = db.Exec("UPDATE answers SET is_delete = 1 WHERE id = ?", answerID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "删除失败", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}
