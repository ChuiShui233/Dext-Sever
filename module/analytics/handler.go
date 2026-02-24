package analytics

import (
	"Dext-Server/config"
	"Dext-Server/model"
	"Dext-Server/utils"
	"database/sql"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func CheckSurveyNameHandler(c *gin.Context) {

	db := config.DB

	name := c.Param("name")
	username := c.MustGet("username").(string)

	// 验证输入
	if !isValidSurveyName(name) {
		utils.SendError(c, http.StatusBadRequest, "无效的问卷名称")
		return
	}

	var count int
	err := db.QueryRow(`
        SELECT COUNT(*) FROM surveys s
        JOIN projects p ON s.project_id = p.id
        WHERE s.survey_name = ? AND p.create_by = ?`,
		name, username).Scan(&count)

	if err != nil {
		utils.LogError("检查问卷名称失败", err)
		utils.SendError(c, http.StatusInternalServerError, "检查问卷名称失败")
		return
	}

	c.JSON(http.StatusOK, gin.H{"count": count})
}

// 添加问卷名称验证函数
func isValidSurveyName(name string) bool {
	// 检查长度
	if len(name) < 1 || len(name) > 100 {
		return false
	}

	// 检查是否包含SQL注入特征
	sqlInjectionPatterns := []string{
		"'", "\"", ";", "--", "/*", "*/", "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC",
		"OR", "AND", "=", ">", "<", "(", ")", "[", "]", "{", "}", "|", "\\", "/", "*", "+", "-", "%",
	}

	for _, pattern := range sqlInjectionPatterns {
		if strings.Contains(strings.ToUpper(name), strings.ToUpper(pattern)) {
			return false
		}
	}

	return true
}

func GetSurveyStatsHandler(c *gin.Context) {

	db := config.DB

	surveyID := c.Param("id")
	username := c.MustGet("username").(string)

	var stats model.SurveyStats
	var lastViewTime, lastSubmitTime string

	err := db.QueryRow(`
        SELECT s.id, s.survey_name, 
               COALESCE(ss.view_count, 0) AS view_count,
               COALESCE(ss.submit_count, 0) AS submit_count,
               COALESCE(ss.last_view_time, '1970-01-01 00:00:00') AS last_view_time,
               COALESCE(ss.last_submit_time, '1970-01-01 00:00:00') AS last_submit_time
        FROM surveys s
        JOIN projects p ON s.project_id = p.id
        LEFT JOIN survey_stats ss ON s.id = ss.survey_id
        WHERE s.id = ? AND p.create_by = ?`,
		surveyID, username).
		Scan(
			&stats.SurveyID,
			&stats.SurveyName,
			&stats.ViewCount,
			&stats.SubmitCount,
			&lastViewTime,
			&lastSubmitTime,
		)

	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("拒绝连接: 访问不存在的问卷 %s", surveyID)
			c.AbortWithStatus(http.StatusNotFound)
		} else {
			log.Printf("获取问卷统计失败: %v", err)
			utils.SendError(c, http.StatusInternalServerError, "获取问卷统计失败")
		}
		return
	}

	// 解析时间
	stats.LastViewTime, _ = time.Parse("2006-01-02 15:04:05", lastViewTime)
	stats.LastSubmitTime, _ = time.Parse("2006-01-02 15:04:05", lastSubmitTime)

	// 获取提交用户列表
	rows, err := db.Query(`
SELECT u.username, MAX(ss.submit_time) as last_submit_time
FROM survey_submissions ss
JOIN users u ON ss.user_id = u.id
WHERE ss.survey_id = ? AND ss.is_delete = 0
GROUP BY u.username
ORDER BY last_submit_time DESC
LIMIT 100`, surveyID)

	if err != nil {
		log.Printf("获取提交用户列表失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, "获取提交用户列表失败")
		return
	}
	defer rows.Close()

	for rows.Next() {
		var username string
		var lastSubmitTime string // 用临时变量接收，不使用即可
		if err := rows.Scan(&username, &lastSubmitTime); err != nil {
			log.Printf("读取用户数据失败: %v", err)
			utils.SendError(c, http.StatusInternalServerError, "读取用户数据失败")
			return
		}
		stats.SubmittedUsers = append(stats.SubmittedUsers, username)
	}

	c.JSON(http.StatusOK, stats)
}

func GetAllSurveyStatsHandler(c *gin.Context) {

	db := config.DB

	username := c.MustGet("username").(string)

	rows, err := db.Query(`
        SELECT s.id, s.survey_name, 
               COALESCE(ss.view_count, 0) AS view_count,
               COALESCE(ss.submit_count, 0) AS submit_count,
               COALESCE(ss.last_view_time, '1970-01-01 00:00:00') AS last_view_time,
               COALESCE(ss.last_submit_time, '1970-01-01 00:00:00') AS last_submit_time
        FROM surveys s
        JOIN projects p ON s.project_id = p.id
        LEFT JOIN survey_stats ss ON s.id = ss.survey_id
        WHERE p.create_by = ?`,
		username)

	if err != nil {
		log.Printf("获取问卷统计列表失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, "获取问卷统计列表失败")
		return
	}
	defer rows.Close()

	var statsList []model.SurveyStats
	for rows.Next() {
		var stats model.SurveyStats
		var lastViewTime, lastSubmitTime string

		err := rows.Scan(
			&stats.SurveyID,
			&stats.SurveyName,
			&stats.ViewCount,
			&stats.SubmitCount,
			&lastViewTime,
			&lastSubmitTime,
		)
		if err != nil {
			log.Printf("读取统计数据失败: %v", err)
			utils.SendError(c, http.StatusInternalServerError, "读取统计数据失败")
			return
		}

		// 解析时间字符串
		stats.LastViewTime, _ = time.Parse("2006-01-02 15:04:05", lastViewTime)
		stats.LastSubmitTime, _ = time.Parse("2006-01-02 15:04:05", lastSubmitTime)

		// 初始化 SubmittedUsers 为空数组，避免前端解析错误
		stats.SubmittedUsers = []string{}

		statsList = append(statsList, stats)
	}

	c.JSON(http.StatusOK, statsList)
}

func RecordSurveyViewHandler(c *gin.Context) {

	db := config.DB

	surveyID := c.Param("id")
	clientIP := c.ClientIP()

	tx, err := db.Begin()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "创建事务失败")
		return
	}

	// 记录访问
	_, err = tx.Exec(`
        INSERT INTO survey_views (survey_id, viewer_ip)
        VALUES (?, ?)`,
		surveyID, clientIP)

	if err != nil {
		tx.Rollback()
		utils.SendError(c, http.StatusInternalServerError, "记录访问失败")
		return
	}

	// 更新统计信息
	_, err = tx.Exec(`
        INSERT INTO survey_stats (survey_id, view_count, last_view_time)
        VALUES (?, 1, CURRENT_TIMESTAMP)
        ON DUPLICATE KEY UPDATE
        view_count = view_count + 1,
        last_view_time = CURRENT_TIMESTAMP`,
		surveyID)

	if err != nil {
		tx.Rollback()
		utils.SendError(c, http.StatusInternalServerError, "更新统计信息失败")
		return
	}

	if err = tx.Commit(); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "提交事务失败")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "访问已记录"})
}
