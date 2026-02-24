package analytics

import (
	"Dext-Server/config"
	"Dext-Server/utils"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type RecentSubmission struct {
	Username   string    `json:"username"`
	AvatarURL  *string   `json:"avatarUrl"`
	SurveyName string    `json:"surveyName"`
	SubmitTime time.Time `json:"submitTime"`
	TimeAgo    string    `json:"timeAgo"`
}

func GetRecentSubmissionsHandler(c *gin.Context) {
	db := config.DB
	username := c.MustGet("username").(string)

	// 获取最近的问卷提交记录 - 使用answers表而不是survey_submissions表
	rows, err := db.Query(`
		SELECT u.username, u.avatar_url, s.survey_name, a.create_time
		FROM answers a
		JOIN users u ON a.user_id = u.id
		JOIN surveys s ON a.survey_id = s.id
		JOIN projects p ON s.project_id = p.id
		WHERE p.create_by = ? AND a.is_delete = 0
		ORDER BY a.create_time DESC
		LIMIT 20`, username)

	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "获取最近提交记录失败")
		return
	}
	defer rows.Close()

	var submissions []RecentSubmission
	for rows.Next() {
		var submission RecentSubmission
		var avatarURL sql.NullString
		var submitTime time.Time

		err := rows.Scan(
			&submission.Username,
			&avatarURL,
			&submission.SurveyName,
			&submitTime,
		)
		if err != nil {
			utils.SendError(c, http.StatusInternalServerError, "读取提交记录失败")
			return
		}

		// 处理头像URL
		if avatarURL.Valid {
			submission.AvatarURL = &avatarURL.String
		}

		// 直接使用驱动解析后的时间（受 DSN 中 parseTime 与 loc 影响）
		submission.SubmitTime = submitTime

		// 计算时间差
		submission.TimeAgo = formatTimeAgo(submission.SubmitTime)

		submissions = append(submissions, submission)
	}

	c.JSON(http.StatusOK, gin.H{
		"submissions": submissions,
		"total":       len(submissions),
	})
}

func formatTimeAgo(submitTime time.Time) string {
	now := time.Now()
	diff := now.Sub(submitTime)

	// 处理负时间差（未来时间）
	if diff < 0 {
		fmt.Printf("检测到负时间差，返回'刚刚'\n")
		return "刚刚"
	}

	if diff < time.Minute {
		return "刚刚"
	} else if diff < time.Hour {
		minutes := int(diff.Minutes())
		return fmt.Sprintf("%d分钟前", minutes)
	} else if diff < 24*time.Hour {
		hours := int(diff.Hours())
		return fmt.Sprintf("%d小时前", hours)
	} else if diff < 30*24*time.Hour { // 限制在30天内
		days := int(diff.Hours() / 24)
		return fmt.Sprintf("%d天前", days)
	} else {
		// 超过30天显示具体日期
		return submitTime.Format("2006-01-02")
	}
}
