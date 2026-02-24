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

// 概览：当前用户所有问卷的总浏览数、总提交数、总问卷数、活跃问卷数（发布中）
func GetOverviewHandler(c *gin.Context) {
	db := config.DB
	username := c.MustGet("username").(string)

	// 查询总浏览数与总提交数
	var totalViews, totalSubmits sql.NullInt64
	err := db.QueryRow(`
    SELECT COALESCE(SUM(ss.view_count),0) AS total_views,
           COALESCE(SUM(ss.submit_count),0) AS total_submits
    FROM surveys s
    JOIN projects p ON s.project_id = p.id
    LEFT JOIN survey_stats ss ON ss.survey_id = s.id
    WHERE p.create_by = ?`, username).Scan(&totalViews, &totalSubmits)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "获取总览失败", err)
		return
	}

	// 查询总问卷数和活跃问卷数（status=1，即发布中的问卷）
	var totalSurveys, activeSurveys int
	err = db.QueryRow(`
    SELECT COUNT(*) AS total,
           SUM(CASE WHEN s.survey_status = 1 THEN 1 ELSE 0 END) AS active
    FROM surveys s
    JOIN projects p ON s.project_id = p.id
    WHERE p.create_by = ?`, username).Scan(&totalSurveys, &activeSurveys)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "获取问卷统计失败", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"totalViews":    totalViews.Int64,
		"totalSubmits":  totalSubmits.Int64,
		"totalSurveys":  totalSurveys,
		"activeSurveys": activeSurveys,
	})
}

// 提交趋势：range=7d | month（默认7d）。7日按天聚合，月按月份聚合近12个月
func GetSubmitTrendHandler(c *gin.Context) {
	db := config.DB
	username := c.MustGet("username").(string)
	rng := c.DefaultQuery("range", "7d")

	type Point struct {
		Label string
		Count int
	}
	var points []Point

	if rng == "month" {
		// 近12个月（含本月）聚合
		rows, err := db.Query(`
      SELECT DATE_FORMAT(ss.submit_time, '%Y-%m') AS ym, COUNT(*)
      FROM survey_submissions ss
      JOIN surveys s ON ss.survey_id = s.id
      JOIN projects p ON s.project_id = p.id
      WHERE p.create_by = ? AND ss.is_delete = 0
        AND ss.submit_time >= DATE_FORMAT(DATE_SUB(CURDATE(), INTERVAL 11 MONTH),'%Y-%m-01')
      GROUP BY ym
      ORDER BY ym ASC`, username)
		if err != nil {
			utils.SendError(c, http.StatusInternalServerError, "获取趋势失败", err)
			return
		}
		defer rows.Close()
		m := map[string]int{}
		for rows.Next() {
			var ym string
			var cnt int
			_ = rows.Scan(&ym, &cnt)
			m[ym] = cnt
		}
		// 填充缺失月份
		now := time.Now()
		for i := 11; i >= 0; i-- {
			t := now.AddDate(0, -i, 0)
			ym := t.Format("2006-01")
			points = append(points, Point{Label: ym, Count: m[ym]})
		}
	} else {
		// 近7日滚动窗口（过去 6 天到当前时刻），避免时区/边界导致的数据缺失
		rows, err := db.Query(`
      SELECT DATE_FORMAT(DATE(ss.submit_time), '%Y-%m-%d') AS d, COUNT(*)
      FROM survey_submissions ss
      JOIN surveys s ON ss.survey_id = s.id
      JOIN projects p ON s.project_id = p.id
      WHERE p.create_by = ? AND ss.is_delete = 0
        AND ss.submit_time >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
      GROUP BY d
      ORDER BY d ASC`, username)

		// 调试日志：打印查询条件和结果
		fmt.Printf("7日趋势查询 - 用户: %s, 时间范围: >= %s\n", username, time.Now().AddDate(0, 0, -6).Format("2006-01-02"))
		if err != nil {
			utils.SendError(c, http.StatusInternalServerError, "获取趋势失败", err)
			return
		}
		defer rows.Close()
		m := map[string]int{}
		for rows.Next() {
			var d string
			var cnt int
			_ = rows.Scan(&d, &cnt)
			m[d] = cnt
		}
		// 填充缺失日期
		today := time.Now()
		for i := 6; i >= 0; i-- {
			d := today.AddDate(0, 0, -i).Format("2006-01-02")
			points = append(points, Point{Label: d, Count: m[d]})
		}
	}

	labels := make([]string, 0, len(points))
	counts := make([]int, 0, len(points))
	for _, p := range points {
		labels = append(labels, p.Label)
		counts = append(counts, p.Count)
	}

	c.JSON(http.StatusOK, gin.H{
		"labels": labels,
		"counts": counts,
		"range":  rng,
	})
}
