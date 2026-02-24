package survey

import (
	"Dext-Server/config"
	"Dext-Server/model"
	"Dext-Server/utils"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// GET /api/survey/surveys?query=&type=&page=1&pageSize=10
// 获取问卷列表，支持按问卷名称模糊搜索、问卷类型过滤，分页
func GetSurveysHandler(c *gin.Context) {
	db := config.DB
	username := c.MustGet("username").(string)

	query := strings.TrimSpace(c.DefaultQuery("query", ""))
	typeStr := strings.TrimSpace(c.DefaultQuery("type", ""))
	pageStr := c.Query("page")
	pageSizeStr := c.Query("pageSize")

	// 构建WHERE条件
	where := []string{"p.create_by = ?"}
	args := []interface{}{username}
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
	
	// 如果没有分页参数，返回全部数据
	if pageStr == "" && pageSizeStr == "" {
		// 不分页，获取全部数据
		listSQL := `
			SELECT s.id, s.survey_uid, s.survey_name, s.description, s.survey_type, 
			       s.survey_status, s.total_times, s.per_user_limit, s.project_id, s.deadline,
			       s.auto_submit, s.allow_anonymous, s.create_time, s.update_time
			FROM surveys s
			JOIN projects p ON s.project_id = p.id
			WHERE ` + whereSQL + `
			ORDER BY s.create_time DESC
		`
		
		rows, err := db.Query(listSQL, args...)
		if err != nil {
			utils.SendError(c, http.StatusInternalServerError, "获取问卷列表失败", err)
			return
		}
		defer rows.Close()

		var surveys []model.Survey
		for rows.Next() {
			var s model.Survey
			var perUser sql.NullInt64
			if err := rows.Scan(
				&s.ID, &s.SurveyUID, &s.SurveyName, &s.Description,
				&s.SurveyType, &s.SurveyStatus, &s.TotalTimes, &perUser,
				&s.ProjectID, &s.Deadline, &s.AutoSubmit, &s.AllowAnonymous,
				&s.CreateTime, &s.UpdateTime,
			); err != nil {
				utils.SendError(c, http.StatusInternalServerError, "读取问卷数据失败", err)
				return
			}
			if perUser.Valid {
				v := int(perUser.Int64)
				s.PerUserLimit = &v
			}
			surveys = append(surveys, s)
		}

		c.JSON(http.StatusOK, surveys)
		return
	}
	
	// 有分页参数，执行分页逻辑
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}
	offset := (page - 1) * pageSize

	// 总数
	countSQL := `
		SELECT COUNT(*)
		FROM surveys s
		JOIN projects p ON s.project_id = p.id
		WHERE ` + whereSQL + `
	`
	var total int
	if err := db.QueryRow(countSQL, args...).Scan(&total); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "统计问卷数量失败")
		return
	}

	// 列表
	listSQL := `
		SELECT s.id, s.survey_uid, s.survey_name, s.description, s.survey_type, 
		       s.survey_status, s.total_times, s.per_user_limit, s.project_id, s.deadline,
		       s.auto_submit, s.allow_anonymous, s.create_time, s.update_time
		FROM surveys s
		JOIN projects p ON s.project_id = p.id
		WHERE ` + whereSQL + `
		ORDER BY s.create_time DESC
		LIMIT ? OFFSET ?
	`
	argsList := append([]interface{}{}, args...)
	argsList = append(argsList, pageSize, offset)

	rows, err := db.Query(listSQL, argsList...)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "获取问卷列表失败", err)
		return
	}
	defer rows.Close()

	var surveys []model.Survey
	for rows.Next() {
		var s model.Survey
		var perUser sql.NullInt64
		if err := rows.Scan(
			&s.ID, &s.SurveyUID, &s.SurveyName, &s.Description,
			&s.SurveyType, &s.SurveyStatus, &s.TotalTimes, &perUser,
			&s.ProjectID, &s.Deadline, &s.AutoSubmit, &s.AllowAnonymous,
			&s.CreateTime, &s.UpdateTime,
		); err != nil {
			utils.SendError(c, http.StatusInternalServerError, "读取问卷数据失败", err)
			return
		}
		if perUser.Valid {
			v := int(perUser.Int64)
			s.PerUserLimit = &v
		} else {
			s.PerUserLimit = nil
		}
		surveys = append(surveys, s)
	}

	c.JSON(http.StatusOK, gin.H{
		"items":      surveys,
		"total":      total,
		"page":       page,
		"pageSize":   pageSize,
		"totalPages": (total + pageSize - 1) / pageSize,
	})
}

// 创建问卷
func CreateSurveyHandler(c *gin.Context) {
	db := config.DB

	var survey model.Survey
	if err := c.ShouldBindJSON(&survey); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的问卷数据", err)
		return
	}

	// 归一化次数限制：per_user_limit <= 0 视为不限制（nil）；total_times < 0 归零
	if survey.PerUserLimit != nil && *survey.PerUserLimit <= 0 {
		survey.PerUserLimit = nil
	}
	if survey.TotalTimes < 0 {
		survey.TotalTimes = 0
	}

	// 若类型不是限时(1)，强制清空 deadline
	if survey.SurveyType != 1 {
		survey.Deadline = nil
	}

	username := c.MustGet("username").(string)
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM projects WHERE id = ? AND create_by = ?`, survey.ProjectID, username).Scan(&count); err != nil || count == 0 {
		utils.SendError(c, http.StatusForbidden, "无权创建问卷", err)
		return
	}

	surveyUID := utils.GenerateRandomUID(16)
	now := time.Now().Format("2006-01-02 15:04:05")

	normalizeDeadline := func(ptr *string) *string {
		if ptr == nil {
			return nil
		}
		s := strings.TrimSpace(*ptr)
		if s == "" {
			return nil
		}
		// 尝试多种格式解析
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			v := t.Local().Format("2006-01-02 15:04:05")
			return &v
		}
		layouts := []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05"}
		for _, layout := range layouts {
			if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
				v := t.Format("2006-01-02 15:04:05")
				return &v
			}
		}
		// 兜底：返回 nil，避免写入非法值
		return nil
	}

	normalizedDeadline := normalizeDeadline(survey.Deadline)

	result, err := db.Exec(`
		INSERT INTO surveys (survey_uid, survey_name, description, survey_type, survey_status, total_times, per_user_limit, project_id, deadline, auto_submit, allow_anonymous, create_time, update_time)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		surveyUID, survey.SurveyName, survey.Description, survey.SurveyType, survey.SurveyStatus, survey.TotalTimes, survey.PerUserLimit, survey.ProjectID, normalizedDeadline, survey.AutoSubmit, survey.AllowAnonymous, now, now)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "创建问卷失败", err)
		return
	}

	id, _ := result.LastInsertId()
	survey.ID = int(id)
	survey.SurveyUID = surveyUID
	survey.CreateTime = now
	survey.UpdateTime = now

	c.JSON(http.StatusCreated, survey)
}

// 更新问卷
func UpdateSurveyHandler(c *gin.Context) {
	db := config.DB

	var survey model.Survey
	if err := c.ShouldBindJSON(&survey); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的问卷数据", err)
		return
	}

	// 归一化次数限制：per_user_limit <= 0 视为不限制（nil）；total_times < 0 归零
	if survey.PerUserLimit != nil && *survey.PerUserLimit <= 0 {
		survey.PerUserLimit = nil
	}
	if survey.TotalTimes < 0 {
		survey.TotalTimes = 0
	}

	// 若类型不是限时(1)，强制清空 deadline
	if survey.SurveyType != 1 {
		survey.Deadline = nil
	}

	username := c.MustGet("username").(string)
	var count int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM surveys s
		JOIN projects p ON s.project_id = p.id
		WHERE s.id = ? AND p.create_by = ?`, survey.ID, username).Scan(&count); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "验证问卷所有权失败", err)
		return
	}
	if count == 0 {
		utils.SendError(c, http.StatusForbidden, "无权更新问卷", nil)
		return
	}

	// 读取当前状态与当前截止时间（格式化为 yyyy-MM-dd HH:mm:ss 以便比较）
	var currentStatus int
	var currentDeadline sql.NullString
	if err := db.QueryRow(`
		SELECT survey_status, DATE_FORMAT(deadline, '%Y-%m-%d %H:%i:%s')
		FROM surveys WHERE id = ?`, survey.ID).Scan(&currentStatus, &currentDeadline); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "读取问卷当前状态失败", err)
		return
	}

	// 完结保护逻辑：
	// - 若当前为已完结(2)且目标仍为已完结(2)，则禁止修改 deadline；
	// - 若当前为已完结(2)但目标改为发布(1)，允许重新设置截止时间（相当于重新开放）。
	if currentStatus == 2 {
		// 规范化工具
		normalize := func(s string) string {
			if s == "" {
				return ""
			}
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				return t.Format("2006-01-02 15:04:05")
			}
			layouts := []string{
				"2006-01-02 15:04:05",
				"2006-01-02T15:04:05",
			}
			for _, layout := range layouts {
				if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
					return t.Format("2006-01-02 15:04:05")
				}
			}
			return s
		}

		// 当前库中的截止时间（标准化字符串）
		_ = ""
		if currentDeadline.Valid {
			_ = currentDeadline.String
		}

		// 前端传入的截止时间（标准化）
		payloadDeadline := ""
		if survey.Deadline != nil {
			payloadDeadline = *survey.Deadline
		}
		normalizedPayload := normalize(payloadDeadline)

		switch survey.SurveyStatus {
		case 2:
			// 例外：若类型切换为非限时，则允许清空 deadline
			if survey.SurveyType != 1 {
				survey.Deadline = nil
			} else {
				// 限时问卷：如果payload提供了deadline，则使用；否则保持原值
				if normalizedPayload != "" {
					// 解析并校验必须在未来
					if t, err := time.ParseInLocation("2006-01-02 15:04:05", normalizedPayload, time.Local); err != nil || !t.After(time.Now()) {
						utils.SendError(c, http.StatusBadRequest, "限时问卷的截止时间必须是未来时间", nil)
						return
					}
					survey.Deadline = &normalizedPayload
				}
				// 如果payload没有提供deadline，保持原值不变
			}

			// 检查是否从其他状态切换到暂停，如果是，需要验证必要字段
			if survey.SurveyType == 1 && survey.Deadline == nil {
				// 限时问卷但没有deadline，这是不合法的
				if normalizedPayload == "" {
					utils.SendError(c, http.StatusBadRequest, "限时问卷必须设置截止时间", nil)
					return
				} else {
					survey.Deadline = nil
				}
			}
		case 1:
			// 重新发布：允许更新 deadline，但若为限时问卷（survey_type=1），则需要提供未来时间
			if survey.SurveyType == 1 {
				if normalizedPayload == "" {
					utils.SendError(c, http.StatusBadRequest, "重新发布限时问卷需提供新的截止时间", nil)
					return
				}
				// 解析并校验必须在未来
				var t time.Time
				var err1 error
				if t, err1 = time.ParseInLocation("2006-01-02 15:04:05", normalizedPayload, time.Local); err1 != nil {
					utils.SendError(c, http.StatusBadRequest, "截止时间格式无效，应为 YYYY-MM-DD HH:MM:SS", err1)
					return
				}
				if !t.After(time.Now()) {
					utils.SendError(c, http.StatusBadRequest, "截止时间必须晚于当前时间", nil)
					return
				}
				// 替换为标准化字符串，后续统一 normalize 再写库
				s := normalizedPayload
				survey.Deadline = &s
			} else {
				// 非限时问卷允许清空截止时间
				if normalizedPayload == "" {
					survey.Deadline = nil
				} else {
					s := normalizedPayload
					survey.Deadline = &s
				}
			}
		}
	}

	now := time.Now().Format("2006-01-02 15:04:05")

	normalizeDeadline := func(ptr *string) *string {
		if ptr == nil {
			return nil
		}
		s := strings.TrimSpace(*ptr)
		if s == "" {
			return nil
		}
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			v := t.Local().Format("2006-01-02 15:04:05")
			return &v
		}
		layouts := []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05"}
		for _, layout := range layouts {
			if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
				v := t.Format("2006-01-02 15:04:05")
				return &v
			}
		}
		return nil
	}

	normalizedDeadline := normalizeDeadline(survey.Deadline)

	_, err := db.Exec(`
		UPDATE surveys
		SET survey_name = ?, description = ?, survey_type = ?, 
		    survey_status = ?, total_times = ?, per_user_limit = ?, project_id = ?, deadline = ?, auto_submit = ?, allow_anonymous = ?, update_time = ?
		WHERE id = ?`,
		survey.SurveyName, survey.Description, survey.SurveyType,
		survey.SurveyStatus, survey.TotalTimes, survey.PerUserLimit, survey.ProjectID, normalizedDeadline, survey.AutoSubmit, survey.AllowAnonymous, now, survey.ID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "更新问卷失败", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "问卷更新成功"})
}

// 删除单个问卷
func DeleteSurveyHandler(c *gin.Context) {
	db := config.DB
	id := c.Param("id")
	username := c.MustGet("username").(string)

	var count int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM surveys s
		JOIN projects p ON s.project_id = p.id
		WHERE s.id = ? AND p.create_by = ?`, id, username).Scan(&count); err != nil || count == 0 {
		utils.SendError(c, http.StatusForbidden, "无权删除问卷", err)
		return
	}

	if _, err := db.Exec("DELETE FROM surveys WHERE id = ?", id); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "删除问卷失败", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "问卷删除成功"})
}

// 获取问卷详情
func GetSurveyByIDHandler(c *gin.Context) {
	db := config.DB
	id := c.Param("id")
	username := c.MustGet("username").(string)

	var survey model.Survey
	var perUser sql.NullInt64
	err := db.QueryRow(`
		SELECT s.id, s.survey_uid, s.survey_name, s.description, s.survey_type, 
		       s.survey_status, s.total_times, s.per_user_limit, s.project_id, s.deadline,
		       s.auto_submit, s.allow_anonymous, s.create_time, s.update_time
		FROM surveys s
		JOIN projects p ON s.project_id = p.id
		WHERE s.id = ? AND p.create_by = ?`, id, username).
		Scan(&survey.ID, &survey.SurveyUID, &survey.SurveyName, &survey.Description,
			&survey.SurveyType, &survey.SurveyStatus, &survey.TotalTimes, &perUser,
			&survey.ProjectID, &survey.Deadline, &survey.AutoSubmit, &survey.AllowAnonymous,
			&survey.CreateTime, &survey.UpdateTime)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("拒绝连接: 访问不存在的问卷 %s", id)
			c.AbortWithStatus(http.StatusNotFound)
		} else {
			utils.SendError(c, http.StatusInternalServerError, "获取问卷失败", err)
		}
		return
	}

	if perUser.Valid {
		v := int(perUser.Int64)
		survey.PerUserLimit = &v
	}
	c.JSON(http.StatusOK, survey)
}

// 批量删除问卷
func BatchDeleteSurveysHandler(c *gin.Context) {
	db := config.DB
	username := c.MustGet("username").(string)

	var request struct {
		SurveyIDs []int `json:"surveyIds" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的请求数据", err)
		return
	}
	if len(request.SurveyIDs) == 0 {
		utils.SendError(c, http.StatusBadRequest, "未指定要删除的问卷", nil)
		return
	}
	if len(request.SurveyIDs) > 50 {
		utils.SendError(c, http.StatusBadRequest, "一次最多只能删除50份问卷", nil)
		return
	}

	placeholders := strings.Repeat("?,", len(request.SurveyIDs))
	placeholders = placeholders[:len(placeholders)-1]

	query := fmt.Sprintf(`
		SELECT COUNT(*) FROM surveys s
		JOIN projects p ON s.project_id = p.id
		WHERE s.id IN (%s) AND p.create_by = ?`, placeholders)

	args := make([]interface{}, len(request.SurveyIDs)+1)
	for i, id := range request.SurveyIDs {
		args[i] = id
	}
	args[len(request.SurveyIDs)] = username

	var count int
	if err := db.QueryRow(query, args...).Scan(&count); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "验证问卷所有权失败", err)
		return
	}
	if count != len(request.SurveyIDs) {
		utils.SendError(c, http.StatusForbidden, "部分问卷不存在或无权限删除", nil)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "开启事务失败", err)
		return
	}
	defer tx.Rollback()

	for _, surveyID := range request.SurveyIDs {
		_, _ = tx.Exec("DELETE FROM answer_details WHERE answer_id IN (SELECT id FROM answers WHERE survey_id = ?)", surveyID)
		_, _ = tx.Exec("DELETE FROM answers WHERE survey_id = ?", surveyID)
		_, _ = tx.Exec("DELETE FROM surveys WHERE id = ?", surveyID)
	}

	if err := tx.Commit(); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "提交事务失败", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      fmt.Sprintf("成功删除 %d 份问卷", len(request.SurveyIDs)),
		"deletedCount": len(request.SurveyIDs),
	})
}

// 公开访问问卷信息（返回问卷名称、问题数据和背景壁纸）
func GetPublicSurveyHandler(c *gin.Context) {
	db := config.DB
	surveyUID := c.Param("uid")

	// 验证问卷是否存在且状态为已发布
	var survey model.Survey
	err := db.QueryRow(`
		SELECT id, survey_name, description, survey_status, COALESCE(auto_submit, FALSE), COALESCE(allow_anonymous, FALSE)
		FROM surveys 
		WHERE survey_uid = ? AND survey_status = 1
          AND (deadline IS NULL OR deadline > NOW())`, surveyUID).
		Scan(&survey.ID, &survey.SurveyName, &survey.Description, &survey.SurveyStatus, &survey.AutoSubmit, &survey.AllowAnonymous)

	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("拒绝连接: 访问不存在或未发布的问卷")
			c.AbortWithStatus(http.StatusNotFound)
		} else {
			utils.SendError(c, http.StatusInternalServerError, "获取问卷失败")
		}
		return
	}

	// 记录一次访问并更新统计（失败不影响正文返回）
	go func(surveyID int, ip string) {
		// 记录访问
		if _, err := db.Exec(`
			INSERT INTO survey_views (survey_id, viewer_ip)
			VALUES (?, ?)`, surveyID, ip); err != nil {
			// 忽略错误
		}
		// 更新统计信息
		_, _ = db.Exec(`
			INSERT INTO survey_stats (survey_id, view_count, last_view_time)
			VALUES (?, 1, CURRENT_TIMESTAMP)
			ON DUPLICATE KEY UPDATE
			view_count = view_count + 1,
			last_view_time = CURRENT_TIMESTAMP`, surveyID)
	}(survey.ID, c.ClientIP())

	// 获取问卷的问题列表
	rows, err := db.Query(`
		SELECT q.id, q.question_description, q.question_type, q.media_urls, COALESCE(q.image_scale, 1.0), q.is_required, q.jump_logic
		FROM questions q
		WHERE q.survey_id = ? 
		ORDER BY q.id ASC`, survey.ID)

	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "获取问题列表失败")
		return
	}
	defer rows.Close()

	var questions []map[string]interface{}
	for rows.Next() {
		var (
			id, questionType    int
			questionDescription string
			mediaUrls           sql.NullString
			imageScale          float64
			isRequired          bool
			jumpLogicStr        sql.NullString
		)

		if err := rows.Scan(&id, &questionDescription, &questionType, &mediaUrls, &imageScale, &isRequired, &jumpLogicStr); err != nil {
			continue
		}

		// 解析媒体URLs
		var mediaUrlsList []string
		if mediaUrls.Valid && mediaUrls.String != "" {
			// 假设媒体URLs是JSON数组格式存储的
			var urls []string
			if json.Unmarshal([]byte(mediaUrls.String), &urls) == nil {
				mediaUrlsList = urls
			}
		}

		// 获取该问题的选项，包含跳题目标
		optionRows, optionErr := db.Query(`
			SELECT id, option_text, media_url, destination_question_id 
			FROM question_options 
			WHERE question_id = ? 
			ORDER BY id ASC`, id)

		var options []map[string]interface{}
		if optionErr != nil {
			// 如果查询选项失败，跳过该问题
			continue
		} else {
			defer optionRows.Close()
			for optionRows.Next() {
				var optionID int
				var optionText string
				var mediaUrl sql.NullString
				var dest sql.NullInt64
				if optionRows.Scan(&optionID, &optionText, &mediaUrl, &dest) == nil {
					option := map[string]interface{}{
						"id":   optionID,
						"text": optionText,
					}
					if mediaUrl.Valid && mediaUrl.String != "" {
						// 规范化为相对路径，避免 http/https 主机不一致导致的混合内容或跨域问题
						urlStr := mediaUrl.String
						if idx := strings.Index(urlStr, "/openassets/"); idx >= 0 {
							urlStr = urlStr[idx:]
						}
						option["mediaUrl"] = urlStr
					}
					if dest.Valid {
						option["destination"] = int(dest.Int64)
					}
					options = append(options, option)
				}
			}
		}

		// 解析 jump_logic
		var jumpLogic map[int]int
		if jumpLogicStr.Valid && jumpLogicStr.String != "" {
			if err := json.Unmarshal([]byte(jumpLogicStr.String), &jumpLogic); err != nil {
				log.Printf("公开问卷API: 解析问题 %d 的 jumpLogic 失败: %v", id, err)
				jumpLogic = map[int]int{}
			} else {
				// 验证 jumpLogic 中的选项 ID 是否存在于当前选项中
				validJumpLogic := map[int]int{}
				optionIDs := make(map[int]bool)
				for _, opt := range options {
					if optID, ok := opt["id"].(int); ok {
						optionIDs[optID] = true
					}
				}
				
				for optionID, targetID := range jumpLogic {
					if optionIDs[optionID] {
						validJumpLogic[optionID] = targetID
					} else {
						log.Printf("公开问卷API: 问题 %d 的 jumpLogic 包含无效选项ID %d，已忽略", id, optionID)
					}
				}
				jumpLogic = validJumpLogic
			}
		} else {
			jumpLogic = map[int]int{}
		}

		// 如果 jumpLogic 为空（包括过滤后为空），从选项的 destination 字段构建跳转逻辑
		if len(jumpLogic) == 0 {
			log.Printf("公开问卷API: 问题 %d 的 jumpLogic 为空，尝试从选项 destination 构建", id)
			for _, opt := range options {
				if optID, ok := opt["id"].(int); ok {
					if dest, exists := opt["destination"]; exists && dest != nil {
						if destID, ok := dest.(int); ok && destID != 0 {
							jumpLogic[optID] = destID
							log.Printf("公开问卷API: 从选项 %d 的 destination 构建跳转逻辑: %d", optID, destID)
						} else {
							log.Printf("公开问卷API: 选项 %d 的 destination 为 0 或无效，跳过", optID)
						}
					} else {
						log.Printf("公开问卷API: 选项 %d 没有 destination 字段或为 null", optID)
					}
				}
			}
		}

		question := map[string]interface{}{
			"id":           id,
			"title":        questionDescription,
			"questionType": questionType,
			"options":      options,
			"required":     isRequired,
			"order":        id,
			"mediaUrls":    mediaUrlsList,
			"imageScale":   imageScale,
			"jumpLogic":    jumpLogic,
		}
		questions = append(questions, question)
	}

	// 获取问卷背景壁纸
	var desktopBackground, mobileBackground sql.NullString
	_ = db.QueryRow(`
		SELECT desktop_background, mobile_background 
		FROM survey_backgrounds 
		WHERE survey_id = ?`, survey.ID).
		Scan(&desktopBackground, &mobileBackground)

	// 如果没有背景数据，设置为空字符串
	desktopBg := ""
	mobileBg := ""
	if desktopBackground.Valid {
		desktopBg = desktopBackground.String
	}
	if mobileBackground.Valid {
		mobileBg = mobileBackground.String
	}

	// 返回公开访问的问卷信息
	c.JSON(http.StatusOK, gin.H{
		"surveyName":        survey.SurveyName,
		"description":       survey.Description,
		"questions":         questions,
		"desktopBackground": desktopBg,
		"mobileBackground":  mobileBg,
		"autoSubmit":        survey.AutoSubmit,
		"allowAnonymous":    survey.AllowAnonymous,
	})
}

// 公开提交问卷答案
func SubmitPublicAnswerHandler(c *gin.Context) {
	db := config.DB
	surveyUID := c.Param("uid")

	// 验证问卷是否存在且状态为已发布，同时获取匿名提交设置
	var surveyID int
	var allowAnonymous bool
	err := db.QueryRow(`
		SELECT id, COALESCE(allow_anonymous, FALSE) FROM surveys 
		WHERE survey_uid = ? AND survey_status = 1
          AND (deadline IS NULL OR deadline > NOW())`, surveyUID).Scan(&surveyID, &allowAnonymous)

	if err != nil {
		if err == sql.ErrNoRows {
			utils.SendError(c, http.StatusNotFound, "问卷不存在或未发布")
		} else {
			utils.SendError(c, http.StatusInternalServerError, "验证问卷失败")
		}
		return
	}

	var request struct {
		Answers []struct {
			QuestionID int      `json:"questionId" binding:"required"`
			Answer     []string `json:"answer"`
			Indices    []int    `json:"indices"`
		} `json:"answers" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的答案数据")
		return
	}

	// 在创建事务前先检查提交上限（总/单用户）
	var totalTimes sql.NullInt64
	var perUserLimit sql.NullInt64
	if err := db.QueryRow(`SELECT total_times, per_user_limit FROM surveys WHERE id = ?`, surveyID).Scan(&totalTimes, &perUserLimit); err != nil {
		utils.SendError(c, http.StatusBadRequest, "问卷不存在", err)
		return
	}

	// 获取用户ID，支持匿名提交
	var userID string
	var username string
	
	// 检查是否有登录用户
	if userIDInterface, exists := c.Get("user_id"); exists && userIDInterface != nil {
		userID = userIDInterface.(string)
		if usernameInterface, exists := c.Get("username"); exists && usernameInterface != nil {
			username = usernameInterface.(string)
		}
	}
	
	// 如果没有登录用户但允许匿名提交，生成匿名用户ID
	if userID == "" {
		if !allowAnonymous {
			utils.SendError(c, http.StatusUnauthorized, "需要登录才能提交问卷")
			return
		}
		    // 生成稳定匿名ID（受配置控制：ANON_ID_MODE, ANON_INCLUDE_PORT, TRUST_PROXY, ANON_ID_SALT）
    mode := config.GetAnonIDMode()       // off | normal | strict
    includePort := config.AnonIncludePort()
    trustProxy := config.TrustProxy()
    salt := config.GetAnonIDSalt()

    // 取真实IP
    realIP := c.ClientIP()
    if trustProxy {
      if xff := c.Request.Header.Get("X-Forwarded-For"); xff != "" {
        // 取链首IP
        parts := strings.Split(xff, ",")
        if len(parts) > 0 {
          ip := strings.TrimSpace(parts[0])
          if ip != "" {
            realIP = ip
          }
        }
      }
    }

    // 可选端口
    port := ""
    if includePort {
      if hostPort := c.Request.RemoteAddr; hostPort != "" {
        // 形如 1.2.3.4:56789
        if idx := strings.LastIndex(hostPort, ":"); idx > 0 && idx < len(hostPort)-1 {
          port = hostPort[idx+1:]
        }
      }
    }

    ua := c.GetHeader("User-Agent")
    al := c.GetHeader("Accept-Language")

    var raw string
    switch mode {
    case "off":
      // 仅IP（可能多人共用同一ID）
      raw = fmt.Sprintf("IP=%s|S=%s|Z=%s", realIP, surveyUID, salt)
    case "strict":
      // 更严格：IP + UA + Accept-Language + surveyUID + 可选端口 + salt
      raw = fmt.Sprintf("IP=%s|UA=%s|AL=%s|S=%s|P=%s|Z=%s", realIP, ua, al, surveyUID, port, salt)
    default: // normal
      // 折中：IP + UA + surveyUID + salt
      raw = fmt.Sprintf("IP=%s|UA=%s|S=%s|Z=%s", realIP, ua, surveyUID, salt)
    }

    sum := sha256.Sum256([]byte(raw))
    userID = "anonymous_" + hex.EncodeToString(sum[:8])
    username = "匿名用户"
	}

	// 用户维度提交次数
	var userCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM answers WHERE survey_id = ? AND user_id = ?`, surveyID, userID).Scan(&userCount); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "查询用户提交次数失败")
		return
	}
	if perUserLimit.Valid && perUserLimit.Int64 > 0 && int64(userCount) >= perUserLimit.Int64 {
		utils.SendError(c, http.StatusForbidden, "已达到该问卷的单用户提交次数上限")
		return
	}

	// 总提交次数
	var totalCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM answers WHERE survey_id = ?`, surveyID).Scan(&totalCount); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "查询问卷总提交次数失败")
		return
	}
	if totalTimes.Valid && totalTimes.Int64 > 0 && int64(totalCount) >= totalTimes.Int64 {
		// 触顶时将问卷置为已完结（防御性）
		_, _ = db.Exec(`UPDATE surveys SET survey_status = 2 WHERE id = ? AND survey_status <> 2`, surveyID)
		utils.SendError(c, http.StatusForbidden, "该问卷的总提交次数已用尽")
		return
	}

	// 开始事务
	tx, err := db.Begin()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "开启事务失败")
		return
	}
	defer tx.Rollback()

	// 创建答卷记录
	now := time.Now().Format("2006-01-02 15:04:05")

	// 确保匿名用户存在于 users 表以满足 answers.user_id 外键约束
	// 仅当未登录（匿名）时执行
	if username == "匿名用户" {
		var exists int
		if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE id = ?`, userID).Scan(&exists); err != nil {
			utils.SendError(c, http.StatusInternalServerError, "检查匿名用户失败")
			return
		}
		if exists == 0 {
			// 生成 12 字符以内的唯一用户名：例如 an_ + 8位hex = 11 字符
			// 复用上文 raw 的哈希（若无可回退使用时间戳）
			sum := sha256.Sum256([]byte(userID + now))
			uname := "an_" + hex.EncodeToString(sum[:4])
			if len(uname) > 12 {
				uname = uname[:12]
			}
			// 插入最小必要字段，password_hash 使用占位符，避免实际登录使用
			if _, err := tx.Exec(`
				INSERT INTO users (id, username, password_hash, user_role)
				VALUES (?, ?, ?, 0)`, userID, uname, "-"); err != nil {
				utils.SendError(c, http.StatusInternalServerError, "创建匿名用户失败")
				return
			}
		}
	}
	result, err := tx.Exec(`
		INSERT INTO answers (survey_id, user_id, user_account, create_time) 
		VALUES (?, ?, ?, ?)`, surveyID, userID, username, now)

	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "创建答卷记录失败")
		return
	}

	answerID, _ := result.LastInsertId()

	// 保存最小答案详情（仅 indices/texts）到 answer_details
	for _, answer := range request.Answers {
		// 读取该题选项列表（按保存顺序）
		optRows, errQ := tx.Query(`
			SELECT option_text FROM question_options WHERE question_id = ? ORDER BY id ASC`, answer.QuestionID)
		if errQ != nil {
			utils.SendError(c, http.StatusInternalServerError, "读取题目选项失败")
			return
		}
		var optTexts []string
		for optRows.Next() {
			var t string
			_ = optRows.Scan(&t)
			optTexts = append(optTexts, t)
		}
		optRows.Close()

		// 组装 texts 和 indices（优先用前端 indices）
		// 构建自定义填写内容映射：key = __custom_input__:索引:内容
		customInputMap := make(map[int]string)
		for _, text := range answer.Answer {
			if strings.HasPrefix(text, "__custom_input__:") {
				// 解析格式：__custom_input__:索引:用户填写内容
				parts := strings.SplitN(text, ":", 3)
				if len(parts) == 3 {
					idx, err := strconv.Atoi(parts[1])
					if err == nil {
						customInputMap[idx] = text // 保存完整格式
					}
				}
			}
		}
		
		var indices []int
		texts := make([]string, 0, len(answer.Answer))
		if len(answer.Indices) > 0 {
			seen := map[int]bool{}
			for _, idx := range answer.Indices {
				if idx >= 0 && idx < len(optTexts) && !seen[idx] {
					seen[idx] = true
					indices = append(indices, idx)
					
					// 如果是自定义填写选项且有用户输入，使用完整内容
					if optTexts[idx] == "__custom_input__" {
						if customText, exists := customInputMap[idx]; exists {
							texts = append(texts, customText)
						} else {
							texts = append(texts, optTexts[idx])
						}
					} else {
						texts = append(texts, optTexts[idx])
					}
				}
			}
		} else {
			// 回退：根据文本推导 indices（支持同名文本，通过多重计数）
			counts := map[string]int{}
			for _, t := range answer.Answer {
				counts[t] = counts[t] + 1
			}
			for i, t := range optTexts {
				if c := counts[t]; c > 0 {
					indices = append(indices, i)
					texts = append(texts, t)
					counts[t] = c - 1
				}
			}
			// 若无法从选项文本中匹配（如文本/评分），则直接使用前端提供的原始答案文本
			if len(texts) == 0 && len(answer.Answer) > 0 {
				texts = append(texts, answer.Answer...)
			}
		}

		// 保存最小答案详情到 answer_details（JSON: {texts:[], indices:[]}）
		payload := map[string]interface{}{
			"texts":   texts,
			"indices": indices,
		}
		data, _ := json.Marshal(payload)
		if _, err := tx.Exec(`
			INSERT INTO answer_details (answer_id, question_id, selected_options)
			VALUES (?, ?, ?)`, answerID, answer.QuestionID, string(data)); err != nil {
			utils.SendError(c, http.StatusInternalServerError, "保存答案失败")
			return
		}
	}

	// 记录提交并更新统计（在同一事务中）
	_, err = tx.Exec(`
		INSERT INTO survey_submissions (survey_id, user_id, submit_time)
		VALUES (?, ?, CURRENT_TIMESTAMP)`, surveyID, userID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "记录提交失败")
		return
	}

	_, err = tx.Exec(`
		INSERT INTO survey_stats (survey_id, submit_count, last_submit_time)
		VALUES (?, 1, CURRENT_TIMESTAMP)
		ON DUPLICATE KEY UPDATE
		submit_count = submit_count + 1,
		last_submit_time = CURRENT_TIMESTAMP`, surveyID)
	if err == nil {
		if totalTimes.Valid && totalTimes.Int64 > 0 {
			if int64(totalCount+1) >= totalTimes.Int64 {
				_, _ = tx.Exec(`UPDATE surveys SET survey_status = 2 WHERE id = ?`, surveyID)
			}
		}
	}
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "更新统计信息失败")
		return
	}

	// 提交事务
	if err := tx.Commit(); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "提交答案失败")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "答案提交成功",
		"answerId": answerID,
	})
}
