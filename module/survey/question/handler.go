package question

import (
	"Dext-Server/config"
	"Dext-Server/model"
	"Dext-Server/utils"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func GetSurveyQuestionsHandler(c *gin.Context) {

	db := config.DB

	surveyID := c.Param("surveyId")
	username := c.MustGet("username").(string)

	// 验证问卷所有权
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM surveys s
		JOIN projects p ON s.project_id = p.id
		WHERE s.id = ? AND p.create_by = ?`, surveyID, username).Scan(&count)
	if err != nil || count == 0 {
		utils.SendError(c, http.StatusForbidden, "无权访问此问卷")
		return
	}

	// 先检查数据库中是否有数据
	var questionCount int
	err = db.QueryRow("SELECT COUNT(*) FROM questions WHERE survey_id = ?", surveyID).Scan(&questionCount)
	if err != nil {
		log.Printf("检查问题数量失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, "检查问题数量失败")
		return
	}

	// 查询问题列表 - 使用完整的database_schema.sql结构
	rows, err := db.Query(`
		SELECT id, survey_id, question_type, question_description, question_order, is_required, media_urls, jump_logic, COALESCE(image_scale, 1.0)
		FROM questions
		WHERE survey_id = ?
		ORDER BY question_order ASC`, surveyID)
	if err != nil {
		log.Printf("查询问题列表失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, "获取问题列表失败")
		return
	}
	defer rows.Close()

	var questions []model.Question
	for rows.Next() {
		var q model.Question
		var mediaURLsStr, jumpLogicStr sql.NullString
		var isRequired bool

		err := rows.Scan(
			&q.ID,
			&q.SurveyID,
			&q.QuestionType,
			&q.QuestionDescription,
			&q.Order,
			&isRequired,
			&mediaURLsStr,
			&jumpLogicStr,
			&q.ImageScale,
		)
		if err != nil {
			log.Printf("读取问题数据失败: %v", err)
			continue
		}

		// 设置title字段以兼容前端
		q.Title = q.QuestionDescription

		// 解析媒体URL和跳题逻辑
		if mediaURLsStr.Valid && mediaURLsStr.String != "" {
			var mediaURLs []string
			if err := json.Unmarshal([]byte(mediaURLsStr.String), &mediaURLs); err == nil {
				// 过滤不存在的媒体文件
				validURLs := filterExistingMediaURLs(mediaURLs)
				q.MediaURLs = validURLs

				// 如果有URL被过滤掉，更新数据库
				if len(validURLs) != len(mediaURLs) {
					updatedJSON, _ := json.Marshal(validURLs)
					_, err := db.Exec("UPDATE questions SET media_urls = ? WHERE id = ?", updatedJSON, q.ID)
					if err != nil {
						log.Printf("更新问题媒体URL失败: %v", err)
					}
				}
			} else {
				log.Printf("解析媒体URL失败: %v, 数据: %s", err, mediaURLsStr.String)
			}
		} else {
			q.MediaURLs = []string{} // 默认为空数组
		}

		if jumpLogicStr.Valid && jumpLogicStr.String != "" {
			var jumpLogic map[int]int
			if err := json.Unmarshal([]byte(jumpLogicStr.String), &jumpLogic); err == nil {
				q.JumpLogic = jumpLogic
			} else {
				log.Printf("解析跳题逻辑失败: %v, 数据: %s", err, jumpLogicStr.String)
			}
		} else {
			q.JumpLogic = map[int]int{} // 默认为空map
		}

		q.Required = isRequired

		// 查询选项 - 使用完整的database_schema.sql结构
		optionRows, err := db.Query(`
			SELECT id, question_id, option_text, option_order, media_url, destination_question_id, custom_input_placeholder
			FROM question_options
			WHERE question_id = ?
			ORDER BY option_order ASC`, q.ID)
		if err != nil {
			log.Printf("查询选项失败: %v", err)
			continue
		}
		defer optionRows.Close()

		for optionRows.Next() {
			var opt model.Option
			var mediaURL, destinationQuestionID, customPlaceholder sql.NullString
			err := optionRows.Scan(
				&opt.ID,
				&opt.QuestionID,
				&opt.OptionText,
				&opt.Order,
				&mediaURL,
				&destinationQuestionID,
				&customPlaceholder,
			)
			if err != nil {
				log.Printf("读取选项数据失败: %v", err)
				continue
			}

			// 设置text字段以兼容前端
			opt.Text = opt.OptionText

			// 处理媒体URL
			if mediaURL.Valid && mediaURL.String != "" {
				// 检查文件是否存在
				if isMediaFileExists(mediaURL.String) {
					opt.MediaURL = mediaURL.String
					opt.MediaUrl = mediaURL.String // 兼容前端字段名
				} else {
					// 文件不存在，清空URL并更新数据库
					opt.MediaURL = ""
					opt.MediaUrl = ""
					_, err := db.Exec("UPDATE question_options SET media_url = NULL WHERE id = ?", opt.ID)
					if err != nil {
						log.Printf("清空选项媒体URL失败: %v", err)
					}
				}
			}
			if destinationQuestionID.Valid {
				if destID, err := strconv.Atoi(destinationQuestionID.String); err == nil {
					opt.Destination = &destID
					log.Printf("从数据库读取选项 %d 的 destination: %d", opt.ID, destID)
				}
			} else {
				log.Printf("选项 %d 数据库中 destination_question_id 为 NULL", opt.ID)
			}
			if customPlaceholder.Valid {
				opt.CustomInputPlaceholder = customPlaceholder.String
			}

			q.Options = append(q.Options, opt)
		}

		// 若为评级题（question_type = 3），根据前端约定从 options 中解析 RatingConfig 返回
		if q.QuestionType == 3 {
			// 默认值
			rc := &model.RatingConfig{
				Min:       0,
				Max:       100,
				Initial:   50,
				MinLabel:  "最小值",
				MidLabel:  "一般",
				MaxLabel:  "最大值",
				Style:     "star",
				Icon:      "star",
				AllowHalf: true,
				Stars:     5,
			}
			// 解析文本
			parseFloat := func(s string, def float64) float64 {
				if v, err := strconv.ParseFloat(s, 64); err == nil {
					return v
				}
				return def
			}
			if len(q.Options) >= 1 {
				rc.Min = parseFloat(q.Options[0].Text, rc.Min)
			}
			if len(q.Options) >= 2 {
				rc.Max = parseFloat(q.Options[1].Text, rc.Max)
			}
			if len(q.Options) >= 3 {
				rc.Initial = parseFloat(q.Options[2].Text, rc.Initial)
			}
			if len(q.Options) >= 4 && q.Options[3].Text != "" {
				rc.MinLabel = q.Options[3].Text
			}
			if len(q.Options) >= 5 && q.Options[4].Text != "" {
				rc.MaxLabel = q.Options[4].Text
			}
			if len(q.Options) >= 6 && q.Options[5].Text != "" {
				rc.MidLabel = q.Options[5].Text
			}
			if len(q.Options) >= 7 && (q.Options[6].Text == "star" || q.Options[6].Text == "crumb") {
				rc.Style = q.Options[6].Text
			}
			if len(q.Options) >= 8 && q.Options[7].Text != "" {
				rc.Icon = q.Options[7].Text
			}
			if len(q.Options) >= 9 {
				rc.AllowHalf = strings.ToLower(q.Options[8].Text) == "true"
			}
			if len(q.Options) >= 10 {
				if n, err := strconv.Atoi(q.Options[9].Text); err == nil {
					if n < 1 {
						n = 1
					}
					if n > 10 {
						n = 10
					}
					rc.Stars = n
				}
			}
			// 解析自定义标签（第11项，JSON 字符串，例如 {"0.5":"Useless","1":"Useless"}）
			if len(q.Options) >= 11 {
				raw := strings.TrimSpace(q.Options[10].Text)
				if raw != "" {
					var labels map[string]string
					if err := json.Unmarshal([]byte(raw), &labels); err == nil && len(labels) > 0 {
						rc.Labels = labels
					}
				}
			}
			q.RatingConfig = rc
		}

		questions = append(questions, q)
	}

	c.JSON(http.StatusOK, questions)
}

func AddSurveyQuestionHandler(c *gin.Context) {

	db := config.DB

	surveyID := c.Param("surveyId")
	username := c.MustGet("username").(string)

	// 验证问卷所有权
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM surveys s
		JOIN projects p ON s.project_id = p.id
		WHERE s.id = ? AND p.create_by = ?`, surveyID, username).Scan(&count)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "验证问卷所有权失败")
		return
	}
	if count == 0 {
		utils.SendError(c, http.StatusForbidden, "无权限操作此问卷")
		return
	}

	var question model.Question
	if err := c.ShouldBindJSON(&question); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的题目数据")
		return
	}

	// 兼容前端：若 QuestionDescription 为空则使用 Title
	if strings.TrimSpace(question.QuestionDescription) == "" && strings.TrimSpace(question.Title) != "" {
		question.QuestionDescription = question.Title
	}
	// 安全过滤输入
	question.QuestionDescription = utils.SanitizeInput(question.QuestionDescription)

	// 获取当前最大排序号
	var maxOrder int
	err = db.QueryRow("SELECT COALESCE(MAX(question_order), 0) FROM questions WHERE survey_id = ?", surveyID).Scan(&maxOrder)
	if err != nil {
		log.Printf("获取最大排序号失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, "系统错误")
		return
	}

	// 准备媒体URL和跳题逻辑JSON
	mediaURLsJSON, _ := json.Marshal(question.MediaURLs)
	jumpLogicJSON, _ := json.Marshal(question.JumpLogic)

	// 开启事务
	tx, err := db.Begin()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "创建事务失败")
		return
	}
	defer tx.Rollback()

	// 插入问题
	result, err := tx.Exec(`
        INSERT INTO questions (survey_id, question_type, question_description, question_order, is_required, media_urls, jump_logic, image_scale)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		surveyID, question.QuestionType, question.QuestionDescription, maxOrder+1, question.Required, mediaURLsJSON, jumpLogicJSON, question.ImageScale)
	if err != nil {
		log.Printf("插入问题失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, "添加问题失败")
		return
	}

	questionID, _ := result.LastInsertId()
	question.ID = int(questionID)
	question.SurveyID, _ = strconv.Atoi(surveyID)
	question.Order = maxOrder + 1

	// 插入选项
	for i, opt := range question.Options {
		// 兼容前端字段名：text -> option_text, mediaUrl -> media_url
		if strings.TrimSpace(opt.OptionText) == "" && strings.TrimSpace(opt.Text) != "" {
			opt.OptionText = opt.Text
		}
		if strings.TrimSpace(opt.MediaURL) == "" && strings.TrimSpace(opt.MediaUrl) != "" {
			opt.MediaURL = opt.MediaUrl
		}
		opt.QuestionID = question.ID
		opt.Order = i + 1

		// 验证 destination 值的合法性
		if opt.Destination != nil {
			dest := *opt.Destination
			log.Printf("选项 %d 的 destination 值: %d", opt.ID, dest)
			if dest < -1 || dest > 500 {
				tx.Rollback()
				log.Printf("拒绝无效的跳转目标: %d", dest)
				utils.SendError(c, http.StatusBadRequest, fmt.Sprintf("无效的跳转目标: %d", dest))
				return
			}
		} else {
			log.Printf("选项 %d 的 destination 为 null", opt.ID)
		}

		_, err = tx.Exec(`
            INSERT INTO question_options (question_id, option_text, option_order, media_url, destination_question_id, custom_input_placeholder)
            VALUES (?, ?, ?, ?, ?, ?)`,
			opt.QuestionID, opt.OptionText, opt.Order, opt.MediaURL, opt.Destination, opt.CustomInputPlaceholder)
		if err != nil {
			log.Printf("插入选项失败: %v", err)
			tx.Rollback()
			utils.SendError(c, http.StatusInternalServerError, "插入选项失败")
			return
		}
	}

	if err = tx.Commit(); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "提交事务失败")
		return
	}

	c.JSON(http.StatusCreated, question)
}

func UpdateSurveyQuestionHandler(c *gin.Context) {

	db := config.DB

	surveyID := c.Param("surveyId")
	questionID := c.Param("questionId")
	username := c.MustGet("username").(string)

	// 验证问卷所有权
	var count int
	err := db.QueryRow(`
        SELECT COUNT(*) FROM questions sq
        JOIN surveys s ON sq.survey_id = s.id
        JOIN projects p ON s.project_id = p.id
        WHERE sq.id = ? AND sq.survey_id = ? AND p.create_by = ?`, questionID, surveyID, username).Scan(&count)
	if err != nil || count == 0 {
		utils.SendError(c, http.StatusForbidden, "无权更新此问题")
		return
	}

	var question model.Question
	if err := c.ShouldBindJSON(&question); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的题目数据")
		return
	}

	// 兼容前端：若 QuestionDescription 为空则使用 Title
	if strings.TrimSpace(question.QuestionDescription) == "" && strings.TrimSpace(question.Title) != "" {
		question.QuestionDescription = question.Title
	}
	// 安全过滤输入
	question.QuestionDescription = utils.SanitizeInput(question.QuestionDescription)

	// 准备媒体URL和跳题逻辑JSON
	mediaURLsJSON, _ := json.Marshal(question.MediaURLs)
	jumpLogicJSON, _ := json.Marshal(question.JumpLogic)

	// 开启事务
	tx, err := db.Begin()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "创建事务失败")
		return
	}
	defer tx.Rollback()

	// 更新问题
	_, err = tx.Exec(`
        UPDATE questions 
        SET question_type = ?, question_description = ?, is_required = ?, media_urls = ?, jump_logic = ?, image_scale = ?
        WHERE id = ? AND survey_id = ?`,
		question.QuestionType, question.QuestionDescription, question.Required, mediaURLsJSON, jumpLogicJSON, question.ImageScale, questionID, surveyID)
	if err != nil {
		log.Printf("更新问题失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, "更新问题失败")
		return
	}

	// 删除旧选项
	_, err = tx.Exec("DELETE FROM question_options WHERE question_id = ?", questionID)
	if err != nil {
		log.Printf("删除旧选项失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, "更新选项失败")
		return
	}

	// 插入新选项
	for i, opt := range question.Options {
		// 兼容前端字段名：text -> option_text, mediaUrl -> media_url
		if strings.TrimSpace(opt.OptionText) == "" && strings.TrimSpace(opt.Text) != "" {
			opt.OptionText = opt.Text
		}
		if strings.TrimSpace(opt.MediaURL) == "" && strings.TrimSpace(opt.MediaUrl) != "" {
			opt.MediaURL = opt.MediaUrl
		}
		opt.QuestionID, _ = strconv.Atoi(questionID)
		opt.Order = i + 1

		// 验证 destination 值的合法性
		if opt.Destination != nil {
			dest := *opt.Destination
			log.Printf("更新选项 %d 的 destination 值: %d", opt.ID, dest)
			if dest < -1 || dest > 500 {
				tx.Rollback()
				log.Printf("拒绝无效的跳转目标: %d", dest)
				utils.SendError(c, http.StatusBadRequest, fmt.Sprintf("无效的跳转目标: %d", dest))
				return
			}
		} else {
			log.Printf("更新选项 %d 的 destination 为 null", opt.ID)
		}

		_, err = tx.Exec(`
            INSERT INTO question_options (question_id, option_text, option_order, media_url, destination_question_id, custom_input_placeholder)
            VALUES (?, ?, ?, ?, ?, ?)`,
			opt.QuestionID, opt.OptionText, opt.Order, opt.MediaURL, opt.Destination, opt.CustomInputPlaceholder)
		if err != nil {
			log.Printf("插入新选项失败: %v", err)
			utils.SendError(c, http.StatusInternalServerError, "更新选项失败")
			return
		}
	}

	if err = tx.Commit(); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "提交事务失败")
		return
	}

	c.JSON(http.StatusOK, question)
}

func DeleteSurveyQuestionHandler(c *gin.Context) {

	db := config.DB

	surveyID := c.Param("surveyId")
	questionID := c.Param("questionId")
	username := c.MustGet("username").(string)

	// 验证问卷所有权
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM questions sq
		JOIN surveys s ON sq.survey_id = s.id
		JOIN projects p ON s.project_id = p.id
		WHERE sq.id = ? AND sq.survey_id = ? AND p.create_by = ?`, questionID, surveyID, username).Scan(&count)
	if err != nil || count == 0 {
		utils.SendError(c, http.StatusForbidden, "无权删除此问题")
		return
	}

	// 开启事务
	tx, err := db.Begin()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "创建事务失败")
		return
	}
	defer tx.Rollback()

	// 删除选项（外键约束会自动处理）
	_, err = tx.Exec("DELETE FROM question_options WHERE question_id = ?", questionID)
	if err != nil {
		log.Printf("删除选项失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, "删除选项失败")
		return
	}

	// 删除问题
	_, err = tx.Exec("DELETE FROM questions WHERE id = ? AND survey_id = ?", questionID, surveyID)
	if err != nil {
		log.Printf("删除问题失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, "删除问题失败")
		return
	}

	if err = tx.Commit(); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "提交事务失败")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "问题删除成功"})
}

func ReorderSurveyQuestionsHandler(c *gin.Context) {

	db := config.DB

	surveyID := c.Param("surveyId")
	username := c.MustGet("username").(string)

	// 验证问卷所有权
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM surveys s
		JOIN projects p ON s.project_id = p.id
		WHERE s.id = ? AND p.create_by = ?`, surveyID, username).Scan(&count)
	if err != nil || count == 0 {
		utils.SendError(c, http.StatusForbidden, "无权重新排序此问卷的问题")
		return
	}

	var req struct {
		QuestionIds []int `json:"questionIds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的排序数据")
		return
	}

	if len(req.QuestionIds) == 0 {
		utils.SendError(c, http.StatusBadRequest, "问题ID列表不能为空")
		return
	}

	// 验证所有问题都属于此问卷
	placeholders := strings.Repeat("?,", len(req.QuestionIds))
	placeholders = placeholders[:len(placeholders)-1]
	query := fmt.Sprintf("SELECT COUNT(*) FROM questions WHERE id IN (%s) AND survey_id = ?", placeholders)
	args := make([]interface{}, len(req.QuestionIds)+1)
	for i, id := range req.QuestionIds {
		args[i] = id
	}
	args[len(req.QuestionIds)] = surveyID

	err = db.QueryRow(query, args...).Scan(&count)
	if err != nil {
		log.Printf("验证问题所有权失败: %v", err)
		utils.SendError(c, http.StatusInternalServerError, "系统错误")
		return
	}

	if count != len(req.QuestionIds) {
		utils.SendError(c, http.StatusForbidden, "部分问题不存在或无权限操作")
		return
	}

	// 开启事务
	tx, err := db.Begin()
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "创建事务失败")
		return
	}
	defer tx.Rollback()

	// 更新问题排序
	for i, questionID := range req.QuestionIds {
		_, err = tx.Exec("UPDATE questions SET question_order = ? WHERE id = ? AND survey_id = ?", i+1, questionID, surveyID)
		if err != nil {
			log.Printf("更新问题排序失败: %v", err)
			utils.SendError(c, http.StatusInternalServerError, "重新排序失败")
			return
		}
	}

	if err = tx.Commit(); err != nil {
		utils.SendError(c, http.StatusInternalServerError, "提交事务失败")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "排序成功"})
}

// filterExistingMediaURLs 过滤出实际存在的媒体文件URL
func filterExistingMediaURLs(urls []string) []string {
	var validURLs []string
	for _, url := range urls {
		if isMediaFileExists(url) {
			validURLs = append(validURLs, url)
		} else {
			log.Printf("媒体文件不存在，已从配置中移除: %s", url)
		}
	}
	return validURLs
}

// isMediaFileExists 检查媒体文件是否存在
func isMediaFileExists(url string) bool {
	if url == "" {
		return false
	}

	// 从URL中提取文件路径
	// URL格式: /openassets/files/survey-assets/xxx.mp4
	if !strings.HasPrefix(url, "/openassets/files/") {
		return true // 不是本地文件，假定存在
	}

	// 移除前缀获取相对路径
	relPath := strings.TrimPrefix(url, "/openassets/files/")

	// 构建完整路径
	fullPath := filepath.Join("assets_storage", relPath)

	// 检查文件是否存在
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return false
	}

	return true
}
