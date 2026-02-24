package analytics

import (
	"Dext-Server/config"
	"Dext-Server/utils"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// GET /api/survey/submissions/:answerId/detail
// 返回当前登录用户这次提交对应问卷的题目、选项与该次作答
func GetSubmissionDetailHandler(c *gin.Context) {
	db := config.DB
	userID := c.MustGet("user_id").(string)
	answerIDStr := c.Param("answerId")
	answerID, err := strconv.Atoi(answerIDStr)
	if err != nil || answerID <= 0 {
		utils.SendError(c, http.StatusBadRequest, "无效的答卷ID")
		return
	}

	// 验证该答卷是否属于当前用户，并拿到 survey_id
	var surveyID int
	var surveyName, creator string
	err = db.QueryRow(`
        SELECT a.survey_id, s.survey_name, p.create_by
        FROM answers a
        JOIN surveys s ON a.survey_id = s.id
        JOIN projects p ON s.project_id = p.id
        WHERE a.id = ? AND a.user_id = ? AND a.is_delete = 0`, answerID, userID).Scan(&surveyID, &surveyName, &creator)
	if err != nil {
		log.Printf("拒绝连接: 用户 %s 访问不存在或无权限的提交 %d", userID, answerID)
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	// 读取题目与选项
	rows, err := db.Query(`
        SELECT q.id, q.question_type, q.question_description, q.question_order, q.is_required,
               COALESCE(q.media_urls, '[]') AS media_urls,
               COALESCE(q.image_scale, 1.0) AS image_scale
        FROM questions q
        WHERE q.survey_id = ?
        ORDER BY q.question_order ASC, q.id ASC`, surveyID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "查询题目失败")
		return
	}
	defer rows.Close()

	type Option struct {
		Text     string  `json:"text"`
		Order    int     `json:"order"`
		MediaURL *string `json:"mediaUrl,omitempty"`
	}
	type Question struct {
		ID           int      `json:"id"`
		QuestionType int      `json:"questionType"`
		Title        string   `json:"title"`
		Required     bool     `json:"required"`
		Order        int      `json:"order"`
		MediaUrls    []string `json:"mediaUrls"`
		ImageScale   float64  `json:"imageScale"`
		Options      []Option `json:"options"`
	}

	var questions []Question
	for rows.Next() {
		var q Question
		var mediaUrlsRaw string
		if err := rows.Scan(&q.ID, &q.QuestionType, &q.Title, &q.Order, &q.Required, &mediaUrlsRaw, &q.ImageScale); err != nil {
			utils.SendError(c, http.StatusInternalServerError, "读取题目失败")
			return
		}
		if err := json.Unmarshal([]byte(mediaUrlsRaw), &q.MediaUrls); err != nil {
			q.MediaUrls = []string{}
		}
		// 查询每题选项
		optRows, err := db.Query(`
            SELECT option_text, option_order, media_url
            FROM question_options WHERE question_id = ?
            ORDER BY option_order ASC, id ASC`, q.ID)
		if err != nil {
			utils.SendError(c, http.StatusInternalServerError, "查询选项失败")
			return
		}
		var opts []Option
		for optRows.Next() {
			var o Option
			var media sqlNullString
			if err := optRows.Scan(&o.Text, &o.Order, &media); err == nil {
				if media.Valid {
					s := media.String
					o.MediaURL = &s
				}
				opts = append(opts, o)
			}
		}
		optRows.Close()
		q.Options = opts
		questions = append(questions, q)
	}

	// 读取该次答题的答案明细
	adRows, err := db.Query(`
        SELECT question_id, selected_options FROM answer_details WHERE answer_id = ?`, answerID)
	if err != nil {
		utils.SendError(c, http.StatusInternalServerError, "查询答案失败")
		return
	}
	defer adRows.Close()

	myAnswers := map[int][]string{}
	myAnswerIndices := map[int][]int{}
	for adRows.Next() {
		var qid int
		var sel string
		if err := adRows.Scan(&qid, &sel); err == nil {
			// 新格式：JSON 对象 {"texts": [...], "indices": [...]}
			var obj struct {
				Texts   []string `json:"texts"`
				Indices []int    `json:"indices"`
			}
			if json.Unmarshal([]byte(sel), &obj) == nil {
				// 接受空数组或 null 的对象格式，避免回退到逗号拆分
				if obj.Texts != nil {
					myAnswers[qid] = obj.Texts
				} else {
					myAnswers[qid] = []string{}
				}
				if obj.Indices != nil {
					myAnswerIndices[qid] = obj.Indices
				}

			} else {
				// 旧格式：尝试解析为 JSON 数组，否则按逗号分割
				var arr []string
				if json.Unmarshal([]byte(sel), &arr) == nil {
					myAnswers[qid] = arr
				} else {
					if sel == "" {
						myAnswers[qid] = []string{}
					} else {
						parts := strings.Split(sel, ",")
						for i := range parts {
							parts[i] = strings.TrimSpace(parts[i])
						}
						myAnswers[qid] = parts
					}
				}
			}
		}
	}
	// 兼容：若没有 indices，则基于题目与选项由文本推导（处理同名文本）
	for _, q := range questions {
		qid := q.ID
		if _, ok := myAnswerIndices[qid]; ok {
			continue
		}
		opts := q.Options
		counts := map[string]int{}
		for _, t := range myAnswers[qid] {
			counts[t] = counts[t] + 1
		}
		var indices []int
		for idx, o := range opts {
			if c := counts[o.Text]; c > 0 {
				indices = append(indices, idx)
				counts[o.Text] = c - 1
			}
		}
		if len(indices) > 0 {
			myAnswerIndices[qid] = indices
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"surveyId":        surveyID,
		"surveyName":      surveyName,
		"creator":         creator,
		"questions":       questions,
		"myAnswers":       myAnswers,
		"myAnswerIndices": myAnswerIndices,
	})
}

// helper for NULL string scan
type sqlNullString struct {
	Valid  bool
	String string
}

func (s *sqlNullString) Scan(src interface{}) error {
	if src == nil {
		s.Valid = false
		s.String = ""
		return nil
	}
	switch v := src.(type) {
	case []byte:
		s.Valid = true
		s.String = string(v)
	case string:
		s.Valid = true
		s.String = v
	default:
		s.Valid = false
		s.String = ""
	}
	return nil
}
