package answer

import (
	"Dext-Server/config"
	"Dext-Server/model"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrAnswerNotFound          = errors.New("答案不存在")
	ErrSurveyNotFound          = errors.New("问卷不存在")
	ErrPermissionDenied        = errors.New("无权限访问")
	ErrPartialPermissionDenied = errors.New("部分答案不存在或无权限删除")
	ErrPerUserLimitReached     = errors.New("已达到该问卷的单用户提交次数上限")
	ErrTotalLimitReached       = errors.New("该问卷的总提交次数已用尽")
)

// Repository 定义答案数据访问接口
type Repository interface {
	// 检查提交限制
	CheckSubmitLimit(surveyID int, userID string) error

	// 保存答案
	SaveAnswer(answer *model.Answer, userID, username string) error

	// 验证问卷所有权
	VerifySurveyOwnership(surveyID int, username string) error

	// 获取问卷的所有答案
	GetAnswersBySurveyID(surveyID int) ([]model.Answer, error)

	// 根据ID获取答案（带权限验证）
	GetAnswerByIDWithPermission(answerID int, username string) (*model.Answer, error)

	// 验证答案所有权
	VerifyAnswerOwnership(answerID int, username string) error

	// 验证批量答案所有权
	VerifyBatchAnswerOwnership(answerIDs []int, username string) (int, error)

	// 删除答案 (逻辑删除)
	DeleteAnswerByID(answerID int) error

	// 批量删除答案 (逻辑删除)
	BatchDeleteAnswers(answerIDs []int) (int, error)

	// 物理删除答案 (仅创建者可用)
	PhysicalDeleteAnswerByID(answerID int) error

	// 批量物理删除答案 (仅创建者可用)
	BatchPhysicalDeleteAnswers(answerIDs []int) (int, error)

	// 获取已删除答案列表 (回收站)
	GetDeletedAnswersBySurveyID(surveyID int) ([]model.Answer, error)

	// 恢复已删除答案
	RestoreAnswerByID(answerID int) error

	// 批量恢复已删除答案
	BatchRestoreAnswers(answerIDs []int) (int, error)

	// 验证已删除答案所有权 (用于回收站操作)
	VerifyDeletedAnswerOwnership(answerID int, username string) error

	// 验证批量已删除答案所有权
	VerifyBatchDeletedAnswerOwnership(answerIDs []int, username string) (int, error)

	// 清理过期的回收站数据
	PhysicalDeleteExpiredAnswers(days int) (int, error)
}

type repositoryImpl struct{}

// NewRepository 创建 Repository 实例
func NewRepository() Repository {
	return &repositoryImpl{}
}

// CheckSubmitLimit 检查提交限制
func (r *repositoryImpl) CheckSubmitLimit(surveyID int, userID string) error {
	db := config.DB

	// 查询提交限制
	var totalTimes sql.NullInt64
	var perUserLimit sql.NullInt64
	if err := db.QueryRow(`SELECT total_times, per_user_limit FROM surveys WHERE id = ?`, surveyID).
		Scan(&totalTimes, &perUserLimit); err != nil {
		if err == sql.ErrNoRows {
			return ErrSurveyNotFound
		}
		return err
	}

	// 检查用户维度提交次数
	var userCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM answers WHERE survey_id = ? AND user_id = ? AND is_delete = 0`,
		surveyID, userID).Scan(&userCount); err != nil {
		return err
	}
	if perUserLimit.Valid && perUserLimit.Int64 > 0 && int64(userCount) >= perUserLimit.Int64 {
		return ErrPerUserLimitReached
	}

	// 检查总提交次数
	var totalCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM answers WHERE survey_id = ? AND is_delete = 0`, surveyID).
		Scan(&totalCount); err != nil {
		return err
	}
	if totalTimes.Valid && totalTimes.Int64 > 0 && int64(totalCount) >= totalTimes.Int64 {
		// 触顶时顺手将问卷置为已完结
		_, _ = db.Exec(`UPDATE surveys SET survey_status = 2 WHERE id = ? AND survey_status <> 2`, surveyID)
		return ErrTotalLimitReached
	}

	return nil
}

// SaveAnswer 保存答案
func (r *repositoryImpl) SaveAnswer(answer *model.Answer, userID, username string) error {
	db := config.DB

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 插入答案主表
	result, err := tx.Exec(`
		INSERT INTO answers (survey_id, user_id, user_account)
		VALUES (?, ?, ?)`,
		answer.SurveyID, userID, username)
	if err != nil {
		return err
	}

	answerID, _ := result.LastInsertId()

	// 插入答案详情
	for _, q := range answer.Questions {
		// 构建包含 texts 和 indices 的 JSON 对象
		data := map[string]interface{}{
			"texts":   q.Texts,
			"indices": q.SelectedOptions,
		}
		optionsJSON, err := json.Marshal(data)
		if err != nil {
			return err
		}

		_, err = tx.Exec(`
			INSERT INTO answer_details (answer_id, question_id, selected_options)
			VALUES (?, ?, ?)`,
			answerID, q.QuestionID, string(optionsJSON))
		if err != nil {
			return err
		}
	}

	// 记录提交
	_, err = tx.Exec(`
		INSERT INTO survey_submissions (survey_id, user_id, submit_time, answer_id)
		VALUES (?, ?, CURRENT_TIMESTAMP, ?)`,
		answer.SurveyID, userID, answerID)
	if err != nil {
		return err
	}

	// 更新统计
	_, err = tx.Exec(`
		INSERT INTO survey_stats (survey_id, submit_count, last_submit_time)
		VALUES (?, 1, CURRENT_TIMESTAMP)
		ON DUPLICATE KEY UPDATE
		submit_count = submit_count + 1,
		last_submit_time = CURRENT_TIMESTAMP`, answer.SurveyID)
	if err != nil {
		return err
	}

	// 检查是否达到总上限并自动完结
	var totalTimes sql.NullInt64
	var totalCount int
	if err := tx.QueryRow(`SELECT total_times FROM surveys WHERE id = ?`, answer.SurveyID).
		Scan(&totalTimes); err == nil {
		if totalTimes.Valid && totalTimes.Int64 > 0 {
			if err := tx.QueryRow(`SELECT COUNT(*) FROM answers WHERE survey_id = ? AND is_delete = 0`, answer.SurveyID).
				Scan(&totalCount); err == nil {
				if int64(totalCount) >= totalTimes.Int64 {
					_, _ = tx.Exec(`UPDATE surveys SET survey_status = 2 WHERE id = ?`, answer.SurveyID)
				}
			}
		}
	}

	return tx.Commit()
}

// VerifySurveyOwnership 验证问卷所有权
func (r *repositoryImpl) VerifySurveyOwnership(surveyID int, username string) error {
	db := config.DB

	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM surveys s
		JOIN projects p ON s.project_id = p.id
		WHERE s.id = ? AND p.create_by = ?`, surveyID, username).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrPermissionDenied
	}
	return nil
}

// GetAnswersBySurveyID 获取问卷的所有答案
func (r *repositoryImpl) GetAnswersBySurveyID(surveyID int) ([]model.Answer, error) {
	db := config.DB

	answers := make([]model.Answer, 0)
	rows, err := db.Query(`
		SELECT a.id, a.survey_id, a.user_id, a.user_account, a.create_time
		FROM answers a
		WHERE a.survey_id = ? AND a.is_delete = 0`, surveyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var a model.Answer
		if err := rows.Scan(&a.ID, &a.SurveyID, &a.UserID, &a.UserAccount, &a.CreateTime); err != nil {
			return nil, err
		}

		// 获取答案详情
		details, err := r.getAnswerDetails(a.ID)
		if err != nil {
			return nil, err
		}
		a.Questions = details

		answers = append(answers, a)
	}

	return answers, nil
}

// GetAnswerByIDWithPermission 根据ID获取答案（带权限验证）
func (r *repositoryImpl) GetAnswerByIDWithPermission(answerID int, username string) (*model.Answer, error) {
	db := config.DB

	var answer model.Answer
	err := db.QueryRow(`
		SELECT a.id, a.survey_id, a.user_id, a.user_account, a.create_time
		FROM answers a
		JOIN surveys s ON a.survey_id = s.id
		JOIN projects p ON s.project_id = p.id
		WHERE a.id = ? AND p.create_by = ? AND a.is_delete = 0`, answerID, username).
		Scan(&answer.ID, &answer.SurveyID, &answer.UserID, &answer.UserAccount, &answer.CreateTime)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrAnswerNotFound
		}
		return nil, err
	}

	// 获取答案详情
	details, err := r.getAnswerDetails(answer.ID)
	if err != nil {
		return nil, err
	}
	answer.Questions = details

	return &answer, nil
}

// getAnswerDetails 获取答案详情（内部方法）
func (r *repositoryImpl) getAnswerDetails(answerID int) ([]model.AnswerDetail, error) {
	db := config.DB

	rows, err := db.Query(`
		SELECT question_id, selected_options
		FROM answer_details
		WHERE answer_id = ?`, answerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var details []model.AnswerDetail
	for rows.Next() {
		var d model.AnswerDetail
		var optionsStr string
		if err := rows.Scan(&d.QuestionID, &optionsStr); err != nil {
			return nil, err
		}

		// 解析 selected_options
		d.SelectedOptions, d.SelectChoices = parseSelectedOptions(optionsStr)
		details = append(details, d)
	}

	return details, nil
}

// parseSelectedOptions 解析选项字符串
func parseSelectedOptions(optionsStr string) ([]int, string) {
	// 优先解析新格式 JSON 对象
	var obj struct {
		Texts   []string `json:"texts"`
		Indices []int    `json:"indices"`
	}
	if err := json.Unmarshal([]byte(optionsStr), &obj); err == nil {
		indices := obj.Indices
		if indices == nil {
			indices = []int{}
		}
		selectChoices := ""
		if len(obj.Texts) > 0 {
			selectChoices = obj.Texts[0]
		}
		return indices, selectChoices
	}

	// 尝试解析为 JSON 数组
	var arrInt []int
	if err := json.Unmarshal([]byte(optionsStr), &arrInt); err == nil {
		return arrInt, ""
	}

	// 回退：逗号分隔字符串
	indices := []int{}
	for _, opt := range strings.Split(optionsStr, ",") {
		var optInt int
		if _, scanErr := fmt.Sscan(strings.TrimSpace(opt), &optInt); scanErr == nil {
			indices = append(indices, optInt)
		}
	}

	// 若原始是数字文本，保存在 SelectChoices
	selectChoices := ""
	if len(indices) == 0 && strings.TrimSpace(optionsStr) != "" {
		selectChoices = strings.TrimSpace(optionsStr)
	}

	return indices, selectChoices
}

// VerifyAnswerOwnership 验证答案所有权
func (r *repositoryImpl) VerifyAnswerOwnership(answerID int, username string) error {
	db := config.DB

	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) 
		FROM answers a
		JOIN surveys s ON a.survey_id = s.id
		JOIN projects p ON s.project_id = p.id
		WHERE a.id = ? AND p.create_by = ? AND a.is_delete = 0`, answerID, username).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrPermissionDenied
	}
	return nil
}

// VerifyBatchAnswerOwnership 验证批量答案所有权
func (r *repositoryImpl) VerifyBatchAnswerOwnership(answerIDs []int, username string) (int, error) {
	db := config.DB

	placeholders := strings.Repeat("?,", len(answerIDs))
	placeholders = placeholders[:len(placeholders)-1]

	query := fmt.Sprintf(`
		SELECT COUNT(*) 
		FROM answers a
		JOIN surveys s ON a.survey_id = s.id
		JOIN projects p ON s.project_id = p.id
		WHERE a.id IN (%s) AND p.create_by = ? AND a.is_delete = 0`, placeholders)

	args := make([]interface{}, len(answerIDs)+1)
	for i, id := range answerIDs {
		args[i] = id
	}
	args[len(answerIDs)] = username

	var count int
	if err := db.QueryRow(query, args...).Scan(&count); err != nil {
		return 0, err
	}

	return count, nil
}

// DeleteAnswerByID 逻辑删除答案
func (r *repositoryImpl) DeleteAnswerByID(answerID int) error {
	db := config.DB

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 逻辑删除答案主表
	if _, err := tx.Exec("UPDATE answers SET is_delete = 1, deleted_at = CURRENT_TIMESTAMP WHERE id = ?", answerID); err != nil {
		return err
	}

	// 逻辑删除提交记录表
	if _, err := tx.Exec("UPDATE survey_submissions SET is_delete = 1, deleted_at = CURRENT_TIMESTAMP WHERE answer_id = ?", answerID); err != nil {
		return err
	}

	// 更新统计：递减提交次数
	var surveyID int
	if err := tx.QueryRow("SELECT survey_id FROM answers WHERE id = ?", answerID).Scan(&surveyID); err == nil {
		_, _ = tx.Exec("UPDATE survey_stats SET submit_count = GREATEST(0, submit_count - 1) WHERE survey_id = ?", surveyID)
	}

	return tx.Commit()
}

// BatchDeleteAnswers 批量逻辑删除答案
func (r *repositoryImpl) BatchDeleteAnswers(answerIDs []int) (int, error) {
	db := config.DB

	if len(answerIDs) == 0 {
		return 0, nil
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	placeholders := strings.Repeat("?,", len(answerIDs))
	placeholders = placeholders[:len(placeholders)-1]

	args := make([]interface{}, len(answerIDs))
	for i, id := range answerIDs {
		args[i] = id
	}

	// 批量逻辑删除答案主表
	queryAnswers := fmt.Sprintf("UPDATE answers SET is_delete = 1, deleted_at = CURRENT_TIMESTAMP WHERE id IN (%s)", placeholders)
	res, err := tx.Exec(queryAnswers, args...)
	if err != nil {
		return 0, err
	}

	// 批量逻辑删除提交记录表
	querySubmissions := fmt.Sprintf("UPDATE survey_submissions SET is_delete = 1, deleted_at = CURRENT_TIMESTAMP WHERE answer_id IN (%s)", placeholders)
	if _, err := tx.Exec(querySubmissions, args...); err != nil {
		return 0, err
	}

	// 更新统计：按问卷递减提交次数
	// 先找出这些答案分别属于哪些问卷及其数量
	queryStats := fmt.Sprintf("SELECT survey_id, COUNT(*) FROM answers WHERE id IN (%s) GROUP BY survey_id", placeholders)
	statsRows, err := tx.Query(queryStats, args...)
	if err == nil {
		type surveyCount struct {
			id    int
			count int
		}
		var updates []surveyCount
		for statsRows.Next() {
			var sc surveyCount
			if err := statsRows.Scan(&sc.id, &sc.count); err == nil {
				updates = append(updates, sc)
			}
		}
		statsRows.Close()

		for _, sc := range updates {
			_, _ = tx.Exec("UPDATE survey_stats SET submit_count = GREATEST(0, submit_count - ?) WHERE survey_id = ?", sc.count, sc.id)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	count, _ := res.RowsAffected()
	return int(count), nil
}

// PhysicalDeleteExpiredAnswers 清理过期的回收站数据
func (r *repositoryImpl) PhysicalDeleteExpiredAnswers(days int) (int, error) {
	db := config.DB

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// 找出所有过期且已逻辑删除的答案ID
	query := "SELECT id FROM answers WHERE is_delete = 1 AND deleted_at < DATE_SUB(CURRENT_TIMESTAMP, INTERVAL ? DAY)"
	rows, err := tx.Query(query, days)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var answerIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err == nil {
			answerIDs = append(answerIDs, id)
		}
	}

	if len(answerIDs) == 0 {
		return 0, nil
	}

	placeholders := strings.Repeat("?,", len(answerIDs))
	placeholders = placeholders[:len(placeholders)-1]

	args := make([]interface{}, len(answerIDs))
	for i, id := range answerIDs {
		args[i] = id
	}

	// 1. 删除答案详情
	queryDetails := fmt.Sprintf("DELETE FROM answer_details WHERE answer_id IN (%s)", placeholders)
	if _, err := tx.Exec(queryDetails, args...); err != nil {
		return 0, err
	}

	// 2. 删除提交记录
	querySubmissions := fmt.Sprintf("DELETE FROM survey_submissions WHERE answer_id IN (%s)", placeholders)
	if _, err := tx.Exec(querySubmissions, args...); err != nil {
		return 0, err
	}

	// 3. 删除答案主表
	queryAnswers := fmt.Sprintf("DELETE FROM answers WHERE id IN (%s)", placeholders)
	res, err := tx.Exec(queryAnswers, args...)
	if err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	count, _ := res.RowsAffected()
	return int(count), nil
}

// GetDeletedAnswersBySurveyID 获取已删除答案列表 (回收站)
func (r *repositoryImpl) GetDeletedAnswersBySurveyID(surveyID int) ([]model.Answer, error) {
	db := config.DB

	answers := make([]model.Answer, 0)
	rows, err := db.Query(`
		SELECT a.id, a.survey_id, a.user_id, a.user_account, a.create_time, a.deleted_at
		FROM answers a
		WHERE a.survey_id = ? AND a.is_delete = 1`, surveyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var a model.Answer
		if err := rows.Scan(&a.ID, &a.SurveyID, &a.UserID, &a.UserAccount, &a.CreateTime, &a.DeletedAt); err != nil {
			return nil, err
		}

		// 获取答案详情
		details, err := r.getAnswerDetails(a.ID)
		if err != nil {
			return nil, err
		}
		a.Questions = details

		answers = append(answers, a)
	}

	return answers, nil
}

// RestoreAnswerByID 恢复已删除答案
func (r *repositoryImpl) RestoreAnswerByID(answerID int) error {
	db := config.DB

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 恢复答案主表
	if _, err := tx.Exec("UPDATE answers SET is_delete = 0, deleted_at = NULL WHERE id = ?", answerID); err != nil {
		return err
	}

	// 恢复提交记录表
	if _, err := tx.Exec("UPDATE survey_submissions SET is_delete = 0, deleted_at = NULL WHERE answer_id = ?", answerID); err != nil {
		return err
	}

	// 更新统计：递增提交次数
	var surveyID int
	if err := tx.QueryRow("SELECT survey_id FROM answers WHERE id = ?", answerID).Scan(&surveyID); err == nil {
		_, _ = tx.Exec("UPDATE survey_stats SET submit_count = submit_count + 1 WHERE survey_id = ?", surveyID)
	}

	return tx.Commit()
}

// BatchRestoreAnswers 批量恢复已删除答案
func (r *repositoryImpl) BatchRestoreAnswers(answerIDs []int) (int, error) {
	db := config.DB

	if len(answerIDs) == 0 {
		return 0, nil
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	placeholders := strings.Repeat("?,", len(answerIDs))
	placeholders = placeholders[:len(placeholders)-1]

	args := make([]interface{}, len(answerIDs))
	for i, id := range answerIDs {
		args[i] = id
	}

	// 批量恢复答案主表
	queryAnswers := fmt.Sprintf("UPDATE answers SET is_delete = 0, deleted_at = NULL WHERE id IN (%s)", placeholders)
	res, err := tx.Exec(queryAnswers, args...)
	if err != nil {
		return 0, err
	}

	// 批量恢复提交记录表
	querySubmissions := fmt.Sprintf("UPDATE survey_submissions SET is_delete = 0, deleted_at = NULL WHERE answer_id IN (%s)", placeholders)
	if _, err := tx.Exec(querySubmissions, args...); err != nil {
		return 0, err
	}

	// 更新统计：按问卷递增提交次数
	queryStats := fmt.Sprintf("SELECT survey_id, COUNT(*) FROM answers WHERE id IN (%s) GROUP BY survey_id", placeholders)
	statsRows, err := tx.Query(queryStats, args...)
	if err == nil {
		type surveyCount struct {
			id    int
			count int
		}
		var updates []surveyCount
		for statsRows.Next() {
			var sc surveyCount
			if err := statsRows.Scan(&sc.id, &sc.count); err == nil {
				updates = append(updates, sc)
			}
		}
		statsRows.Close()

		for _, sc := range updates {
			_, _ = tx.Exec("UPDATE survey_stats SET submit_count = submit_count + ? WHERE survey_id = ?", sc.count, sc.id)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	count, _ := res.RowsAffected()
	return int(count), nil
}

// VerifyDeletedAnswerOwnership 验证已删除答案所有权
func (r *repositoryImpl) VerifyDeletedAnswerOwnership(answerID int, username string) error {
	db := config.DB

	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) 
		FROM answers a
		JOIN surveys s ON a.survey_id = s.id
		JOIN projects p ON s.project_id = p.id
		WHERE a.id = ? AND p.create_by = ? AND a.is_delete = 1`, answerID, username).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrPermissionDenied
	}
	return nil
}

// VerifyBatchDeletedAnswerOwnership 验证批量已删除答案所有权
func (r *repositoryImpl) VerifyBatchDeletedAnswerOwnership(answerIDs []int, username string) (int, error) {
	db := config.DB

	placeholders := strings.Repeat("?,", len(answerIDs))
	placeholders = placeholders[:len(placeholders)-1]

	query := fmt.Sprintf(`
		SELECT COUNT(*) 
		FROM answers a
		JOIN surveys s ON a.survey_id = s.id
		JOIN projects p ON s.project_id = p.id
		WHERE a.id IN (%s) AND p.create_by = ? AND a.is_delete = 1`, placeholders)

	args := make([]interface{}, len(answerIDs)+1)
	for i, id := range answerIDs {
		args[i] = id
	}
	args[len(answerIDs)] = username

	var count int
	if err := db.QueryRow(query, args...).Scan(&count); err != nil {
		return 0, err
	}

	return count, nil
}

// PhysicalDeleteAnswerByID 物理删除答案
func (r *repositoryImpl) PhysicalDeleteAnswerByID(answerID int) error {
	db := config.DB

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 先获取 survey_id 用于更新统计
	var surveyID int
	if err := tx.QueryRow("SELECT survey_id FROM answers WHERE id = ?", answerID).Scan(&surveyID); err != nil {
		return err
	}

	// 物理删除答案详情
	if _, err := tx.Exec("DELETE FROM answer_details WHERE answer_id = ?", answerID); err != nil {
		return err
	}

	// 物理删除提交记录
	if _, err := tx.Exec("DELETE FROM survey_submissions WHERE answer_id = ?", answerID); err != nil {
		return err
	}

	// 物理删除答案主表
	if _, err := tx.Exec("DELETE FROM answers WHERE id = ?", answerID); err != nil {
		return err
	}

	// 更新统计：递减提交次数
	_, _ = tx.Exec("UPDATE survey_stats SET submit_count = GREATEST(0, submit_count - 1) WHERE survey_id = ?", surveyID)

	return tx.Commit()
}

// BatchPhysicalDeleteAnswers 批量物理删除答案
func (r *repositoryImpl) BatchPhysicalDeleteAnswers(answerIDs []int) (int, error) {
	db := config.DB

	if len(answerIDs) == 0 {
		return 0, nil
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	placeholders := strings.Repeat("?,", len(answerIDs))
	placeholders = placeholders[:len(placeholders)-1]

	args := make([]interface{}, len(answerIDs))
	for i, id := range answerIDs {
		args[i] = id
	}

	// 先获取这些答案所属的问卷统计
	queryStats := fmt.Sprintf("SELECT survey_id, COUNT(*) FROM answers WHERE id IN (%s) GROUP BY survey_id", placeholders)
	statsRows, err := tx.Query(queryStats, args...)
	type surveyCount struct {
		id    int
		count int
	}
	var updates []surveyCount
	if err == nil {
		for statsRows.Next() {
			var sc surveyCount
			if err := statsRows.Scan(&sc.id, &sc.count); err == nil {
				updates = append(updates, sc)
			}
		}
		statsRows.Close()
	}

	// 批量物理删除答案详情
	queryDetails := fmt.Sprintf("DELETE FROM answer_details WHERE answer_id IN (%s)", placeholders)
	if _, err := tx.Exec(queryDetails, args...); err != nil {
		return 0, err
	}

	// 批量物理删除提交记录
	querySubmissions := fmt.Sprintf("DELETE FROM survey_submissions WHERE answer_id IN (%s)", placeholders)
	if _, err := tx.Exec(querySubmissions, args...); err != nil {
		return 0, err
	}

	// 批量物理删除答案主表
	queryAnswers := fmt.Sprintf("DELETE FROM answers WHERE id IN (%s)", placeholders)
	res, err := tx.Exec(queryAnswers, args...)
	if err != nil {
		return 0, err
	}

	// 更新统计：按问卷递减提交次数
	for _, sc := range updates {
		_, _ = tx.Exec("UPDATE survey_stats SET submit_count = GREATEST(0, submit_count - ?) WHERE survey_id = ?", sc.count, sc.id)
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	count, _ := res.RowsAffected()
	return int(count), nil
}
