package answer

import (
	"Dext-Server/config"
	"Dext-Server/model"
	"database/sql"
	"errors"
	"strconv"
	"strings"
)

// Service 定义答案业务逻辑接口
type Service interface {
	// 提交答案
	SubmitAnswer(answer *model.Answer, userID, username string) error

	// 获取问卷下所有答案
	GetAnswersBySurvey(surveyID int, username string) ([]model.Answer, error)

	// 根据ID获取答案
	GetAnswerByID(answerID int, username string) (*model.Answer, error)

	// 删除单个答案
	DeleteAnswer(answerID int, username string) error

	// 批量删除答案
	BatchDeleteAnswers(answerIDs []int, username string) (int, error)

	// 物理删除单个答案 (仅创建者可用)
	PhysicalDeleteAnswer(answerID int, username string) error

	// 批量物理删除答案 (仅创建者可用)
	BatchPhysicalDeleteAnswers(answerIDs []int, username string) (int, error)

	// 获取已删除答案列表 (回收站)
	GetDeletedAnswers(surveyID int, username string) ([]model.Answer, error)

	// 恢复已删除答案
	RestoreAnswer(answerID int, username string) error

	// 批量恢复已删除答案
	BatchRestoreAnswers(answerIDs []int, username string) (int, error)

	// 清理回收站 (定时任务调用)
	CleanupRecycleBin(days int) (int, error)
}

// serviceImpl 实现 Service 接口
type serviceImpl struct {
	repo Repository
}

// NewService 创建答案服务实例
func NewService(repo Repository) Service {
	return &serviceImpl{
		repo: repo,
	}
}

// SubmitAnswer 提交答案
func (s *serviceImpl) SubmitAnswer(answer *model.Answer, userID, username string) error {
	// 检查提交限制
	if err := s.repo.CheckSubmitLimit(answer.SurveyID, userID); err != nil {
		return err
	}

	// 验证答案内容
	if err := s.validateAnswerContent(answer); err != nil {
		return err
	}

	// 保存答案
	return s.repo.SaveAnswer(answer, userID, username)
}

// validateAnswerContent 验证答案内容
func (s *serviceImpl) validateAnswerContent(answer *model.Answer) error {
	db := config.DB

	// 获取问卷的所有题目
	rows, err := db.Query(`
		SELECT id, question_type, required
		FROM questions
		WHERE survey_id = ?`, answer.SurveyID)
	if err != nil {
		return err
	}
	defer rows.Close()

	// 构建题目映射
	questions := make(map[int]*model.Question)
	for rows.Next() {
		q := &model.Question{}
		if err := rows.Scan(&q.ID, &q.QuestionType, &q.Required); err != nil {
			return err
		}
		questions[q.ID] = q
	}

	// 遍历答案并验证
	for _, answerDetail := range answer.Questions {
		question, exists := questions[answerDetail.QuestionID]
		if !exists {
			continue
		}

		// 对于输入题（question_type = 4），验证字数限制
		if question.QuestionType == 4 {
			// 从 answerDetail.Texts 字段获取输入内容
			// 前端提交的 answer 字段是 List<String>，输入题取第一个元素
			var inputText string
			if len(answerDetail.Texts) > 0 {
				inputText = answerDetail.Texts[0]
			}

			if inputText != "" {
				if err := s.validateTextInputLength(answerDetail.QuestionID, inputText); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// validateTextInputLength 验证输入题字数限制
func (s *serviceImpl) validateTextInputLength(questionID int, answer string) error {
	db := config.DB

	// 获取题目的选项配置
	var optionText string
	err := db.QueryRow(`
		SELECT option_text
		FROM options
		WHERE question_id = ?
		LIMIT 1`, questionID).Scan(&optionText)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil // 没有配置，不验证
		}
		return err
	}

	// 解析 maxLength 配置
	maxLength := 500 // 默认值
	parts := strings.Split(optionText, "|")
	for _, part := range parts {
		if strings.HasPrefix(part, "maxLength:") {
			if length, err := strconv.Atoi(strings.TrimPrefix(part, "maxLength:")); err == nil {
				maxLength = length
			}
			break
		}
	}

	// 验证字数
	if len([]rune(answer)) > maxLength {
		return errors.New("输入内容超过字数限制")
	}

	return nil
}

// GetAnswersBySurvey 获取问卷下所有答案
func (s *serviceImpl) GetAnswersBySurvey(surveyID int, username string) ([]model.Answer, error) {
	// 验证权限
	if err := s.repo.VerifySurveyOwnership(surveyID, username); err != nil {
		return nil, err
	}

	// 获取答案列表
	return s.repo.GetAnswersBySurveyID(surveyID)
}

// GetAnswerByID 根据ID获取答案
func (s *serviceImpl) GetAnswerByID(answerID int, username string) (*model.Answer, error) {
	// 验证权限并获取答案
	return s.repo.GetAnswerByIDWithPermission(answerID, username)
}

// DeleteAnswer 删除单个答案
func (s *serviceImpl) DeleteAnswer(answerID int, username string) error {
	// 验证权限
	if err := s.repo.VerifyAnswerOwnership(answerID, username); err != nil {
		return err
	}

	// 删除答案
	return s.repo.DeleteAnswerByID(answerID)
}

// BatchDeleteAnswers 批量逻辑删除答案
func (s *serviceImpl) BatchDeleteAnswers(answerIDs []int, username string) (int, error) {
	// 验证权限（用户自己或创建者，这里 VerifyBatchAnswerOwnership 已经包含了这个逻辑）
	validCount, err := s.repo.VerifyBatchAnswerOwnership(answerIDs, username)
	if err != nil {
		return 0, err
	}

	if validCount != len(answerIDs) {
		return 0, ErrPartialPermissionDenied
	}

	// 批量逻辑删除
	return s.repo.BatchDeleteAnswers(answerIDs)
}

// PhysicalDeleteAnswer 物理删除单个答案
func (s *serviceImpl) PhysicalDeleteAnswer(answerID int, username string) error {
	// 物理删除必须是问卷创建者
	// 先获取答案对应的问卷ID
	answer, err := s.repo.GetAnswerByIDWithPermission(answerID, username)
	if err != nil {
		return err
	}

	// 验证问卷所有权
	if err := s.repo.VerifySurveyOwnership(answer.SurveyID, username); err != nil {
		return err
	}

	return s.repo.PhysicalDeleteAnswerByID(answerID)
}

// BatchPhysicalDeleteAnswers 批量物理删除答案
func (s *serviceImpl) BatchPhysicalDeleteAnswers(answerIDs []int, username string) (int, error) {
	// 物理删除必须是问卷创建者
	// 这里简单起见，逐个验证或批量验证所有权
	// 由于 VerifyBatchAnswerOwnership 已经检查了 p.create_by = username，
	// 且 answers 表 join 了 surveys 和 projects，这实际上已经保证了只有创建者能通过验证。

	validCount, err := s.repo.VerifyBatchAnswerOwnership(answerIDs, username)
	if err != nil {
		return 0, err
	}

	if validCount != len(answerIDs) {
		return 0, ErrPartialPermissionDenied
	}

	return s.repo.BatchPhysicalDeleteAnswers(answerIDs)
}

// GetDeletedAnswers 获取已删除答案列表 (回收站)
func (s *serviceImpl) GetDeletedAnswers(surveyID int, username string) ([]model.Answer, error) {
	// 验证问卷所有权 (只有创建者能看回收站)
	if err := s.repo.VerifySurveyOwnership(surveyID, username); err != nil {
		return nil, err
	}

	return s.repo.GetDeletedAnswersBySurveyID(surveyID)
}

// RestoreAnswer 恢复已删除答案
func (s *serviceImpl) RestoreAnswer(answerID int, username string) error {
	// 验证已删除答案的所有权 (只有创建者能恢复)
	if err := s.repo.VerifyDeletedAnswerOwnership(answerID, username); err != nil {
		return err
	}

	return s.repo.RestoreAnswerByID(answerID)
}

// BatchRestoreAnswers 批量恢复已删除答案
func (s *serviceImpl) BatchRestoreAnswers(answerIDs []int, username string) (int, error) {
	// 验证批量已删除答案的所有权
	validCount, err := s.repo.VerifyBatchDeletedAnswerOwnership(answerIDs, username)
	if err != nil {
		return 0, err
	}

	if validCount != len(answerIDs) {
		return 0, ErrPartialPermissionDenied
	}

	return s.repo.BatchRestoreAnswers(answerIDs)
}

// CleanupRecycleBin 清理回收站 (定时任务调用)
func (s *serviceImpl) CleanupRecycleBin(days int) (int, error) {
	return s.repo.PhysicalDeleteExpiredAnswers(days)
}
