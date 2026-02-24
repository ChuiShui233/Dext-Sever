package answer

import (
	"Dext-Server/model"
	"Dext-Server/utils"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

var (
	answerService Service
)

// InitService 初始化答案服务
func InitService() {
	repo := NewRepository()
	answerService = NewService(repo)
}

// CleanupRecycleBinTask 定时清理回收站任务
func CleanupRecycleBinTask(days int) (int, error) {
	if answerService == nil {
		return 0, fmt.Errorf("answerService not initialized")
	}
	return answerService.CleanupRecycleBin(days)
}

// SubmitAnswerHandler 提交答案
func SubmitAnswerHandler(c *gin.Context) {
	var answer model.Answer
	if err := c.ShouldBindJSON(&answer); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的答案数据", err)
		return
	}

	userID := c.MustGet("user_id").(string)
	username := c.MustGet("username").(string)

	if err := answerService.SubmitAnswer(&answer, userID, username); err != nil {
		switch err {
		case ErrSurveyNotFound:
			utils.SendError(c, http.StatusBadRequest, "问卷不存在", err)
		case ErrPerUserLimitReached:
			utils.SendError(c, http.StatusForbidden, "已达到该问卷的单用户提交次数上限", nil)
		case ErrTotalLimitReached:
			utils.SendError(c, http.StatusForbidden, "该问卷的总提交次数已用尽", nil)
		default:
			utils.SendError(c, http.StatusInternalServerError, "提交答案失败", err)
		}
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "答案提交成功"})
}

// GetAnswersHandler 获取问卷下所有答案
func GetAnswersHandler(c *gin.Context) {
	surveyIDStr := c.Param("surveyId")
	username := c.MustGet("username").(string)

	surveyID, err := strconv.Atoi(surveyIDStr)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的问卷ID", err)
		return
	}

	answers, err := answerService.GetAnswersBySurvey(surveyID, username)
	if err != nil {
		if err == ErrPermissionDenied {
			utils.SendError(c, http.StatusForbidden, "无权查看答案", err)
		} else {
			utils.SendError(c, http.StatusInternalServerError, "获取答案列表失败", err)
		}
		return
	}

	c.JSON(http.StatusOK, answers)
}

// GetAnswerByIDHandler 根据答案ID获取答案
func GetAnswerByIDHandler(c *gin.Context) {
	idStr := c.Param("id")
	username := c.MustGet("username").(string)

	id, err := strconv.Atoi(idStr)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的答案ID", err)
		return
	}

	answer, err := answerService.GetAnswerByID(id, username)
	if err != nil {
		if err == ErrAnswerNotFound {
			log.Printf("拒绝连接: 访问不存在的答案 %d", id)
			c.AbortWithStatus(http.StatusNotFound)
		} else {
			utils.SendError(c, http.StatusInternalServerError, "获取答案失败", err)
		}
		return
	}

	c.JSON(http.StatusOK, answer)
}

// DeleteAnswerHandler 物理删除单个答案 (仅限创建者)
func DeleteAnswerHandler(c *gin.Context) {
	idStr := c.Param("id")
	username := c.MustGet("username").(string)

	id, err := strconv.Atoi(idStr)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的答案ID", err)
		return
	}

	if err := answerService.PhysicalDeleteAnswer(id, username); err != nil {
		if err == ErrPermissionDenied {
			utils.SendError(c, http.StatusForbidden, "答案不存在或无权限物理删除 (仅限创建者)", nil)
		} else {
			utils.SendError(c, http.StatusInternalServerError, "物理删除答案失败", err)
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "答案物理删除成功",
	})
}

// BatchDeleteAnswersHandler 批量物理删除答案 (仅限创建者)
func BatchDeleteAnswersHandler(c *gin.Context) {
	username := c.MustGet("username").(string)

	var request struct {
		AnswerIDs []int `json:"answerIds" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的请求数据", err)
		return
	}

	if len(request.AnswerIDs) == 0 {
		utils.SendError(c, http.StatusBadRequest, "未指定要删除的答案", nil)
		return
	}

	deletedCount, err := answerService.BatchPhysicalDeleteAnswers(request.AnswerIDs, username)
	if err != nil {
		if err == ErrPartialPermissionDenied {
			utils.SendError(c, http.StatusForbidden, "部分答案不存在或无权限物理删除", nil)
		} else {
			utils.SendError(c, http.StatusInternalServerError, "批量物理删除答案失败", err)
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      fmt.Sprintf("成功物理删除 %d 个答案", deletedCount),
		"deletedCount": deletedCount,
	})
}

// LogicDeleteAnswerHandler 逻辑删除单个答案
func LogicDeleteAnswerHandler(c *gin.Context) {
	idStr := c.Param("id")
	username := c.MustGet("username").(string)

	id, err := strconv.Atoi(idStr)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的答案ID", err)
		return
	}

	if err := answerService.DeleteAnswer(id, username); err != nil {
		if err == ErrPermissionDenied {
			utils.SendError(c, http.StatusForbidden, "答案不存在或无权限逻辑删除", nil)
		} else {
			utils.SendError(c, http.StatusInternalServerError, "逻辑删除答案失败", err)
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "答案逻辑删除成功",
	})
}

// BatchLogicDeleteAnswersHandler 批量逻辑删除答案
func BatchLogicDeleteAnswersHandler(c *gin.Context) {
	username := c.MustGet("username").(string)

	var request struct {
		AnswerIDs []int `json:"answerIds" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的请求数据", err)
		return
	}

	if len(request.AnswerIDs) == 0 {
		utils.SendError(c, http.StatusBadRequest, "未指定要删除的答案", nil)
		return
	}

	deletedCount, err := answerService.BatchDeleteAnswers(request.AnswerIDs, username)
	if err != nil {
		if err == ErrPartialPermissionDenied {
			utils.SendError(c, http.StatusForbidden, "部分答案不存在或无权限逻辑删除", nil)
		} else {
			utils.SendError(c, http.StatusInternalServerError, "批量逻辑删除答案失败", err)
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      fmt.Sprintf("成功逻辑删除 %d 个答案", deletedCount),
		"deletedCount": deletedCount,
	})
}

// GetDeletedAnswersHandler 获取回收站列表
func GetDeletedAnswersHandler(c *gin.Context) {
	surveyIDStr := c.Param("surveyId")
	username := c.MustGet("username").(string)

	surveyID, err := strconv.Atoi(surveyIDStr)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的问卷ID", err)
		return
	}

	answers, err := answerService.GetDeletedAnswers(surveyID, username)
	if err != nil {
		if err == ErrPermissionDenied {
			utils.SendError(c, http.StatusForbidden, "无权查看回收站", err)
		} else {
			utils.SendError(c, http.StatusInternalServerError, "获取回收站列表失败", err)
		}
		return
	}

	c.JSON(http.StatusOK, answers)
}

// RestoreAnswerHandler 恢复单个答案
func RestoreAnswerHandler(c *gin.Context) {
	idStr := c.Param("id")
	username := c.MustGet("username").(string)

	id, err := strconv.Atoi(idStr)
	if err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的答案ID", err)
		return
	}

	if err := answerService.RestoreAnswer(id, username); err != nil {
		if err == ErrPermissionDenied {
			utils.SendError(c, http.StatusForbidden, "答案不存在或无权限恢复", nil)
		} else {
			utils.SendError(c, http.StatusInternalServerError, "恢复答案失败", err)
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "答案恢复成功",
	})
}

// BatchRestoreAnswersHandler 批量恢复答案
func BatchRestoreAnswersHandler(c *gin.Context) {
	username := c.MustGet("username").(string)

	var request struct {
		AnswerIDs []int `json:"answerIds" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		utils.SendError(c, http.StatusBadRequest, "无效的请求数据", err)
		return
	}

	if len(request.AnswerIDs) == 0 {
		utils.SendError(c, http.StatusBadRequest, "未指定要恢复的答案", nil)
		return
	}

	restoredCount, err := answerService.BatchRestoreAnswers(request.AnswerIDs, username)
	if err != nil {
		if err == ErrPartialPermissionDenied {
			utils.SendError(c, http.StatusForbidden, "部分答案不存在或无权限恢复", nil)
		} else {
			utils.SendError(c, http.StatusInternalServerError, "批量恢复答案失败", err)
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":       fmt.Sprintf("成功恢复 %d 个答案", restoredCount),
		"restoredCount": restoredCount,
	})
}
