package main

import (
	"database/sql"
	"log"
)

// OAuth邮箱冲突处理策略
type ConflictPolicy int

const (
	// 允许登录，记录冲突但不更新主账号邮箱
	PolicyAllowWithWarning ConflictPolicy = iota
	// 拒绝登录，要求用户手动处理冲突
	PolicyRejectLogin
	// 强制解绑冲突用户的邮箱（危险操作）
	PolicyForceUnbind
	// 创建新账号，不关联现有账号
	PolicyCreateNewAccount
)

// 邮箱冲突处理器
type EmailConflictHandler struct {
	db     *sql.DB
	policy ConflictPolicy
}

// 创建邮箱冲突处理器
func NewEmailConflictHandler(db *sql.DB, policy ConflictPolicy) *EmailConflictHandler {
	return &EmailConflictHandler{
		db:     db,
		policy: policy,
	}
}

// 处理OAuth邮箱变更冲突
func (h *EmailConflictHandler) HandleEmailConflict(
	userID, provider, oldEmail, newEmail string,
) (bool, error) {
	// 检查是否存在冲突
	var conflictUserID string
	err := h.db.QueryRow(`
		SELECT id FROM users WHERE email = ? AND id != ?
	`, newEmail, userID).Scan(&conflictUserID)

	if err == sql.ErrNoRows {
		// 没有冲突，可以正常更新
		return true, nil
	}

	if err != nil {
		return false, err
	}

	// 存在冲突，根据策略处理
	log.Printf("检测到邮箱冲突: 用户 %s 的 %s OAuth邮箱从 %s 变更为 %s，但 %s 已被用户 %s 使用",
		userID, provider, oldEmail, newEmail, newEmail, conflictUserID)

	// 记录冲突到数据库
	_, err = h.db.Exec(`
		INSERT INTO oauth_email_conflicts (
			user_id, provider, old_email, new_email, 
			conflict_user_id, conflict_type
		) VALUES (?, ?, ?, ?, ?, 'email_occupied')
	`, userID, provider, oldEmail, newEmail, conflictUserID)

	if err != nil {
		log.Printf("记录邮箱冲突失败: %v", err)
	}

	switch h.policy {
	case PolicyAllowWithWarning:
		return h.handleAllowWithWarning(userID, provider, oldEmail, newEmail, conflictUserID)
	case PolicyRejectLogin:
		return h.handleRejectLogin(userID, provider, oldEmail, newEmail, conflictUserID)
	case PolicyForceUnbind:
		return h.handleForceUnbind(userID, provider, oldEmail, newEmail, conflictUserID)
	case PolicyCreateNewAccount:
		return h.handleCreateNewAccount(userID, provider, oldEmail, newEmail, conflictUserID)
	default:
		return h.handleAllowWithWarning(userID, provider, oldEmail, newEmail, conflictUserID)
	}
}

// 策略1: 允许登录但记录警告
func (h *EmailConflictHandler) handleAllowWithWarning(
	userID, provider, oldEmail, newEmail, conflictUserID string,
) (bool, error) {
	_ = oldEmail // 记录但不在此策略中使用
	_ = conflictUserID // 记录但不在此策略中使用
	log.Printf("采用策略: 允许登录但不更新主账号邮箱，避免邮箱占用冲突")
	
	// 更新冲突解决状态
	_, err := h.db.Exec(`
		UPDATE oauth_email_conflicts 
		SET resolution_status = 'resolved', 
			resolved_at = NOW(),
			resolution_method = 'allow_with_warning',
			notes = '允许登录，保持OAuth绑定信息更新但不影响主账号邮箱'
		WHERE user_id = ? AND provider = ? AND new_email = ?
	`, userID, provider, newEmail)

	if err != nil {
		log.Printf("更新冲突解决状态失败: %v", err)
	}

	return true, nil
}

// 策略2: 拒绝登录
func (h *EmailConflictHandler) handleRejectLogin(
	userID, provider, oldEmail, newEmail, conflictUserID string,
) (bool, error) {
	_ = oldEmail // 记录但不在此策略中使用
	_ = conflictUserID // 记录但不在此策略中使用
	log.Printf("采用策略: 拒绝登录，要求用户手动处理邮箱冲突")
	
	// 记录拒绝原因
	_, err := h.db.Exec(`
		UPDATE oauth_email_conflicts 
		SET resolution_status = 'pending',
			resolution_method = 'reject_login',
			notes = '拒绝登录，需要用户手动解决邮箱冲突'
		WHERE user_id = ? AND provider = ? AND new_email = ?
	`, userID, provider, newEmail)

	if err != nil {
		log.Printf("更新冲突状态失败: %v", err)
	}

	return false, nil
}

// 策略3: 强制解绑冲突用户邮箱（危险操作）
func (h *EmailConflictHandler) handleForceUnbind(
	userID, provider, oldEmail, newEmail, conflictUserID string,
) (bool, error) {
	_ = oldEmail // 记录但不在此策略中使用
	log.Printf("采用策略: 强制解绑冲突用户的邮箱 (危险操作)")
	
	// 清空冲突用户的邮箱
	_, err := h.db.Exec(`
		UPDATE users SET email = NULL WHERE id = ?
	`, conflictUserID)

	if err != nil {
		log.Printf("强制解绑冲突用户邮箱失败: %v", err)
		return false, err
	}

	// 记录解决方案
	_, err = h.db.Exec(`
		UPDATE oauth_email_conflicts 
		SET resolution_status = 'resolved',
			resolved_at = NOW(),
			resolution_method = 'force_unbind',
			notes = '强制清空冲突用户邮箱，允许OAuth用户使用该邮箱'
		WHERE user_id = ? AND provider = ? AND new_email = ?
	`, userID, provider, newEmail)

	if err != nil {
		log.Printf("更新冲突解决状态失败: %v", err)
	}

	log.Printf("已强制解绑用户 %s 的邮箱 %s", conflictUserID, newEmail)
	return true, nil
}

// 策略4: 创建新账号
func (h *EmailConflictHandler) handleCreateNewAccount(
	userID, provider, oldEmail, newEmail, conflictUserID string,
) (bool, error) {
	_ = oldEmail // 记录但不在此策略中使用
	_ = conflictUserID // 记录但不在此策略中使用
	log.Printf("采用策略: 为OAuth用户创建新账号")
	
	// 这个策略需要在调用方实现，因为涉及到用户创建逻辑
	// 这里只记录决策
	_, err := h.db.Exec(`
		UPDATE oauth_email_conflicts 
		SET resolution_status = 'resolved',
			resolved_at = NOW(),
			resolution_method = 'create_new_account',
			notes = '为OAuth用户创建新账号，避免邮箱冲突'
		WHERE user_id = ? AND provider = ? AND new_email = ?
	`, userID, provider, newEmail)

	if err != nil {
		log.Printf("更新冲突解决状态失败: %v", err)
	}

	return false, nil // 返回false表示需要创建新账号
}

// 获取系统配置的冲突处理策略
func GetConflictPolicy() ConflictPolicy {
	// 可以从环境变量或配置文件读取
	// 默认使用最安全的策略
	return PolicyAllowWithWarning
}
