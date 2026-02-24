-- OAuth邮箱冲突处理策略
-- 处理OAuth服务商邮箱变更导致的邮箱占用问题

-- 创建邮箱冲突日志表
CREATE TABLE IF NOT EXISTS oauth_email_conflicts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    provider VARCHAR(20) NOT NULL,
    old_email VARCHAR(255),
    new_email VARCHAR(255) NOT NULL,
    conflict_user_id VARCHAR(64),
    conflict_type ENUM('email_occupied', 'email_changed', 'binding_conflict') NOT NULL,
    resolution_status ENUM('pending', 'resolved', 'ignored') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    resolution_method VARCHAR(100),
    notes TEXT,
    
    INDEX idx_user_provider (user_id, provider),
    INDEX idx_conflict_user (conflict_user_id),
    INDEX idx_status (resolution_status),
    INDEX idx_created (created_at)
);

-- 创建邮箱变更历史表
CREATE TABLE IF NOT EXISTS oauth_email_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    provider VARCHAR(20) NOT NULL,
    old_email VARCHAR(255),
    new_email VARCHAR(255) NOT NULL,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_user_provider (user_id, provider),
    INDEX idx_email_history (old_email, new_email),
    INDEX idx_changed_at (changed_at)
);

-- 查询邮箱冲突的存储过程
DELIMITER //
CREATE PROCEDURE CheckOAuthEmailConflict(
    IN p_user_id VARCHAR(64),
    IN p_provider VARCHAR(20),
    IN p_old_email VARCHAR(255),
    IN p_new_email VARCHAR(255)
)
BEGIN
    DECLARE conflict_user_id VARCHAR(64) DEFAULT NULL;
    DECLARE conflict_exists INT DEFAULT 0;
    
    -- 检查新邮箱是否被其他用户占用
    SELECT id INTO conflict_user_id 
    FROM users 
    WHERE email = p_new_email AND id != p_user_id 
    LIMIT 1;
    
    -- 如果存在冲突，记录到冲突表
    IF conflict_user_id IS NOT NULL THEN
        INSERT INTO oauth_email_conflicts (
            user_id, provider, old_email, new_email, 
            conflict_user_id, conflict_type
        ) VALUES (
            p_user_id, p_provider, p_old_email, p_new_email,
            conflict_user_id, 'email_occupied'
        );
        
        SET conflict_exists = 1;
    END IF;
    
    -- 记录邮箱变更历史
    INSERT INTO oauth_email_history (
        user_id, provider, old_email, new_email
    ) VALUES (
        p_user_id, p_provider, p_old_email, p_new_email
    );
    
    -- 返回冲突状态
    SELECT conflict_exists as has_conflict, conflict_user_id;
END //
DELIMITER ;

-- 解决邮箱冲突的存储过程
DELIMITER //
CREATE PROCEDURE ResolveOAuthEmailConflict(
    IN p_conflict_id INT,
    IN p_resolution_method VARCHAR(100),
    IN p_notes TEXT
)
BEGIN
    UPDATE oauth_email_conflicts 
    SET 
        resolution_status = 'resolved',
        resolved_at = CURRENT_TIMESTAMP,
        resolution_method = p_resolution_method,
        notes = p_notes
    WHERE id = p_conflict_id;
END //
DELIMITER ;

-- 查询用户的邮箱变更历史
DELIMITER //
CREATE PROCEDURE GetUserEmailHistory(
    IN p_user_id VARCHAR(64)
)
BEGIN
    SELECT 
        h.provider,
        h.old_email,
        h.new_email,
        h.changed_at,
        c.conflict_type,
        c.resolution_status
    FROM oauth_email_history h
    LEFT JOIN oauth_email_conflicts c ON (
        h.user_id = c.user_id 
        AND h.provider = c.provider 
        AND h.new_email = c.new_email
    )
    WHERE h.user_id = p_user_id
    ORDER BY h.changed_at DESC;
END //
DELIMITER ;
