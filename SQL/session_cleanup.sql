-- 会话清除和JWT令牌管理SQL脚本
-- 用于清理无效会话和优化令牌验证

-- 1. 创建会话表（如果不存在）
CREATE TABLE IF NOT EXISTS user_sessions (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    INDEX idx_user_id (user_id),
    INDEX idx_expires (expires_at),
    INDEX idx_token_hash (token_hash),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. 创建JWT黑名单表
CREATE TABLE IF NOT EXISTS jwt_blacklist (
    id INT PRIMARY KEY AUTO_INCREMENT,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    user_id VARCHAR(64),
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reason VARCHAR(100) DEFAULT 'manual_logout',
    INDEX idx_token_hash (token_hash),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. 清理过期会话
DELETE FROM user_sessions WHERE expires_at < NOW();

-- 4. 清理过期的JWT黑名单记录
DELETE FROM jwt_blacklist WHERE expires_at < NOW();

-- 5. 清理孤立的会话（用户不存在）
DELETE FROM user_sessions 
WHERE user_id NOT IN (SELECT id FROM users);

-- 6. 查找重复的活跃会话
SELECT user_id, COUNT(*) as session_count 
FROM user_sessions 
WHERE is_active = TRUE 
GROUP BY user_id 
HAVING COUNT(*) > 5;

-- 7. 限制每个用户的活跃会话数量（保留最新的5个）
DELETE s1 FROM user_sessions s1
INNER JOIN (
    SELECT user_id, id,
           ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY last_accessed DESC) as rn
    FROM user_sessions 
    WHERE is_active = TRUE
) s2 ON s1.id = s2.id
WHERE s2.rn > 5;

-- 8. 检查OAuth用户的令牌状态
SELECT 
    u.id,
    u.username,
    u.email,
    COUNT(s.id) as active_sessions,
    MAX(s.last_accessed) as last_session_access
FROM users u
LEFT JOIN user_sessions s ON u.id = s.user_id AND s.is_active = TRUE
WHERE u.email LIKE '%@%'
GROUP BY u.id, u.username, u.email;

-- 9. 创建定期清理的存储过程
DELIMITER //
CREATE PROCEDURE CleanupExpiredSessions()
BEGIN
    -- 清理过期会话
    DELETE FROM user_sessions WHERE expires_at < NOW();
    
    -- 清理过期JWT黑名单
    DELETE FROM jwt_blacklist WHERE expires_at < NOW();
    
    -- 限制每用户会话数
    DELETE s1 FROM user_sessions s1
    INNER JOIN (
        SELECT user_id, id,
               ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY last_accessed DESC) as rn
        FROM user_sessions 
        WHERE is_active = TRUE
    ) s2 ON s1.id = s2.id
    WHERE s2.rn > 10;
    
    SELECT 'Session cleanup completed' as status;
END //
DELIMITER ;

-- 10. 验证查询 - 检查当前系统状态
SELECT 
    'Total Users' as metric,
    COUNT(*) as count
FROM users
UNION ALL
SELECT 
    'Active Sessions' as metric,
    COUNT(*) as count
FROM user_sessions 
WHERE is_active = TRUE AND expires_at > NOW()
UNION ALL
SELECT 
    'Blacklisted Tokens' as metric,
    COUNT(*) as count
FROM jwt_blacklist 
WHERE expires_at > NOW();
