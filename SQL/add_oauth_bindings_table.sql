-- OAuth bindings table - tracks user OAuth account binding status
CREATE TABLE IF NOT EXISTS oauth_bindings (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id VARCHAR(64) NOT NULL,
    provider VARCHAR(20) NOT NULL COMMENT 'OAuth provider: google, github, microsoft',
    provider_user_id VARCHAR(100) NOT NULL COMMENT 'Provider user ID',
    provider_email VARCHAR(255) NOT NULL COMMENT 'Provider account email',
    provider_username VARCHAR(100) COMMENT 'Provider account username',
    provider_name VARCHAR(100) COMMENT 'Provider account display name',
    provider_avatar VARCHAR(500) COMMENT 'Provider account avatar URL',
    is_primary BOOLEAN DEFAULT FALSE COMMENT 'Whether this is the primary login method',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    UNIQUE KEY unique_provider_user (provider, provider_user_id),
    UNIQUE KEY unique_user_provider (user_id, provider),
    INDEX idx_user_id (user_id),
    INDEX idx_provider (provider),
    INDEX idx_provider_email (provider_email),
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create binding records for existing OAuth users
-- Identify OAuth users by user ID prefix and create binding records
INSERT INTO oauth_bindings (user_id, provider, provider_user_id, provider_email, provider_username, provider_name, is_primary)
SELECT 
    u.id,
    CASE 
        WHEN u.id LIKE 'google_%' THEN 'google'
        WHEN u.id LIKE 'github_%' THEN 'github'
        WHEN u.id LIKE 'microsoft_%' THEN 'microsoft'
        WHEN u.id LIKE 'oauth_%' THEN 'google'  -- Default to google
        ELSE 'unknown'
    END as provider,
    SUBSTRING_INDEX(SUBSTRING_INDEX(u.id, '_', -1), '_', 1) as provider_user_id,
    u.email as provider_email,
    u.username as provider_username,
    u.username as provider_name,
    TRUE as is_primary
FROM users u
WHERE (u.id LIKE 'oauth_%' OR u.id LIKE 'google_%' OR u.id LIKE 'github_%' OR u.id LIKE 'microsoft_%')
AND NOT EXISTS (
    SELECT 1 FROM oauth_bindings ob WHERE ob.user_id = u.id
);
