-- Add OAuth support database tables
-- Create OAuth account binding table
CREATE TABLE IF NOT EXISTS oauth_accounts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    provider VARCHAR(32) NOT NULL COMMENT 'OAuth provider: google, github, etc.',
    provider_user_id VARCHAR(255) NOT NULL COMMENT 'Third-party platform user ID',
    provider_email VARCHAR(255) NOT NULL COMMENT 'Third-party platform email',
    provider_name VARCHAR(255) COMMENT 'Third-party platform display name',
    created_at DATETIME NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Foreign key constraints
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE,
    
    -- Unique constraint: one third-party account can only bind to one local account
    UNIQUE KEY unique_provider_user (provider, provider_user_id),
    
    -- Indexes
    INDEX idx_username (username),
    INDEX idx_provider (provider),
    INDEX idx_provider_email (provider_email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='OAuth account binding table';

-- Add fields to existing users table (if not exists)
-- Check and add email column
SET @sql = IF((SELECT COUNT(*) FROM information_schema.COLUMNS 
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'email') = 0,
    'ALTER TABLE users ADD COLUMN email VARCHAR(255) UNIQUE COMMENT ''User email''',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Check and add display_name column
SET @sql = IF((SELECT COUNT(*) FROM information_schema.COLUMNS 
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'display_name') = 0,
    'ALTER TABLE users ADD COLUMN display_name VARCHAR(255) COMMENT ''Display name''',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Check and add avatar_url column
SET @sql = IF((SELECT COUNT(*) FROM information_schema.COLUMNS 
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'avatar_url') = 0,
    'ALTER TABLE users ADD COLUMN avatar_url VARCHAR(500) COMMENT ''Avatar URL''',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
