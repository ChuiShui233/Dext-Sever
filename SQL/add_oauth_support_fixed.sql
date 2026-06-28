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

-- users 表需要的列(email / display_name / avatar_url)已在 database_schema.sql 中,
-- 此前文件中基于 PREPARE 的 ADD COLUMN 与 MariaDB-only 的 CREATE INDEX IF NOT EXISTS
-- 全部移除,新装库不必再跑。
