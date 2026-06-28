-- Email verification code table
-- Store email verification codes for registration, password reset, and email change scenarios

CREATE TABLE IF NOT EXISTS email_verifications (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL COMMENT 'Target email address',
    code VARCHAR(6) NOT NULL COMMENT '6-digit verification code',
    purpose ENUM('register', 'reset_password', 'change_email', 'delete_account') NOT NULL COMMENT 'Verification purpose',
    user_id VARCHAR(64) NULL COMMENT 'Associated user ID (for password reset/email change)',
    verified BOOLEAN DEFAULT FALSE COMMENT 'Whether verified',
    expires_at DATETIME NOT NULL COMMENT 'Expiration time',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Creation time',
    verified_at DATETIME NULL COMMENT 'Verification time',
    
    INDEX idx_email (email),
    INDEX idx_code (code),
    INDEX idx_expires_at (expires_at),
    INDEX idx_email_purpose (email, purpose),
    INDEX idx_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Email verification code table';

-- users.email_verified / email_verified_at 已在 database_schema.sql 中,
-- 此前的 ALTER ADD COLUMN 是为老库升级,新装库由 CREATE TABLE 一次建好,留它会 1060。
-- idx_users_email_verified 同理,已在 schema 中内联。