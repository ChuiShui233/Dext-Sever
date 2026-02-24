-- Email verification code table
-- Store email verification codes for registration, password reset, and email change scenarios

CREATE TABLE IF NOT EXISTS email_verifications (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL COMMENT 'Target email address',
    code VARCHAR(6) NOT NULL COMMENT '6-digit verification code',
    purpose ENUM('register', 'reset_password', 'change_email') NOT NULL COMMENT 'Verification purpose',
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

-- Add email verification status fields to users table
-- Using conditional logic to avoid errors if columns already exist
ALTER TABLE users 
ADD COLUMN email_verified BOOLEAN DEFAULT FALSE COMMENT 'Whether email is verified',
ADD COLUMN email_verified_at DATETIME NULL COMMENT 'Email verification time';

-- Create index
CREATE INDEX idx_users_email_verified ON users(email_verified);