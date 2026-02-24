-- Create oauth_email_conflicts table for tracking OAuth email conflicts
CREATE TABLE IF NOT EXISTS oauth_email_conflicts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL COMMENT 'User ID experiencing the conflict',
    provider VARCHAR(32) NOT NULL COMMENT 'OAuth provider (google, github, microsoft)',
    old_email VARCHAR(255) COMMENT 'Previous email address',
    new_email VARCHAR(255) NOT NULL COMMENT 'New email address causing conflict',
    conflict_user_id VARCHAR(64) COMMENT 'ID of user who already has this email',
    conflict_type ENUM('email_occupied', 'binding_conflict', 'provider_change') NOT NULL COMMENT 'Type of conflict',
    resolution_status ENUM('pending', 'resolved', 'ignored') DEFAULT 'pending' COMMENT 'Status of conflict resolution',
    resolution_method VARCHAR(50) COMMENT 'Method used to resolve conflict',
    notes TEXT COMMENT 'Additional notes about the conflict',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When conflict was detected',
    resolved_at TIMESTAMP NULL COMMENT 'When conflict was resolved',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Indexes for performance
    INDEX idx_user_id (user_id),
    INDEX idx_provider (provider),
    INDEX idx_new_email (new_email),
    INDEX idx_conflict_user_id (conflict_user_id),
    INDEX idx_resolution_status (resolution_status),
    INDEX idx_created_at (created_at),
    
    -- Composite indexes for common queries
    INDEX idx_user_provider (user_id, provider),
    INDEX idx_status_created (resolution_status, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='OAuth email conflicts tracking table';

-- Create oauth_email_history table for tracking email changes
CREATE TABLE IF NOT EXISTS oauth_email_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL COMMENT 'User ID',
    provider VARCHAR(32) NOT NULL COMMENT 'OAuth provider',
    old_email VARCHAR(255) COMMENT 'Previous email',
    new_email VARCHAR(255) NOT NULL COMMENT 'New email',
    change_reason VARCHAR(100) COMMENT 'Reason for email change',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'When change occurred',
    
    -- Indexes
    INDEX idx_user_id (user_id),
    INDEX idx_provider (provider),
    INDEX idx_user_provider (user_id, provider),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='OAuth email change history table';

-- Show created tables
SELECT 'oauth_email_conflicts table created successfully' as status;
SELECT 'oauth_email_history table created successfully' as status;
