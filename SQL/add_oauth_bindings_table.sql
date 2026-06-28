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
    binding_method VARCHAR(20) DEFAULT 'manual' COMMENT 'Binding method: manual, auto',
    -- 跨邮箱绑定 / 安全策略相关列,原本在 _migrations/multi_email_oauth_strategy.sql
    -- 单独 ALTER 加,新装库漏跑会 1054。直接建进 CREATE TABLE。
    binding_status VARCHAR(20) NOT NULL DEFAULT 'active' COMMENT 'Binding status: active/pending/suspended',
    verified_at TIMESTAMP NULL DEFAULT NULL COMMENT 'When the binding was verified',
    notes TEXT COMMENT 'Additional notes about the binding',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY unique_provider_user (provider, provider_user_id),
    UNIQUE KEY unique_user_provider (user_id, provider),
    INDEX idx_user_id (user_id),
    INDEX idx_provider (provider),
    INDEX idx_provider_email (provider_email),
    INDEX idx_oauth_bindings_status (binding_status),

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 跨邮箱绑定的验证 token 表,原本在 _migrations/multi_email_oauth_strategy.sql
-- 单独建,新装库直接建好。
CREATE TABLE IF NOT EXISTS oauth_binding_verifications (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id VARCHAR(64) NOT NULL,
    provider VARCHAR(20) NOT NULL,
    provider_email VARCHAR(255) NOT NULL,
    verification_token VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_token (verification_token),
    INDEX idx_user_provider (user_id, provider),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 数据回填(从历史 users 推断 provider)只在老库升级时需要,新装库 users 表为空,直接跳过
