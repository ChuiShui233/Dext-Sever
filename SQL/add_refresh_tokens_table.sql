-- Create table to persist refresh tokens with rotation support
-- 注意:ENGINE / CHARSET / COLLATE 必须与 users 表保持一致,
-- 否则外键 user_id -> users.id 会因 collation 不匹配被 MySQL 3780 拒绝。
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id VARCHAR(64) NOT NULL,
  token_hash VARCHAR(128) NOT NULL,
  issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  last_used_at DATETIME NULL,
  user_agent VARCHAR(255) NULL,
  ip_address VARCHAR(64) NULL,
  is_revoked TINYINT(1) NOT NULL DEFAULT 0,
  CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_id_expires (user_id, expires_at),
  INDEX idx_token_hash (token_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
