
USE opensever_250034;

ALTER TABLE users 
ADD COLUMN email VARCHAR(255) UNIQUE COMMENT '用户邮箱' AFTER password_hash;

CREATE INDEX idx_email ON users(email);
