SELECT id, username, email, created_at 
FROM users 
WHERE email LIKE '%@%' 
AND password_hash LIKE '$2a$%'
ORDER BY created_at DESC;

ALTER TABLE users MODIFY COLUMN id VARCHAR(64) NOT NULL;

DROP INDEX IF EXISTS idx_user_id ON users;
CREATE INDEX idx_user_id ON users(id);

SELECT 
    TABLE_NAME,
    COLUMN_NAME,
    CONSTRAINT_NAME,
    REFERENCED_TABLE_NAME,
    REFERENCED_COLUMN_NAME
FROM 
    INFORMATION_SCHEMA.KEY_COLUMN_USAGE 
WHERE 
    REFERENCED_TABLE_SCHEMA = DATABASE()
    AND REFERENCED_TABLE_NAME = 'users'
    AND REFERENCED_COLUMN_NAME = 'id';

SELECT 
    COUNT(*) as total_users,
    COUNT(CASE WHEN email LIKE '%@%' THEN 1 END) as oauth_users,
    COUNT(CASE WHEN LENGTH(id) > 10 THEN 1 END) as custom_id_users
FROM users;
