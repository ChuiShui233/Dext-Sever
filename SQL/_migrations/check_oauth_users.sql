-- Check OAuth users in database
SELECT id, username, email, created_at 
FROM users 
WHERE email = 'chaoscodes512@outlook.com'
ORDER BY created_at DESC;

-- Check all recent users
SELECT id, username, email, created_at 
FROM users 
ORDER BY created_at DESC 
LIMIT 10;

-- Check user sessions
SELECT s.id, s.user_id, u.username, u.email, s.created_at
FROM user_sessions s
LEFT JOIN users u ON s.user_id = u.id
ORDER BY s.created_at DESC
LIMIT 5;
