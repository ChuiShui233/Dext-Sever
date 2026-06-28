-- Data Merge Strategy for OAuth Users
-- This script handles various data merging scenarios

-- ==================== Account Merging Strategy ====================

-- 1. Merge OAuth users with existing email-based accounts
-- When an OAuth user logs in with an email that already exists in the system
UPDATE users u1
SET 
    -- Keep the original user ID and basic info
    updated_at = NOW()
WHERE EXISTS (
    SELECT 1 FROM users u2 
    WHERE u2.email = u1.email 
    AND u2.id != u1.id 
    AND (u1.id LIKE 'oauth_%' OR u1.id LIKE 'google_%' OR u1.id LIKE 'github_%' OR u1.id LIKE 'microsoft_%')
);

-- 2. Transfer data from OAuth duplicate accounts to main accounts
-- Transfer projects, surveys, and other user data
UPDATE projects p
SET user_id = (
    SELECT u_main.id 
    FROM users u_main 
    JOIN users u_oauth ON u_main.email = u_oauth.email
    WHERE u_oauth.id = p.user_id
    AND u_oauth.id != u_main.id
    AND (u_oauth.id LIKE 'oauth_%' OR u_oauth.id LIKE 'google_%' OR u_oauth.id LIKE 'github_%' OR u_oauth.id LIKE 'microsoft_%')
    AND NOT (u_main.id LIKE 'oauth_%' OR u_main.id LIKE 'google_%' OR u_main.id LIKE 'github_%' OR u_main.id LIKE 'microsoft_%')
    LIMIT 1
)
WHERE EXISTS (
    SELECT 1 FROM users u_main 
    JOIN users u_oauth ON u_main.email = u_oauth.email
    WHERE u_oauth.id = p.user_id
    AND u_oauth.id != u_main.id
    AND (u_oauth.id LIKE 'oauth_%' OR u_oauth.id LIKE 'google_%' OR u_oauth.id LIKE 'github_%' OR u_oauth.id LIKE 'microsoft_%')
    AND NOT (u_main.id LIKE 'oauth_%' OR u_main.id LIKE 'google_%' OR u_main.id LIKE 'github_%' OR u_main.id LIKE 'microsoft_%')
);

-- 3. Update OAuth bindings to point to main accounts
UPDATE oauth_bindings ob
SET user_id = (
    SELECT u_main.id 
    FROM users u_main 
    JOIN users u_oauth ON u_main.email = u_oauth.email
    WHERE u_oauth.id = ob.user_id
    AND u_oauth.id != u_main.id
    AND (u_oauth.id LIKE 'oauth_%' OR u_oauth.id LIKE 'google_%' OR u_oauth.id LIKE 'github_%' OR u_oauth.id LIKE 'microsoft_%')
    AND NOT (u_main.id LIKE 'oauth_%' OR u_main.id LIKE 'google_%' OR u_main.id LIKE 'github_%' OR u_main.id LIKE 'microsoft_%')
    LIMIT 1
)
WHERE EXISTS (
    SELECT 1 FROM users u_main 
    JOIN users u_oauth ON u_main.email = u_oauth.email
    WHERE u_oauth.id = ob.user_id
    AND u_oauth.id != u_main.id
    AND (u_oauth.id LIKE 'oauth_%' OR u_oauth.id LIKE 'google_%' OR u_oauth.id LIKE 'github_%' OR u_oauth.id LIKE 'microsoft_%')
    AND NOT (u_main.id LIKE 'oauth_%' OR u_main.id LIKE 'google_%' OR u_main.id LIKE 'github_%' OR u_main.id LIKE 'microsoft_%')
);

-- 4. Remove duplicate OAuth user accounts after data transfer
DELETE u_oauth FROM users u_oauth
JOIN users u_main ON u_main.email = u_oauth.email
WHERE u_oauth.id != u_main.id
AND (u_oauth.id LIKE 'oauth_%' OR u_oauth.id LIKE 'google_%' OR u_oauth.id LIKE 'github_%' OR u_oauth.id LIKE 'microsoft_%')
AND NOT (u_main.id LIKE 'oauth_%' OR u_main.id LIKE 'google_%' OR u_main.id LIKE 'github_%' OR u_main.id LIKE 'microsoft_%');

-- ==================== Multi-Provider Binding Strategy ====================

-- 5. Handle multiple OAuth provider bindings for the same user
-- Ensure only one binding per provider per user
DELETE ob1 FROM oauth_bindings ob1
JOIN oauth_bindings ob2 ON ob1.user_id = ob2.user_id AND ob1.provider = ob2.provider
WHERE ob1.id > ob2.id;

-- 6. Set primary OAuth binding (first created one)
UPDATE oauth_bindings ob1
SET is_primary = TRUE
WHERE ob1.created_at = (
    SELECT MIN(ob2.created_at)
    FROM oauth_bindings ob2
    WHERE ob2.user_id = ob1.user_id
)
AND NOT EXISTS (
    SELECT 1 FROM oauth_bindings ob3
    WHERE ob3.user_id = ob1.user_id AND ob3.is_primary = TRUE
);

-- ==================== Data Integrity Checks ====================

-- 7. Verify data integrity after merge
SELECT 
    'Duplicate email check' as check_type,
    COUNT(*) as count,
    CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END as status
FROM (
    SELECT email, COUNT(*) as cnt
    FROM users
    WHERE email IS NOT NULL AND email != ''
    GROUP BY email
    HAVING COUNT(*) > 1
) duplicates

UNION ALL

SELECT 
    'Orphaned OAuth bindings check' as check_type,
    COUNT(*) as count,
    CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END as status
FROM oauth_bindings ob
LEFT JOIN users u ON u.id = ob.user_id
WHERE u.id IS NULL

UNION ALL

SELECT 
    'Multiple primary bindings check' as check_type,
    COUNT(*) as count,
    CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END as status
FROM (
    SELECT user_id, COUNT(*) as cnt
    FROM oauth_bindings
    WHERE is_primary = TRUE
    GROUP BY user_id
    HAVING COUNT(*) > 1
) multiple_primary;
