-- Multi-Email OAuth Binding Strategy
-- Handles OAuth accounts with different email addresses

-- ==================== Enhanced OAuth Bindings Table ====================

-- Add additional fields to track email relationships
ALTER TABLE oauth_bindings 
ADD COLUMN binding_method ENUM('auto', 'manual', 'verified') DEFAULT 'auto' COMMENT 'How the binding was created',
ADD COLUMN binding_status ENUM('active', 'pending', 'suspended') DEFAULT 'active' COMMENT 'Binding status',
ADD COLUMN verified_at TIMESTAMP NULL COMMENT 'When the binding was verified',
ADD COLUMN notes TEXT COMMENT 'Additional notes about the binding';

-- ==================== Cross-Email Binding Logic ====================

-- Create a procedure to handle cross-email OAuth binding
DELIMITER //

CREATE PROCEDURE BindOAuthToExistingUser(
    IN p_user_id VARCHAR(64),
    IN p_provider VARCHAR(20),
    IN p_provider_user_id VARCHAR(100),
    IN p_provider_email VARCHAR(255),
    IN p_provider_username VARCHAR(100),
    IN p_provider_name VARCHAR(100),
    IN p_provider_avatar VARCHAR(500)
)
BEGIN
    DECLARE v_existing_binding_count INT DEFAULT 0;
    DECLARE v_user_exists INT DEFAULT 0;
    
    -- Check if user exists
    SELECT COUNT(*) INTO v_user_exists FROM users WHERE id = p_user_id;
    
    IF v_user_exists = 0 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'User does not exist';
    END IF;
    
    -- Check if binding already exists for this user and provider
    SELECT COUNT(*) INTO v_existing_binding_count 
    FROM oauth_bindings 
    WHERE user_id = p_user_id AND provider = p_provider;
    
    IF v_existing_binding_count > 0 THEN
        -- Update existing binding
        UPDATE oauth_bindings 
        SET 
            provider_user_id = p_provider_user_id,
            provider_email = p_provider_email,
            provider_username = p_provider_username,
            provider_name = p_provider_name,
            provider_avatar = p_provider_avatar,
            binding_method = 'manual',
            binding_status = 'pending',
            updated_at = NOW()
        WHERE user_id = p_user_id AND provider = p_provider;
    ELSE
        -- Create new binding
        INSERT INTO oauth_bindings (
            user_id, provider, provider_user_id, provider_email, 
            provider_username, provider_name, provider_avatar,
            binding_method, binding_status, is_primary
        ) VALUES (
            p_user_id, p_provider, p_provider_user_id, p_provider_email,
            p_provider_username, p_provider_name, p_provider_avatar,
            'manual', 'pending', FALSE
        );
    END IF;
    
END //

DELIMITER ;

-- ==================== Email Verification for Cross-Email Bindings ====================

-- Create email verification tokens table
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

-- ==================== Cross-Email Binding Detection ====================

-- Function to detect potential cross-email bindings
CREATE VIEW potential_cross_email_bindings AS
SELECT 
    u.id as user_id,
    u.email as user_email,
    u.username as user_username,
    ob.provider,
    ob.provider_email,
    ob.provider_username,
    ob.provider_name,
    CASE 
        WHEN u.email = ob.provider_email THEN 'same_email'
        WHEN u.email != ob.provider_email THEN 'different_email'
        ELSE 'unknown'
    END as email_relationship,
    ob.binding_status,
    ob.binding_method
FROM users u
LEFT JOIN oauth_bindings ob ON u.id = ob.user_id
WHERE ob.id IS NOT NULL;

-- ==================== Security Rules for Cross-Email Bindings ====================

-- Create a procedure to validate cross-email binding security
DELIMITER //

CREATE PROCEDURE ValidateCrossEmailBinding(
    IN p_user_id VARCHAR(64),
    IN p_provider VARCHAR(20),
    IN p_provider_email VARCHAR(255),
    OUT p_validation_result VARCHAR(50),
    OUT p_validation_message TEXT
)
BEGIN
    DECLARE v_user_email VARCHAR(255);
    DECLARE v_existing_oauth_user_count INT DEFAULT 0;
    DECLARE v_domain_match BOOLEAN DEFAULT FALSE;
    
    -- Get user's primary email
    SELECT email INTO v_user_email FROM users WHERE id = p_user_id;
    
    -- Check if provider email is already used by another user
    SELECT COUNT(*) INTO v_existing_oauth_user_count
    FROM users u2
    WHERE u2.email = p_provider_email AND u2.id != p_user_id;
    
    IF v_existing_oauth_user_count > 0 THEN
        SET p_validation_result = 'CONFLICT';
        SET p_validation_message = 'Provider email is already used by another user';
    ELSE
        -- Check domain similarity for additional security
        SET v_domain_match = (
            SUBSTRING_INDEX(v_user_email, '@', -1) = SUBSTRING_INDEX(p_provider_email, '@', -1)
        );
        
        IF v_domain_match THEN
            SET p_validation_result = 'SAFE';
            SET p_validation_message = 'Same domain, binding allowed';
        ELSE
            SET p_validation_result = 'VERIFY_REQUIRED';
            SET p_validation_message = 'Different domain, email verification required';
        END IF;
    END IF;
    
END //

DELIMITER ;

-- ==================== Binding Management Queries ====================

-- Get all bindings for a user with email relationship info
SELECT 
    u.id,
    u.username,
    u.email as primary_email,
    ob.provider,
    ob.provider_email,
    ob.provider_username,
    ob.provider_name,
    ob.binding_status,
    ob.binding_method,
    ob.is_primary,
    CASE 
        WHEN u.email = ob.provider_email THEN '✓ Same Email'
        WHEN u.email != ob.provider_email THEN '⚠ Different Email'
        ELSE '? Unknown'
    END as email_status
FROM users u
LEFT JOIN oauth_bindings ob ON u.id = ob.user_id
WHERE u.id = 'your_user_id'
ORDER BY ob.is_primary DESC, ob.created_at ASC;
