ALTER TABLE email_verifications 
MODIFY COLUMN purpose ENUM('register', 'reset_password', 'change_email', 'delete_account') NOT NULL COMMENT 'Verification purpose';
SHOW COLUMNS FROM email_verifications LIKE 'purpose';