-- OpenAssets Database Complete Structure
-- Create database
CREATE DATABASE IF NOT EXISTS opensever_250034 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE opensever_250034;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(12) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE COMMENT 'User email',
    avatar_url VARCHAR(500),
    -- 显示名 / 昵称,原本在 _migrations/add_oauth_support.sql 单独
    -- ALTER 加过,新装库漏跑会 1054。直接进 CREATE TABLE。
    display_name VARCHAR(255) DEFAULT NULL COMMENT 'Display name',
    user_role INT DEFAULT 0,
    failed_attempts INT DEFAULT 0,
    locked_until DATETIME,
    -- 邮箱验证状态,add_email_verification.sql 会 ALTER 加,这里直接建好
    -- 以便全库一次到位、避免 1054。
    email_verified BOOLEAN DEFAULT FALSE COMMENT 'Whether email is verified',
    email_verified_at DATETIME NULL COMMENT 'Email verification time',
    -- 逻辑删除,add_users_logical_delete.sql 会 ALTER 加。
    is_delete TINYINT NOT NULL DEFAULT 0 COMMENT 'Logical delete: 0-Not deleted, 1-Deleted',
    deleted_at TIMESTAMP NULL DEFAULT NULL COMMENT 'Deletion timestamp',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_users_is_delete (is_delete),
    INDEX idx_users_deleted_at (deleted_at),
    INDEX idx_users_email_verified (email_verified)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- OAuth user ID fix patch - 2025/10/06
-- Ensure OAuth users can be stored and queried correctly
UPDATE users SET id = CONCAT('oauth_', UNIX_TIMESTAMP(), '_', SUBSTRING(MD5(email), 1, 8)) 
WHERE email LIKE '%@%' AND LENGTH(id) < 10;

-- Projects table
CREATE TABLE IF NOT EXISTS projects (
    id INT PRIMARY KEY AUTO_INCREMENT,
    project_name VARCHAR(100) NOT NULL,
    project_description TEXT,
    user_id VARCHAR(64) NOT NULL,
    create_by VARCHAR(12) NOT NULL,
    create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    update_by VARCHAR(12) NOT NULL,
    INDEX idx_user_id (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Surveys table
CREATE TABLE IF NOT EXISTS surveys (
    id INT PRIMARY KEY AUTO_INCREMENT,
    survey_uid VARCHAR(64) NOT NULL UNIQUE,
    survey_name VARCHAR(100) NOT NULL,
    description TEXT,
    survey_type INT NOT NULL,
    survey_status INT DEFAULT 0,
    total_times INT DEFAULT 0,
    per_user_limit INT NULL DEFAULT NULL,
    project_id INT NOT NULL,
    deadline DATETIME NULL,
    -- 选完自动提交 / 允许匿名提交,原本在 add_survey_features.sql 里
    -- 单独 ALTER 加的,新装库容易漏。直接写进 CREATE TABLE 避免 1054。
    auto_submit BOOLEAN DEFAULT FALSE COMMENT 'Enable automatic submission when all questions are answered',
    allow_anonymous BOOLEAN DEFAULT FALSE COMMENT 'Allow anonymous users to submit without login',
    create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_project_id (project_id),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Survey backgrounds table
CREATE TABLE IF NOT EXISTS survey_backgrounds (
    id INT AUTO_INCREMENT PRIMARY KEY,
    survey_id INT NOT NULL,
    desktop_background TEXT,
    mobile_background TEXT,
    created_by VARCHAR(50) NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE,
    UNIQUE KEY unique_survey_background (survey_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- Questions table
CREATE TABLE IF NOT EXISTS questions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    survey_id INT NOT NULL,
    question_type INT NOT NULL,
    question_description TEXT NOT NULL,
    question_order INT DEFAULT 0,
    is_required BOOLEAN DEFAULT TRUE,
    media_urls JSON,
    jump_logic JSON,
    -- 图片缩放系数,原本在 add_image_scale_column.sql 单独 ALTER 加,
    -- 新装库漏跑会 1054。直接进 CREATE TABLE。
    image_scale DECIMAL(3,2) NOT NULL DEFAULT 1.00 COMMENT 'Image display scale factor (0.5-2.0)',
    INDEX idx_survey_id (survey_id),
    FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Question options table
CREATE TABLE IF NOT EXISTS question_options (
    id INT PRIMARY KEY AUTO_INCREMENT,
    question_id INT NOT NULL,
    option_text TEXT NOT NULL,
    option_order INT DEFAULT 0,
    media_url VARCHAR(500),
    -- 跳转目标问题 ID:NULL=默认下一题,-1=结束问卷。原本 DEFAULT 0 不允许
    -- NULL/负值,fix_destination_column.sql 单独改过,新装库直接建成可空。
    destination_question_id INT NULL DEFAULT NULL COMMENT 'Jump target question ID; -1=end survey; NULL=default next',
    -- 自定义输入占位符,原本在 add_custom_input_placeholder.sql 单独 ALTER 加,
    -- 新装库漏跑会 1054。直接进 CREATE TABLE。
    custom_input_placeholder VARCHAR(200) DEFAULT NULL COMMENT 'Placeholder text for custom input options',
    INDEX idx_question_id (question_id),
    FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Answers table
CREATE TABLE IF NOT EXISTS answers (
    id INT PRIMARY KEY AUTO_INCREMENT,
    survey_id INT NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    user_account VARCHAR(12) NOT NULL,
    create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- 逻辑删除标记:0-未删,1-已删。原本在 add_history_logical_delete.sql
    -- 单独 ALTER 加,新装库漏跑会 1054。直接进 CREATE TABLE。
    is_delete TINYINT NOT NULL DEFAULT 0 COMMENT 'Logical delete: 0-Not deleted, 1-Deleted',
    deleted_at TIMESTAMP NULL DEFAULT NULL COMMENT 'Deletion timestamp (paired with is_delete)',
    INDEX idx_survey_id (survey_id),
    INDEX idx_user_id (user_id),
    INDEX idx_answers_is_delete (is_delete),
    INDEX idx_answers_deleted_at (deleted_at),
    FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Answer details table
CREATE TABLE IF NOT EXISTS answer_details (
    id INT PRIMARY KEY AUTO_INCREMENT,
    answer_id INT NOT NULL,
    question_id INT NOT NULL,
    selected_options JSON NOT NULL,
    INDEX idx_answer_id (answer_id),
    INDEX idx_question_id (question_id),
    FOREIGN KEY (answer_id) REFERENCES answers(id) ON DELETE CASCADE,
    FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Survey statistics table
CREATE TABLE IF NOT EXISTS survey_stats (
    survey_id INT PRIMARY KEY,
    view_count INT DEFAULT 0,
    submit_count INT DEFAULT 0,
    last_view_time TIMESTAMP NULL DEFAULT NULL,
    last_submit_time TIMESTAMP NULL DEFAULT NULL,
    FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Survey views table
CREATE TABLE IF NOT EXISTS survey_views (
    id INT AUTO_INCREMENT PRIMARY KEY,
    survey_id INT,
    view_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    viewer_ip VARCHAR(45),
    INDEX idx_survey_id (survey_id),
    INDEX idx_view_time (view_time),
    INDEX idx_survey_view_time (survey_id, view_time),
    FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Survey submissions table
CREATE TABLE IF NOT EXISTS survey_submissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    survey_id INT,
    user_id VARCHAR(64),
    submit_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_survey_id (survey_id),
    INDEX idx_user_id (user_id),
    INDEX idx_submit_time (submit_time),
    INDEX idx_survey_submit_time (survey_id, submit_time),
    FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Survey assets files table
CREATE TABLE IF NOT EXISTS survey_assets_files (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    survey_id INT NOT NULL,
    username VARCHAR(50) NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_url TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    content_type VARCHAR(100) NOT NULL,
    upload_time DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Indexes
    INDEX idx_survey_id (survey_id),
    INDEX idx_username (username),
    INDEX idx_upload_time (upload_time),
    INDEX idx_file_name (file_name),
    
    -- Foreign key constraints
    FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;



-- Create additional indexes
-- 注意: idx_survey_uid / idx_users_username / idx_survey_backgrounds_survey_id
-- 等已由对应列的 inline UNIQUE 提供约束,这里不再重复 CREATE INDEX,
-- 否则在已有残留索引的库上会报 Duplicate key name。
CREATE INDEX idx_projects_create_by ON projects(create_by);
CREATE INDEX idx_projects_create_by_id ON projects(create_by, id);
CREATE INDEX idx_surveys_project_id_comp ON surveys(project_id, id);

-- Add indexes for query performance enhancement
CREATE INDEX idx_survey_backgrounds_created_by ON survey_backgrounds(created_by);


-- Add table comments
ALTER TABLE users COMMENT = 'Users table - Store user account information';
ALTER TABLE projects COMMENT = 'Projects table - Store user created projects';
ALTER TABLE surveys COMMENT = 'Surveys table - Store survey basic information';
ALTER TABLE questions COMMENT = 'Questions table - Store questions in surveys';
ALTER TABLE question_options COMMENT = 'Question options table - Store question options';
ALTER TABLE answers COMMENT = 'Answers table - Store user submitted answers';
ALTER TABLE answer_details COMMENT = 'Answer details table - Store answer specific options (JSON: {"texts":[], "indices":[]})';
ALTER TABLE survey_stats COMMENT = 'Survey statistics table - Store survey access and submission statistics';
ALTER TABLE survey_views COMMENT = 'Survey views table - Record survey access information';
ALTER TABLE survey_submissions COMMENT = 'Survey submissions table - Record survey submission information';
ALTER TABLE survey_assets_files COMMENT = 'Survey assets files table - Store survey related assets files';


-- Insert default admin user (optional)
-- INSERT INTO users (id, username, password_hash, user_role) VALUES 
-- ('admin_001', 'admin', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/RK.s5u.Ge', 1);
-- Note: The password hash above needs to be generated according to actual requirements
-- 末尾的 SHOW TABLES / information_schema 查询语句已移除(便于无差异导入)