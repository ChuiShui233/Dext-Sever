-- Migration: add_missing_submissions_deleted_at.sql
-- Add is_delete / deleted_at / answer_id columns to survey_submissions if not exists (idempotent)
-- Also adds their indexes safely

DROP PROCEDURE IF EXISTS add_missing_submissions_deleted_at;

DELIMITER //

CREATE PROCEDURE add_missing_submissions_deleted_at()
BEGIN
    DECLARE _col_exists INT DEFAULT 0;
    DECLARE _idx_exists INT DEFAULT 0;

    -- Add is_delete if not exists
    SELECT COUNT(*) INTO _col_exists
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'survey_submissions'
      AND COLUMN_NAME = 'is_delete';
    IF _col_exists = 0 THEN
        ALTER TABLE survey_submissions ADD COLUMN is_delete TINYINT DEFAULT 0 COMMENT 'Logical delete: 0-not deleted, 1-deleted';
    END IF;

    -- Add deleted_at if not exists
    SELECT COUNT(*) INTO _col_exists
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'survey_submissions'
      AND COLUMN_NAME = 'deleted_at';
    IF _col_exists = 0 THEN
        ALTER TABLE survey_submissions ADD COLUMN deleted_at TIMESTAMP NULL DEFAULT NULL COMMENT 'Deletion timestamp';
    END IF;

    -- Add answer_id if not exists
    SELECT COUNT(*) INTO _col_exists
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'survey_submissions'
      AND COLUMN_NAME = 'answer_id';
    IF _col_exists = 0 THEN
        ALTER TABLE survey_submissions ADD COLUMN answer_id INT COMMENT 'Associated answer ID';
    END IF;

    -- Add idx_submissions_is_delete if not exists
    SELECT COUNT(*) INTO _idx_exists
    FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'survey_submissions'
      AND INDEX_NAME = 'idx_submissions_is_delete';
    IF _idx_exists = 0 THEN
        CREATE INDEX idx_submissions_is_delete ON survey_submissions(is_delete);
    END IF;

    -- Add idx_submissions_deleted_at if not exists
    SELECT COUNT(*) INTO _idx_exists
    FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'survey_submissions'
      AND INDEX_NAME = 'idx_submissions_deleted_at';
    IF _idx_exists = 0 THEN
        CREATE INDEX idx_submissions_deleted_at ON survey_submissions(deleted_at);
    END IF;

    -- Add idx_submissions_answer_id if not exists
    SELECT COUNT(*) INTO _idx_exists
    FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'survey_submissions'
      AND INDEX_NAME = 'idx_submissions_answer_id';
    IF _idx_exists = 0 THEN
        CREATE INDEX idx_submissions_answer_id ON survey_submissions(answer_id);
    END IF;
END//

DELIMITER ;

CALL add_missing_submissions_deleted_at();
DROP PROCEDURE IF EXISTS add_missing_submissions_deleted_at;
