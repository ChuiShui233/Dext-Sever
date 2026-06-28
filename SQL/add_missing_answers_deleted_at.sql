-- Migration: add_missing_answers_deleted_at.sql
-- Add deleted_at column to answers table if not exists (idempotent)
-- Also adds is_delete if missing, and their indexes
-- Safe to run on both old and new DBs; errors are suppressed via handler

DROP PROCEDURE IF EXISTS add_missing_answers_deleted_at;

DELIMITER //

CREATE PROCEDURE add_missing_answers_deleted_at()
BEGIN
    DECLARE _col_exists INT DEFAULT 0;
    DECLARE _idx_exists INT DEFAULT 0;

    -- Add is_delete if not exists
    SELECT COUNT(*) INTO _col_exists
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'answers'
      AND COLUMN_NAME = 'is_delete';
    IF _col_exists = 0 THEN
        ALTER TABLE answers ADD COLUMN is_delete TINYINT NOT NULL DEFAULT 0 COMMENT 'Logical delete: 0-Not deleted, 1-Deleted' AFTER create_time;
    END IF;

    -- Add deleted_at if not exists
    SELECT COUNT(*) INTO _col_exists
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'answers'
      AND COLUMN_NAME = 'deleted_at';
    IF _col_exists = 0 THEN
        ALTER TABLE answers ADD COLUMN deleted_at TIMESTAMP NULL DEFAULT NULL COMMENT 'Deletion timestamp' AFTER is_delete;
    END IF;

    -- Add idx_answers_is_delete if not exists
    SELECT COUNT(*) INTO _idx_exists
    FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'answers'
      AND INDEX_NAME = 'idx_answers_is_delete';
    IF _idx_exists = 0 THEN
        CREATE INDEX idx_answers_is_delete ON answers(is_delete);
    END IF;

    -- Add idx_answers_deleted_at if not exists
    SELECT COUNT(*) INTO _idx_exists
    FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'answers'
      AND INDEX_NAME = 'idx_answers_deleted_at';
    IF _idx_exists = 0 THEN
        CREATE INDEX idx_answers_deleted_at ON answers(deleted_at);
    END IF;
END//

DELIMITER ;

CALL add_missing_answers_deleted_at();
DROP PROCEDURE IF EXISTS add_missing_answers_deleted_at;
