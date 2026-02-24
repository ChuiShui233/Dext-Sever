-- =============================================
-- Migration: Add per_user_limit to surveys (nullable INT)
-- Idempotent and safe to run multiple times
-- =============================================

SET @TARGET_DB := 'opensever_250034';

SET @OLD_SQL_NOTES = @@sql_notes;
SET sql_notes = 0;

SET @sql := CONCAT('USE `', @TARGET_DB, '`');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Add column if not exists
SET @col_exists := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=@TARGET_DB AND TABLE_NAME='surveys' AND COLUMN_NAME='per_user_limit'
);
SET @sql := IF(@col_exists=0,
  'ALTER TABLE surveys ADD COLUMN per_user_limit INT NULL DEFAULT NULL AFTER total_times',
  'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Optional index (not strictly needed, lookups are by survey_id)
-- No index added.

SET sql_notes = @OLD_SQL_NOTES;
