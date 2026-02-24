-- =============================================
-- Migration: Normalize surveys.deadline as DATETIME NULL
-- Safe to run multiple times (idempotent)
-- Tested for MySQL 5.7/8.0 syntax
-- =============================================

SET @TARGET_DB := 'opensever_250034';

SET @OLD_SQL_NOTES = @@sql_notes;
SET sql_notes = 0;

SET @sql := CONCAT('USE `', @TARGET_DB, '`');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col_exists := (
  SELECT COUNT(*)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = @TARGET_DB
    AND TABLE_NAME = 'surveys'
    AND COLUMN_NAME = 'deadline'
);
SET @sql := IF(
  @col_exists = 0,
  'ALTER TABLE surveys ADD COLUMN deadline DATETIME NULL AFTER project_id',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @deadline_type := (
  SELECT DATA_TYPE
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = @TARGET_DB
    AND TABLE_NAME = 'surveys'
    AND COLUMN_NAME = 'deadline'
  LIMIT 1
);

SET @is_char_type := (
  SELECT CASE WHEN @deadline_type IN ('varchar','text','longtext','char','mediumtext','tinytext') THEN 1 ELSE 0 END
);

SET @sql := IF(
  @is_char_type = 1,
  'ALTER TABLE surveys ADD COLUMN IF NOT EXISTS deadline_dt DATETIME NULL AFTER project_id',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql := IF(
  @is_char_type = 1,
  'UPDATE surveys
     SET deadline_dt = CASE
           WHEN deadline IS NULL OR deadline = '''' OR deadline = ''0000-00-00 00:00:00''
             THEN NULL
           WHEN STR_TO_DATE(deadline, ''%Y-%m-%d %H:%i:%s'') IS NOT NULL
             THEN STR_TO_DATE(deadline, ''%Y-%m-%d %H:%i:%s'')
           ELSE NULL
         END',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql := IF(
  @is_char_type = 1,
  'ALTER TABLE surveys DROP COLUMN deadline',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @sql := IF(
  @is_char_type = 1,
  'ALTER TABLE surveys CHANGE COLUMN deadline_dt deadline DATETIME NULL',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

UPDATE surveys
   SET deadline = NULL
 WHERE deadline = '0000-00-00 00:00:00';

SET @idx_exists := (
  SELECT COUNT(*)
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = @TARGET_DB
    AND TABLE_NAME = 'surveys'
    AND INDEX_NAME = 'idx_surveys_status_deadline'
);
SET @sql := IF(
  @idx_exists = 0,
  'CREATE INDEX idx_surveys_status_deadline ON surveys(survey_status, deadline)',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx2_exists := (
  SELECT COUNT(*)
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = @TARGET_DB
    AND TABLE_NAME = 'surveys'
    AND INDEX_NAME = 'idx_surveys_deadline'
);
SET @sql := IF(
  @idx2_exists = 0,
  'CREATE INDEX idx_surveys_deadline ON surveys(deadline)',
  'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SELECT
  COLUMN_NAME, DATA_TYPE, IS_NULLABLE
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = @TARGET_DB AND TABLE_NAME = 'surveys' AND COLUMN_NAME IN ('deadline');

SELECT
  INDEX_NAME, SEQ_IN_INDEX, COLUMN_NAME
FROM information_schema.STATISTICS
WHERE TABLE_SCHEMA = @TARGET_DB AND TABLE_NAME = 'surveys'
  AND INDEX_NAME IN ('idx_surveys_status_deadline','idx_surveys_deadline')
ORDER BY INDEX_NAME, SEQ_IN_INDEX;

SET sql_notes = @OLD_SQL_NOTES;