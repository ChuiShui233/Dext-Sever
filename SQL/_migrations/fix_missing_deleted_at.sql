-- =============================================
-- Migration: Add deleted_at and is_delete columns to answers and survey_submissions
-- Purpose: Support Recycle Bin functionality and scheduled cleanup
-- Note: Simplified syntax for older MySQL versions (5.7 or below)
-- =============================================

USE `opensever_250034`;

-- 1. Add logical delete fields to the answers table
-- If a column already exists, the individual statement will fail with #1060. 
-- You can simply skip the failing statement and execute the next one.

-- Add is_delete if not present
ALTER TABLE `answers` ADD COLUMN `is_delete` TINYINT DEFAULT 0 COMMENT 'Logical delete: 0-Active, 1-Deleted' AFTER `create_time`;

-- Add deleted_at if not present
ALTER TABLE `answers` ADD COLUMN `deleted_at` TIMESTAMP NULL DEFAULT NULL COMMENT 'Deletion timestamp' AFTER `is_delete`;

-- Add indexes (Ignore if already exist)
CREATE INDEX `idx_answers_is_delete` ON `answers`(`is_delete`);
CREATE INDEX `idx_answers_deleted_at` ON `answers`(`deleted_at`);

-- 2. Add logical delete fields to the survey_submissions table
-- Add is_delete if not present
ALTER TABLE `survey_submissions` ADD COLUMN `is_delete` TINYINT DEFAULT 0 COMMENT 'Logical delete: 0-Active, 1-Deleted';

-- Add deleted_at if not present
ALTER TABLE `survey_submissions` ADD COLUMN `deleted_at` TIMESTAMP NULL DEFAULT NULL COMMENT 'Deletion timestamp';

-- Add answer_id if not present
ALTER TABLE `survey_submissions` ADD COLUMN `answer_id` INT COMMENT 'Associated answer ID';

-- Add indexes (Ignore if already exist)
CREATE INDEX `idx_submissions_is_delete` ON `survey_submissions`(`is_delete`);
CREATE INDEX `idx_submissions_answer_id` ON `survey_submissions`(`answer_id`);
