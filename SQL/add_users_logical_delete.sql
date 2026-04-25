-- Add logical delete support to users table
ALTER TABLE `users`
  ADD COLUMN `is_delete` TINYINT DEFAULT 0 COMMENT 'Logical delete: 0-Not deleted, 1-Deleted';

CREATE INDEX `idx_users_is_delete` ON `users`(`is_delete`);
