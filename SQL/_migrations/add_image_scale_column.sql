-- Add image_scale column to questions table
-- This column stores the image display scale factor (0.5-2.0) for media in questions

USE opensever_250034;

-- Add image_scale column to questions table
ALTER TABLE questions 
ADD COLUMN image_scale DECIMAL(3,2) DEFAULT 1.00 COMMENT 'Image display scale factor (0.5-2.0)';

-- Update existing questions to have default scale of 1.0
UPDATE questions SET image_scale = 1.00 WHERE image_scale IS NULL;

-- Show the updated table structure
DESCRIBE questions;
