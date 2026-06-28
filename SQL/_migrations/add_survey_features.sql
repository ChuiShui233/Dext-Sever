-- Add auto_submit and allow_anonymous columns to surveys table
-- These columns enable automatic submission and anonymous submission features

USE opensever_250034;

-- Add auto_submit column (default false)
ALTER TABLE surveys 
ADD COLUMN auto_submit BOOLEAN DEFAULT FALSE COMMENT 'Enable automatic submission when all questions are answered';

-- Add allow_anonymous column (default false)  
ALTER TABLE surveys
ADD COLUMN allow_anonymous BOOLEAN DEFAULT FALSE COMMENT 'Allow anonymous users to submit without login';

-- Update existing surveys to have default values
UPDATE surveys SET auto_submit = FALSE WHERE auto_submit IS NULL;
UPDATE surveys SET allow_anonymous = FALSE WHERE allow_anonymous IS NULL;

-- Show the updated table structure
DESCRIBE surveys;
