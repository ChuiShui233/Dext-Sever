-- Add is_delete and answer_id column to survey_submissions table for logical deletion
-- TINYINT, default 0, 0-not deleted, 1-deleted

ALTER TABLE survey_submissions ADD COLUMN is_delete TINYINT DEFAULT 0 COMMENT 'Logical delete: 0-not deleted, 1-deleted';
ALTER TABLE survey_submissions ADD COLUMN answer_id INT COMMENT 'Associated answer ID';

-- Add index for optimization
CREATE INDEX idx_submissions_is_delete ON survey_submissions(is_delete);
CREATE INDEX idx_submissions_answer_id ON survey_submissions(answer_id);
