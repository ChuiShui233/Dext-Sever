ALTER TABLE answers ADD COLUMN is_delete TINYINT DEFAULT 0 COMMENT 'Logical delete: 0-Not deleted, 1-Deleted';
ALTER TABLE answers ADD COLUMN deleted_at TIMESTAMP NULL DEFAULT NULL COMMENT 'Deletion time';
CREATE INDEX idx_answers_is_delete ON answers(is_delete);
ALTER TABLE survey_submissions ADD COLUMN is_delete TINYINT DEFAULT 0 COMMENT 'Logical delete: 0-Not deleted, 1-Deleted';
ALTER TABLE survey_submissions ADD COLUMN deleted_at TIMESTAMP NULL DEFAULT NULL COMMENT 'Deletion time';
ALTER TABLE survey_submissions ADD COLUMN answer_id INT COMMENT 'Associated answer ID';
CREATE INDEX idx_submissions_is_delete ON survey_submissions(is_delete);
CREATE INDEX idx_submissions_answer_id ON survey_submissions(answer_id);