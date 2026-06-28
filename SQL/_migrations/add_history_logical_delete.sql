ALTER TABLE answers ADD COLUMN is_delete TINYINT DEFAULT 0 COMMENT 'Logical delete: 0-Not deleted, 1-Deleted';
CREATE INDEX idx_answers_is_delete ON answers(is_delete);
