-- Add custom_input_placeholder field to question_options table
-- Used to store placeholder text for custom input options

ALTER TABLE question_options 
ADD COLUMN custom_input_placeholder VARCHAR(200) DEFAULT NULL 
COMMENT 'Placeholder text for custom input options';
