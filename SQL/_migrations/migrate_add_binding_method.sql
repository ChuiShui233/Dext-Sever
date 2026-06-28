-- Add binding_method column to oauth_bindings table
ALTER TABLE oauth_bindings ADD COLUMN binding_method VARCHAR(20) DEFAULT 'manual' COMMENT 'Binding method: manual, auto' AFTER is_primary;
