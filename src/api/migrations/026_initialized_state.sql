-- Add 'initialized' state for newly created resources that haven't been deployed yet.
-- Distinguishes from 'pending' which means a deploy is actively in progress.
ALTER TYPE resource_state ADD VALUE IF NOT EXISTS 'initialized';
