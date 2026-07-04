-- Track whether a user's username is still the auto-generated placeholder
-- (u_<base64>) assigned at signup, so we can offer a one-time claim to set
-- a real, immutable username.

ALTER TABLE users ADD COLUMN username_is_placeholder BOOLEAN NOT NULL DEFAULT true;
