-- Optional global ntfy push target. NULL means disabled.
ALTER TABLE users ADD COLUMN ntfy_topic_url TEXT;
