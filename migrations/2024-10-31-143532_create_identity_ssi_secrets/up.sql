-- Your SQL goes here
CREATE TABLE IF NOT EXISTS ssi_secrets
(
    id     TEXT NOT NULL PRIMARY KEY,
    ssi    TEXT NOT NULL UNIQUE,
    secret TEXT NOT NULL
);
