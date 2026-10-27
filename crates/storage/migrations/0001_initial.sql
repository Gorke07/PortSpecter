CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    plan TEXT NOT NULL,
    completed INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL
);
CREATE TABLE observations (
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (session_id, ip, port)
);
CREATE TABLE macs (
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (session_id, ip)
);
CREATE TABLE profiles (name TEXT PRIMARY KEY, payload TEXT NOT NULL);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
PRAGMA user_version = 1;
