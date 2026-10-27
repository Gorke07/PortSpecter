CREATE TABLE host_names (
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (session_id, ip)
);
PRAGMA user_version = 2;
