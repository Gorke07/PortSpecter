CREATE TABLE device_services (
 session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
 ip TEXT NOT NULL,
 cameras TEXT NOT NULL DEFAULT '[]',
 shares TEXT,
 PRIMARY KEY(session_id, ip)
);
PRAGMA user_version = 4;
