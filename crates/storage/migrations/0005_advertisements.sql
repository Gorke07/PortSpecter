ALTER TABLE device_services ADD COLUMN advertisements TEXT NOT NULL DEFAULT '[]';
PRAGMA user_version = 5;
