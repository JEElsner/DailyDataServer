CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    email_confirmed BOOLEAN DEFAULT false,
    report_time INTEGER,
    password TEXT NOT NULL,
    creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    parent_activity INTEGER,
    is_alias BOOLEAN NOT NULL,
    is_placeholder BOOLEAN NOT NULL,
    user_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user (id) FOREIGN KEY (parent_activity) REFERENCES activity (id) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE TABLE IF NOT EXISTS timelog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    activity_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    latitude FLOAT,
    longitude FLOAT,
    server_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    record_time TIMESTAMP NOT NULL,
    nominal_time TIMESTAMP NOT NULL,
    nominal_time_timezone_offset FLOAT NOT NULL,
    nominal_time_timezone_name TEXT NOT NULL,
    last_modification_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (activity_id) REFERENCES activity (id) ON UPDATE CASCADE ON DELETE RESTRICT
);