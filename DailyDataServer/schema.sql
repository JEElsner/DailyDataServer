CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    email_confirmed BOOLEAN NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    parent_activity INTEGER,
    is_alias BOOLEAN NOT NULL,
    user_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user (id)
    FOREIGN KEY (parent_activity) REFERENCES activity (id)
)

CREATE TABLE IF NOT EXISTS timelog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    activity_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    server_time TIMESTAMP NOT NULL,
    record_time TIMESTAMP NOT NULL,
    nominal_time TIMESTAMP NOT NULL,
    nominal_time_timezone_offset FLOAT NOT NULL,
    nominal_time_timezone_name TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user (id),
    FOREIGN KEY (activity_id) REFERENCES activity (id)
)