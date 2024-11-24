import sqlite3 from 'sqlite3';
import { open } from 'sqlite'

sqlite3.verbose();

// Initialize SQLite database
const db = await open({
    filename: ':memory:',
    driver: sqlite3.Database
});

await db.exec(`
    CREATE TABLE users (
        uuid varchar(36) PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        display_name TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
`);

await db.exec(`
    CREATE TABLE credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_uuid varchar(36) NOT NULL,
        credential_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        sign_count INTEGER NOT NULL,
        FOREIGN KEY (user_uuid) REFERENCES users (uuid)
    )
`);

export default db;
