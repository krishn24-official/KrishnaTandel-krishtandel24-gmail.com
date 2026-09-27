// Database connection and helper functions
import Database from 'better-sqlite3';

// Open SQLite database connection
export function openDatabase(file = process.env.DATABASE_FILE ?? 'app.db') {
  const db = new Database(file);

  db.pragma('foreign_keys = ON');
  db.pragma('journal_mode = WAL');
  db.pragma('busy_timeout = 5000');
  db.pragma('synchronous = NORMAL');

  return db;
}

// Current UTC timestamp in ISO-8601 format
export const nowIso = () => new Date().toISOString();

// Generate unique identifier with prefix
export function newId(prefix) {
  const rand = crypto.randomUUID().replaceAll('-', '').slice(0, 16);
  return `${prefix}_${rand}`;
}

// Increment permission version for member
export function bumpPermVersion(db, { orgId, userId }) {
  db.prepare(
    `UPDATE memberships SET perm_version = perm_version + 1
      WHERE org_id = ? AND user_id = ?`
  ).run(orgId, userId);
}
