// SQLite database (built into Node 22+). All queries use prepared statements
// (parameterized) -> protects against SQL injection.
const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new DatabaseSync(path.join(dataDir, 'app.db'));

db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','customer')),
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  pricing_type TEXT NOT NULL CHECK (pricing_type IN ('sqft','piece')),
  rate REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS quotes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  total REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS quote_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  quote_id INTEGER NOT NULL REFERENCES quotes(id) ON DELETE CASCADE,
  product_id INTEGER NOT NULL REFERENCES products(id),
  width REAL,
  height REAL,
  quantity INTEGER NOT NULL,
  line_total REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS enquiries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'New' CHECK (status IN ('New','In Progress','Completed')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  ip TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

// Seed products if not already seeded
const existingProducts = db.prepare('SELECT COUNT(*) as count FROM products').get();
if (existingProducts.count === 0) {
  const insertProduct = db.prepare('INSERT INTO products (name, pricing_type, rate) VALUES (?, ?, ?)');
  insertProduct.run('Sliding Window', 'sqft', 350);
  insertProduct.run('Openable Window', 'sqft', 400);
  insertProduct.run('VL (Ventilator)', 'piece', 1500);
  insertProduct.run('FX (Fixed Window)', 'sqft', 300);
}

module.exports = db;
