// Admins are created ONLY from the command line (never from the public website).
// Usage: node create-admin.js "Name" email@example.com "StrongPassword@123"
const bcrypt = require('bcryptjs');
const db = require('./db');

const [name, email, password] = process.argv.slice(2);
if (!name || !email || !password) {
  console.log('Usage: node create-admin.js "Name" email password');
  process.exit(1);
}

// Password rule: 10+ characters with upper-case, lower-case and a number
const strongPw = (p) => p.length >= 10 && /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p);

if (!strongPw(password)) {
  console.log('Password must be at least 10 characters and contain upper-case, lower-case, and a number.');
  process.exit(1);
}

const normalizedEmail = email.toLowerCase().trim();
const hash = bcrypt.hashSync(password, 12);

try {
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(normalizedEmail);
  if (existing) {
    db.prepare("UPDATE users SET name = ?, password_hash = ?, role = 'admin', failed_attempts = 0, locked_until = 0 WHERE id = ?")
      .run(name, hash, existing.id);
    console.log('Updated existing user to admin:', normalizedEmail);
  } else {
    db.prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'admin')")
      .run(name, normalizedEmail, hash);
    console.log('Admin created:', normalizedEmail);
  }
} catch (err) {
  console.error('Error creating admin:', err.message);
  process.exit(1);
}
