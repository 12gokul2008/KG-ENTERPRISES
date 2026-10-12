require('fs').existsSync('.env') && process.loadEnvFile && process.loadEnvFile('.env');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const db = require('./db');

const isProd = process.env.NODE_ENV === 'production';
const SECRET = process.env.SESSION_SECRET;
if (isProd && (!SECRET || SECRET.length < 32)) {
  console.error('Set a strong SESSION_SECRET (32+ chars) in production');
  process.exit(1);
}

// 1. Business details (show on every page header/footer)
const BUSINESS = {
  name: 'Karunanithi UPVC',
  owner: 'Karunanithi',
  years: '10+',
  phone: '8754496455'
};

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.disable('x-powered-by');
if (isProd) app.set('trust proxy', 1);

// ---- Security headers (CSP, clickjacking, MIME sniffing, HSTS) ----
app.use(helmet({
  hsts: isProd,
  contentSecurityPolicy: {
    directives: {
      upgradeInsecureRequests: isProd ? [] : null,
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"], // allows client calculator script
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      objectSrc: ["'none'"]
    }
  }
}));

// Limit request body size to 10 KB
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---- Sessions: HttpOnly, SameSite=Strict, Secure (in production), 30-minute idle expiry ----
app.use(session({
  name: 'sid',
  secret: SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: isProd,
    maxAge: 30 * 60 * 1000 // 30-minute idle expiry
  },
  rolling: true // renews idle expiration on activity
}));

// ---- CSRF protection (token stored in session, verified on every POST) ----
app.use((req, res, next) => {
  if (!req.session.csrf) {
    req.session.csrf = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrf = req.session.csrf;
  res.locals.user = req.session.user || null;
  res.locals.biz = BUSINESS;
  res.locals.error = null;
  res.locals.ok = null;

  if (req.method === 'POST') {
    const headerToken = req.headers['x-csrf-token'];
    const bodyToken = req.body && req.body._csrf;
    const token = String(bodyToken || headerToken || '');

    const a = Buffer.from(token);
    const b = Buffer.from(req.session.csrf);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(403).render('message', {
        title: 'Forbidden (403)',
        text: 'Invalid or missing CSRF token. Please refresh the page and try again.'
      });
    }
  }
  next();
});

// ---- Rate Limiting (express-rate-limit) ----
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts. Try again after 15 minutes.'
});

const formLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many submissions. Please try again later.'
});

// ---- Helpers & Security Logging ----
const log = (req, userId, action) => {
  try {
    db.prepare('INSERT INTO audit_log (user_id, action, ip) VALUES (?, ?, ?)')
      .run(userId ?? null, action, req.ip);
  } catch (err) {
    console.error('Audit log failed:', err.message);
  }
};

// Role-based access control: checks session role on the SERVER
const requireRole = (role) => (req, res, next) => {
  const u = req.session.user;
  if (!u) {
    return res.redirect(role === 'admin' ? '/admin/login' : '/login');
  }
  if (u.role !== role) {
    log(req, u.id, `DENIED ${role} route access`);
    return res.status(403).render('message', {
      title: 'Access Denied (403)',
      text: 'You do not have administrative permission to view this resource.'
    });
  }
  next();
};

const validEmail = (e) => /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/.test(e);
// Password rule: 10+ characters with upper-case, lower-case and a number
const strongPw = (p) => p.length >= 10 && /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p);
const DUMMY_HASH = bcrypt.hashSync('dummy-fallback-pass@123', 12);

// Reusable server-side calculator logic
function computeServerQuote(items) {
  if (!Array.isArray(items) || items.length === 0) {
    throw new Error('Quote must include at least one item.');
  }

  const products = db.prepare('SELECT * FROM products').all();
  const productMap = new Map(products.map(p => [p.id, p]));

  let grandTotal = 0;
  const verifiedItems = [];

  for (const item of items) {
    const prodId = Number(item.product_id);
    const prod = productMap.get(prodId);
    if (!prod) {
      throw new Error(`Invalid product selected.`);
    }

    const qty = parseInt(item.quantity, 10);
    if (isNaN(qty) || qty < 1 || qty > 100) {
      throw new Error(`Quantity must be a whole number between 1 and 100.`);
    }

    let width = null;
    let height = null;
    let lineTotal = 0;

    if (prod.pricing_type === 'sqft') {
      width = parseFloat(item.width);
      height = parseFloat(item.height);
      if (isNaN(width) || width < 0.5 || width > 30 || isNaN(height) || height < 0.5 || height > 30) {
        throw new Error(`Width and height for ${prod.name} must be between 0.5 and 30 ft.`);
      }
      // Area = width x height. Price = area x rate x quantity
      const area = width * height;
      lineTotal = Math.round(area * prod.rate * qty);
    } else {
      // For VL / piece: price = rate x quantity
      lineTotal = Math.round(prod.rate * qty);
    }

    grandTotal += lineTotal;
    verifiedItems.push({
      product_id: prod.id,
      name: prod.name,
      pricing_type: prod.pricing_type,
      rate: prod.rate,
      width,
      height,
      quantity: qty,
      line_total: lineTotal
    });
  }

  return { total: grandTotal, items: verifiedItems };
}

// Login Handler with Account Lockout (15 mins after 5 failed logins)
function doLogin(role) {
  return (req, res) => {
    const email = String(req.body.email || '').toLowerCase().trim();
    const password = String(req.body.password || '');
    const view = role === 'admin' ? 'admin-login' : 'login';
    const fail = (msg) => res.status(401).render(view, { title: role === 'admin' ? 'Admin Login' : 'Customer Login', error: msg });

    const u = db.prepare('SELECT * FROM users WHERE email = ? AND role = ?').get(email, role);

    // Check account lockout
    if (u && u.locked_until > Date.now()) {
      log(req, u.id, `LOCKED login attempt (${role})`);
      return fail('Account is temporarily locked due to multiple failed attempts. Try again after 15 minutes.');
    }

    const okPw = bcrypt.compareSync(password, u ? u.password_hash : DUMMY_HASH);

    if (!u || !okPw) {
      if (u) {
        const nextAttempts = u.failed_attempts + 1;
        if (nextAttempts >= 5) {
          // Lock for 15 minutes
          const lockTime = Date.now() + 15 * 60 * 1000;
          db.prepare('UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?').run(lockTime, u.id);
          log(req, u.id, `ACCOUNT LOCKED after 5 failed ${role} attempts`);
        } else {
          db.prepare('UPDATE users SET failed_attempts = ? WHERE id = ?').run(nextAttempts, u.id);
          log(req, u.id, `FAILED password attempt (${nextAttempts}/5) for ${role}`);
        }
      } else {
        log(req, null, `FAILED unknown user login attempt (${role}): ${email.slice(0, 50)}`);
      }
      // Use identical error message for wrong email and wrong password to prevent user enumeration
      return fail('Invalid email or password.');
    }

    // Login successful: reset failed attempts & lockout
    db.prepare('UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?').run(u.id);

    // Regenerate session ID after login to prevent session fixation attacks
    req.session.regenerate((err) => {
      if (err) return fail('Login session generation failed.');
      req.session.user = { id: u.id, name: u.name, email: u.email, role: u.role };
      req.session.csrf = crypto.randomBytes(32).toString('hex');
      log(req, u.id, `LOGIN SUCCESS (${role})`);
      res.redirect(role === 'admin' ? '/admin' : '/dashboard');
    });
  };
}

// ======================== ROUTES ========================

// Public Home Page
app.get('/', (req, res) => {
  const products = db.prepare('SELECT * FROM products ORDER BY id ASC').all();
  res.render('home', {
    title: `${BUSINESS.name} | Premium UPVC Windows & Doors`,
    products
  });
});

// Role Chooser
app.get('/choose', (req, res) => {
  res.render('choose', { title: 'Select Login Portal' });
});

// Server-side quote calculator API (public)
app.post('/api/calculate-quote', (req, res) => {
  try {
    const items = req.body.items;
    const result = computeServerQuote(items);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Save Quote as Enquiry (Logged-in customer or visitor)
app.post('/quote/save', formLimiter, (req, res) => {
  const products = db.prepare('SELECT * FROM products ORDER BY id ASC').all();
  const renderHome = (extra) => res.status(400).render('home', {
    title: `${BUSINESS.name} | Premium UPVC Windows & Doors`,
    products,
    ...extra
  });

  let items = [];
  try {
    items = JSON.parse(req.body.items_json || '[]');
  } catch {
    return renderHome({ error: 'Invalid quote items payload.' });
  }

  let quoteCalc;
  try {
    // ALWAYS calculate price on the SERVER
    quoteCalc = computeServerQuote(items);
  } catch (err) {
    return renderHome({ error: err.message });
  }

  const currentUser = req.session.user;
  let name = '';
  let phone = '';

  if (currentUser) {
    name = currentUser.name;
    // Look up user's phone or use provided
    phone = String(req.body.phone || '').replace(/\s/g, '').slice(0, 15);
    if (!phone) {
      // Find latest phone used by customer if any
      const prevEnq = db.prepare('SELECT phone FROM enquiries WHERE user_id = ? ORDER BY id DESC LIMIT 1').get(currentUser.id);
      phone = prevEnq ? prevEnq.phone : 'N/A';
    }
  } else {
    name = String(req.body.name || '').trim().slice(0, 80);
    phone = String(req.body.phone || '').replace(/\s/g, '').slice(0, 15);
    if (!name || name.length < 2) return renderHome({ error: 'Please enter your name.' });
    if (!/^\+?\d{10,13}$/.test(phone)) return renderHome({ error: 'Please enter a valid 10-13 digit phone number.' });
  }

  // Insert quote record
  const quoteInsert = db.prepare('INSERT INTO quotes (user_id, name, phone, total) VALUES (?, ?, ?, ?)')
    .run(currentUser?.id ?? null, name, phone, quoteCalc.total);
  const quoteId = Number(quoteInsert.lastInsertRowid);

  // Insert quote line items
  const itemInsert = db.prepare(`
    INSERT INTO quote_items (quote_id, product_id, width, height, quantity, line_total)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  for (const it of quoteCalc.items) {
    itemInsert.run(quoteId, it.product_id, it.width ?? null, it.height ?? null, it.quantity, it.line_total);
  }

  // Also record as enquiry for business follow-up
  const quoteSummary = quoteCalc.items.map(it =>
    `${it.name} (${it.pricing_type === 'sqft' ? `${it.width}x${it.height}ft` : 'pc'} x ${it.quantity} = Rs.${it.line_total})`
  ).join(', ');

  db.prepare('INSERT INTO enquiries (user_id, name, phone, message, status) VALUES (?, ?, ?, ?, ?)')
    .run(currentUser?.id ?? null, name, phone, `Quote #${quoteId} (Total: Rs. ${quoteCalc.total}): ${quoteSummary}`, 'New');

  log(req, currentUser?.id ?? null, `SAVED Quote #${quoteId} (Rs. ${quoteCalc.total})`);

  if (currentUser) {
    res.redirect('/dashboard');
  } else {
    res.render('home', {
      title: `${BUSINESS.name} | Premium UPVC Windows & Doors`,
      products,
      ok: `Quote #${quoteId} saved successfully for Rs. ${quoteCalc.total}! Our team will contact you at ${phone}.`
    });
  }
});

// General contact enquiry
app.post('/enquiry', formLimiter, (req, res) => {
  const products = db.prepare('SELECT * FROM products ORDER BY id ASC').all();
  const name = String(req.body.name || '').trim().slice(0, 80);
  const phone = String(req.body.phone || '').replace(/\s/g, '').slice(0, 15);
  const message = String(req.body.message || '').trim().slice(0, 1000);

  const renderHome = (extra) => res.status(400).render('home', {
    title: `${BUSINESS.name} | Premium UPVC Windows & Doors`,
    products,
    ...extra
  });

  if (!name || name.length < 2) return renderHome({ error: 'Please enter your name.' });
  if (!/^\+?\d{10,13}$/.test(phone)) return renderHome({ error: 'Please enter a valid 10-13 digit phone number.' });
  if (!message || message.length < 5) return renderHome({ error: 'Please enter a brief message (minimum 5 characters).' });

  db.prepare('INSERT INTO enquiries (user_id, name, phone, message, status) VALUES (?, ?, ?, ?, ?)')
    .run(req.session.user?.id ?? null, name, phone, message, 'New');

  log(req, req.session.user?.id ?? null, `SUBMITTED enquiry by ${name}`);

  res.render('home', {
    title: `${BUSINESS.name} | Premium UPVC Windows & Doors`,
    products,
    ok: 'Thank you for your message! Karunanithi UPVC will reach out to you shortly.'
  });
});

// ---- Customer Auth Routes ----
app.get('/login', (req, res) => {
  if (req.session.user?.role === 'customer') return res.redirect('/dashboard');
  res.render('login', { title: 'Customer Login' });
});
app.post('/login', loginLimiter, doLogin('customer'));

app.get('/register', (req, res) => {
  res.render('register', { title: 'Register Account' });
});

app.post('/register', loginLimiter, (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 80);
  const email = String(req.body.email || '').toLowerCase().trim().slice(0, 254);
  const password = String(req.body.password || '');
  const err = (m) => res.status(400).render('register', { title: 'Register Account', error: m });

  if (!name || name.length < 2) return err('Enter your full name.');
  if (!validEmail(email)) return err('Enter a valid email address.');
  if (!strongPw(password)) return err('Password must be 10+ characters with at least one upper-case letter, one lower-case letter, and one number.');

  try {
    // PUBLIC REGISTRATION MUST ALWAYS CREATE role = customer
    const hash = bcrypt.hashSync(password, 12);
    db.prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'customer')")
      .run(name, email, hash);
    log(req, null, `CUSTOMER registered: ${email}`);
  } catch (e) {
    return err('Could not complete registration. This email may already be in use.');
  }

  res.render('login', {
    title: 'Customer Login',
    ok: 'Account created successfully! Please log in.'
  });
});

// Customer Dashboard (Prevent IDOR: queries strictly match customer's own user_id)
app.get('/dashboard', requireRole('customer'), (req, res) => {
  const userId = req.session.user.id;

  // Retrieve customer's own enquiries
  const enquiries = db.prepare('SELECT * FROM enquiries WHERE user_id = ? ORDER BY id DESC').all(userId);

  // Retrieve customer's own quotes with their line items
  const quotes = db.prepare('SELECT * FROM quotes WHERE user_id = ? ORDER BY id DESC').all(userId);
  const quoteItemsQuery = db.prepare(`
    SELECT qi.*, p.name as product_name, p.pricing_type, p.rate
    FROM quote_items qi
    JOIN products p ON qi.product_id = p.id
    WHERE qi.quote_id = ?
  `);

  for (const q of quotes) {
    q.items = quoteItemsQuery.all(q.id);
  }

  res.render('dashboard', {
    title: 'Customer Dashboard',
    enquiries,
    quotes
  });
});

// ---- Admin Auth & Dashboard Routes ----
app.get('/admin/login', (req, res) => {
  if (req.session.user?.role === 'admin') return res.redirect('/admin');
  res.render('admin-login', { title: 'Admin Login' });
});
app.post('/admin/login', loginLimiter, doLogin('admin'));

// Admin Dashboard: View all enquiries, quotes, edit rates, view security audit log
app.get('/admin', requireRole('admin'), (req, res) => {
  const products = db.prepare('SELECT * FROM products ORDER BY id ASC').all();
  
  const enquiries = db.prepare(`
    SELECT e.*, u.email as user_email
    FROM enquiries e
    LEFT JOIN users u ON e.user_id = u.id
    ORDER BY e.id DESC
  `).all();

  const quotes = db.prepare(`
    SELECT q.*, u.email as user_email
    FROM quotes q
    LEFT JOIN users u ON q.user_id = u.id
    ORDER BY q.id DESC
  `).all();

  const quoteItemsQuery = db.prepare(`
    SELECT qi.*, p.name as product_name, p.pricing_type, p.rate
    FROM quote_items qi
    JOIN products p ON qi.product_id = p.id
    WHERE qi.quote_id = ?
  `);

  for (const q of quotes) {
    q.items = quoteItemsQuery.all(q.id);
  }

  const logs = db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 30').all();

  res.render('admin', {
    title: 'Admin Control Center',
    products,
    enquiries,
    quotes,
    logs
  });
});

// Admin: Update enquiry status (New / In Progress / Completed)
app.post('/admin/enquiry/:id/status', requireRole('admin'), (req, res) => {
  const enquiryId = Number(req.params.id);
  const status = String(req.body.status || '');
  if (!['New', 'In Progress', 'Completed'].includes(status)) {
    return res.status(400).send('Invalid status value');
  }

  db.prepare('UPDATE enquiries SET status = ? WHERE id = ?').run(status, enquiryId);
  log(req, req.session.user.id, `UPDATED Enquiry #${enquiryId} status -> ${status}`);
  res.redirect('/admin');
});

// Admin: Edit product rate
app.post('/admin/product/:id/rate', requireRole('admin'), (req, res) => {
  const productId = Number(req.params.id);
  const newRate = parseFloat(req.body.rate);

  if (isNaN(newRate) || newRate <= 0) {
    return res.status(400).send('Invalid rate value');
  }

  const prod = db.prepare('SELECT name FROM products WHERE id = ?').get(productId);
  if (!prod) return res.status(404).send('Product not found');

  db.prepare('UPDATE products SET rate = ? WHERE id = ?').run(newRate, productId);
  log(req, req.session.user.id, `UPDATED Product #${productId} (${prod.name}) rate -> Rs. ${newRate}`);
  res.redirect('/admin');
});

// Logout
app.post('/logout', (req, res) => {
  const uid = req.session.user?.id;
  req.session.destroy(() => {
    res.clearCookie('sid');
    res.redirect('/');
  });
  if (uid) log(req, uid, 'LOGOUT');
});

// 404 & 500 handlers
app.use((req, res) => {
  res.status(404).render('message', { title: 'Page Not Found (404)', text: 'The requested page does not exist.' });
});

app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).render('message', { title: 'Server Error (500)', text: 'An unexpected internal error occurred.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Karunanithi UPVC server running on http://localhost:${PORT}`);
});
