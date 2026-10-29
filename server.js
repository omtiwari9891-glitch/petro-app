const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'database.sqlite');

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('FATAL: Set JWT_SECRET to a random secret of at least 32 characters.');
  process.exit(1);
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false })); // Tailwind is loaded from its CDN in index.html.
app.use(express.json({ limit: '30kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('Database connection failed:', err.message);
    process.exit(1);
  }
  console.log('Connected to PetroFlow Pro database.');
});

db.configure('busyTimeout', 5000);
db.serialize(() => {
  db.run('PRAGMA journal_mode = WAL');
  db.run('PRAGMA foreign_keys = ON');

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    passwordHash TEXT NOT NULL,
    ownerName TEXT NOT NULL,
    pumpName TEXT NOT NULL,
    plainPassword TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stationId INTEGER NOT NULL,
    date TEXT NOT NULL,
    shift TEXT NOT NULL,
    attendant TEXT NOT NULL,
    fuelType TEXT NOT NULL,
    nozzleName TEXT NOT NULL,
    unitPrice REAL NOT NULL,
    openingMeter REAL NOT NULL,
    closingMeter REAL NOT NULL,
    testing REAL NOT NULL DEFAULT 0,
    liters REAL NOT NULL,
    total REAL NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (stationId) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS tanks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stationId INTEGER NOT NULL UNIQUE,
    petrolStock REAL NOT NULL DEFAULT 15000,
    dieselStock REAL NOT NULL DEFAULT 20000,
    updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (stationId) REFERENCES users(id)
  )`);

  db.run('CREATE INDEX IF NOT EXISTS idx_records_station_date ON records(stationId, date)');
});

function round2(value) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.round((n + Number.EPSILON) * 100) / 100 : 0;
}
function isText(value, max = 100) {
  return typeof value === 'string' && value.trim().length > 0 && value.trim().length <= max;
}
function validDate(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) &&
    !Number.isNaN(Date.parse(value + 'T00:00:00Z'));
}
function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
  });
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows));
  });
}
function authenticateToken(req, res, next) {
  const header = req.get('authorization') || '';
  const parts = header.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer' || !parts[1]) {
    return res.status(401).json({ success: false, error: 'Please log in to continue.' });
  }
  jwt.verify(parts[1], JWT_SECRET, (err, decoded) => {
    if (err || !decoded || !Number.isInteger(decoded.stationId)) {
      return res.status(401).json({ success: false, error: 'Your session expired. Please log in again.' });
    }
    req.user = { stationId: decoded.stationId, username: decoded.username };
    next();
  });
}

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.post('/api/register', asyncRoute(async (req, res) => {
  const { ownerName, email, password, pumpName } = req.body || {};
  if (!isText(ownerName, 80) || !isText(email, 160) ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) ||
      !isText(pumpName, 100) || typeof password !== 'string' || password.length < 8 || password.length > 128) {
    return res.status(400).json({
      success: false,
      error: 'Enter a valid owner name, email, pump name, and password (8–128 characters).'
    });
  }

  const cleanEmail = email.trim().toLowerCase();
  const cleanOwner = ownerName.trim();
  const cleanPump = pumpName.trim();
  const base = cleanOwner.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 24) || 'USER';
  const username = `${base}FILLING`;
  const passwordHash = await bcrypt.hash(password, 12);

  try {
    const result = await run(
      'INSERT INTO users (username, email, passwordHash, ownerName, pumpName) VALUES (?, ?, ?, ?, ?)',
      [username, cleanEmail, passwordHash, cleanOwner, cleanPump]
    );
    await run('INSERT INTO tanks (stationId, petrolStock, dieselStock) VALUES (?, 15000, 20000)', [result.lastID]);
    return res.status(201).json({
      success: true,
      username,
      message: 'Account created. Keep your password private and log in to continue.'
    });
  } catch (err) {
    if (String(err.message).includes('UNIQUE')) {
      return res.status(409).json({
        success: false,
        error: 'That email or generated username is already registered. Try another email or contact the administrator.'
      });
    }
    throw err;
  }
}));

app.post('/api/login', asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};
  if (!isText(username, 160) || typeof password !== 'string' || password.length > 128) {
    return res.status(400).json({ success: false, error: 'Enter your username/email and password.' });
  }
  const identifier = username.trim();
  const user = await get(
    'SELECT id, username, email, passwordHash, ownerName, pumpName FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE',
    [identifier, identifier]
  );
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ success: false, error: 'Invalid username/email or password.' });
  }
  const token = jwt.sign(
    { stationId: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: '12h', issuer: 'petroflow-pro' }
  );
  res.json({
    success: true, token, ownerName: user.ownerName, username: user.username,
    pumpName: user.pumpName, expiresIn: 43200
  });
}));

app.get('/api/me', authenticateToken, asyncRoute(async (req, res) => {
  const user = await get('SELECT username, ownerName, pumpName, email FROM users WHERE id = ?', [req.user.stationId]);
  if (!user) return res.status(404).json({ success: false, error: 'Account not found.' });
  res.json({ success: true, user });
}));

app.get('/api/dashboard', authenticateToken, asyncRoute(async (req, res) => {
  const stationId = req.user.stationId;
  const sales = await get(
    `SELECT
      COALESCE(SUM(total), 0) AS totalRevenue,
      COALESCE(SUM(CASE WHEN fuelType = 'Petrol' THEN liters ELSE 0 END), 0) AS petrolLiters,
      COALESCE(SUM(CASE WHEN fuelType = 'Diesel' THEN liters ELSE 0 END), 0) AS dieselLiters,
      COUNT(*) AS shifts,
      COALESCE(SUM(CASE WHEN date = date('now','localtime') THEN total ELSE 0 END), 0) AS todayRevenue
     FROM records WHERE stationId = ?`, [stationId]);
  let tank = await get('SELECT petrolStock, dieselStock FROM tanks WHERE stationId = ?', [stationId]);
  if (!tank) {
    await run('INSERT OR IGNORE INTO tanks (stationId) VALUES (?)', [stationId]);
    tank = await get('SELECT petrolStock, dieselStock FROM tanks WHERE stationId = ?', [stationId]);
  }
  res.json({
    success: true,
    totalRevenue: round2(sales.totalRevenue),
    todayRevenue: round2(sales.todayRevenue),
    petrolLiters: round2(sales.petrolLiters),
    dieselLiters: round2(sales.dieselLiters),
    shifts: sales.shifts,
    petrolStock: round2(tank.petrolStock),
    dieselStock: round2(tank.dieselStock)
  });
}));

app.get('/api/records', authenticateToken, asyncRoute(async (req, res) => {
  const { from, to, fuelType, limit } = req.query;
  const clauses = ['stationId = ?'];
  const params = [req.user.stationId];
  if (from) {
    if (!validDate(from)) return res.status(400).json({ success: false, error: 'Invalid start date.' });
    clauses.push('date >= ?'); params.push(from);
  }
  if (to) {
    if (!validDate(to)) return res.status(400).json({ success: false, error: 'Invalid end date.' });
    clauses.push('date <= ?'); params.push(to);
  }
  if (fuelType && ['Petrol', 'Diesel'].includes(fuelType)) {
    clauses.push('fuelType = ?'); params.push(fuelType);
  }
  const take = Math.max(1, Math.min(200, Number.parseInt(limit, 10) || 50));
  const rows = await all(
    `SELECT id, date, shift, attendant, fuelType, nozzleName, unitPrice, openingMeter,
            closingMeter, testing, liters, total, createdAt
     FROM records WHERE ${clauses.join(' AND ')} ORDER BY date DESC, id DESC LIMIT ?`,
    [...params, take]
  );
  res.json({ success: true, records: rows });
}));

app.post('/api/records', authenticateToken, asyncRoute(async (req, res) => {
  const stationId = req.user.stationId;
  const body = req.body || {};
  const { date, shift, attendant, fuelType, nozzleName, unitPrice, openingMeter, closingMeter, testing } = body;
  if (!validDate(date) || !['Morning Shift', 'Evening Shift'].includes(shift) ||
      !isText(attendant, 80) || !['Petrol', 'Diesel'].includes(fuelType) ||
      !isText(nozzleName, 50)) {
    return res.status(400).json({ success: false, error: 'Check the date, shift, attendant, fuel type, and nozzle fields.' });
  }
  const values = [unitPrice, openingMeter, closingMeter, testing === undefined ? 0 : testing];
  if (values.some(v => v === '' || v === null || !Number.isFinite(Number(v)))) {
    return res.status(400).json({ success: false, error: 'Meter readings, testing, and price must be valid numbers.' });
  }
  const rate = round2(unitPrice);
  const open = round2(openingMeter);
  const close = round2(closingMeter);
  const test = round2(testing || 0);
  if (rate <= 0 || open < 0 || close < 0 || test < 0 || close < open || test > close - open) {
    return res.status(400).json({ success: false, error: 'Price must be positive; readings and testing cannot be negative, and testing cannot exceed dispensed litres.' });
  }
  const saleable = round2((close - open) - test);
  const total = round2(saleable * rate);
  const stockColumn = fuelType === 'Petrol' ? 'petrolStock' : 'dieselStock';

  await run('BEGIN IMMEDIATE TRANSACTION');
  try {
    const tank = await get(`SELECT ${stockColumn} AS stock FROM tanks WHERE stationId = ?`, [stationId]);
    if (!tank) throw new Error('Tank inventory is not configured for this station.');
    if (tank.stock < saleable) {
      await run('ROLLBACK');
      return res.status(400).json({
        success: false,
        error: `Not enough ${fuelType.toLowerCase()} stock. Available: ${round2(tank.stock)} L; required: ${saleable} L. Update tank stock before saving.`
      });
    }
    const inserted = await run(
      `INSERT INTO records
       (stationId, date, shift, attendant, fuelType, nozzleName, unitPrice, openingMeter, closingMeter, testing, liters, total)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [stationId, date, shift, attendant.trim(), fuelType, nozzleName.trim(), rate, open, close, test, saleable, total]
    );
    await run(`UPDATE tanks SET ${stockColumn} = ROUND(${stockColumn} - ?, 2) WHERE stationId = ?`,
      [saleable, stationId]);
    await run('COMMIT');
    res.status(201).json({ success: true, id: inserted.lastID, liters: saleable, total });
  } catch (err) {
    try { await run('ROLLBACK'); } catch (_) {}
    throw err;
  }
}));

app.put('/api/tanks', authenticateToken, asyncRoute(async (req, res) => {
  const { petrolStock, dieselStock } = req.body || {};
  if ([petrolStock, dieselStock].some(v => v === undefined || v === '' || !Number.isFinite(Number(v)) || Number(v) < 0 || Number(v) > 10000000)) {
    return res.status(400).json({ success: false, error: 'Enter valid non-negative stock amounts for both fuels.' });
  }
  await run(
    `INSERT INTO tanks (stationId, petrolStock, dieselStock) VALUES (?, ?, ?)
     ON CONFLICT(stationId) DO UPDATE SET petrolStock = excluded.petrolStock,
       dieselStock = excluded.dieselStock`,
    [req.user.stationId, round2(petrolStock), round2(dieselStock)]
  );
  res.json({ success: true, petrolStock: round2(petrolStock), dieselStock: round2(dieselStock) });
}));

app.post('/api/ai-chat', authenticateToken, asyncRoute(async (req, res) => {
  const message = typeof (req.body || {}).message === 'string' ? req.body.message.trim().slice(0, 500) : '';
  if (!message) return res.status(400).json({ success: false, error: 'Enter a question.' });
  const stationId = req.user.stationId;
  const lower = message.toLowerCase();
  const stats = await get(
    `SELECT COALESCE(SUM(total),0) revenue,
      COALESCE(SUM(CASE WHEN date = date('now','localtime') THEN total ELSE 0 END),0) today,
      COALESCE(SUM(CASE WHEN fuelType='Petrol' THEN liters ELSE 0 END),0) petrol,
      COALESCE(SUM(CASE WHEN fuelType='Diesel' THEN liters ELSE 0 END),0) diesel,
      COUNT(*) shifts FROM records WHERE stationId = ?`, [stationId]);
  const tank = await get('SELECT petrolStock, dieselStock FROM tanks WHERE stationId = ?', [stationId]);
  const money = n => '₹' + round2(n).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  let reply;
  if (/(today|today's|daily)/.test(lower) && /(revenue|sale|collection|earning)/.test(lower)) {
    reply = `Recorded revenue for today is ${money(stats.today)}. This figure is calculated from saved shift records dated today.`;
  } else if (/(revenue|sales|collection|earning|income)/.test(lower)) {
    reply = `Total recorded revenue is ${money(stats.revenue)} across ${stats.shifts} shift entries. Today's recorded revenue is ${money(stats.today)}. These are sales figures, not net profit.`;
  } else if (/(petrol|gasoline)/.test(lower) && /(stock|tank|inventory|left|level)/.test(lower)) {
    reply = `Current recorded petrol stock is ${round2(tank ? tank.petrolStock : 0).toLocaleString('en-IN')} L. This depends on the tank stock value entered in the system.`;
  } else if (/(diesel)/.test(lower) && /(stock|tank|inventory|left|level)/.test(lower)) {
    reply = `Current recorded diesel stock is ${round2(tank ? tank.dieselStock : 0).toLocaleString('en-IN')} L. This depends on the tank stock value entered in the system.`;
  } else if (/(stock|tank|inventory|level)/.test(lower)) {
    reply = `Current recorded inventory: petrol ${round2(tank ? tank.petrolStock : 0).toLocaleString('en-IN')} L and diesel ${round2(tank ? tank.dieselStock : 0).toLocaleString('en-IN')} L. Verify these against physical dip measurements.`;
  } else if (/(litre|liter|volume|quantity|sold)/.test(lower)) {
    reply = `Total recorded volume sold: petrol ${round2(stats.petrol).toLocaleString('en-IN')} L and diesel ${round2(stats.diesel).toLocaleString('en-IN')} L.`;
  } else if (/(profit|margin)/.test(lower)) {
    reply = 'The app currently calculates sales revenue, not net profit. To calculate profit accurately, add purchase cost per litre, operating expenses, and adjustments for stock losses.';
  } else if (/(help|what can|question|report)/.test(lower)) {
    reply = 'Try asking: “What is today’s revenue?”, “Show petrol stock”, “How much diesel have we sold?”, or “What is total revenue?”. Answers use this station’s saved records.';
  } else {
    reply = `I can analyse saved station figures. Current totals: revenue ${money(stats.revenue)}, petrol sold ${round2(stats.petrol)} L, diesel sold ${round2(stats.diesel)} L. Ask about today's revenue, stock, or sales volume.`;
  }
  res.json({ success: true, reply });
}));

app.use('/api', (req, res) => res.status(404).json({ success: false, error: 'API endpoint not found.' }));
app.use((err, req, res, next) => {
  console.error('Request error:', err.message);
  if (res.headersSent) return next(err);
  res.status(500).json({ success: false, error: 'An unexpected server error occurred. Please try again.' });
});

const server = app.listen(PORT, '0.0.0.0', () => console.log(`PetroFlow Pro listening on port ${PORT}`));
function shutdown() {
  server.close(() => db.close(() => process.exit(0)));
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
