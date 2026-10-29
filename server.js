const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'petroapp_secure_jwt_secret_9192';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const dbFile = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbFile, (err) => {
    if (err) console.error('Database error:', err.message);
    else console.log('Connected to SQLite for Petro App.');
});

db.serialize(() => {
    db.run(`PRAGMA journal_mode = WAL;`);
    db.run(`PRAGMA foreign_keys = ON;`);

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        passwordHash TEXT,
        ownerName TEXT,
        pumpName TEXT,
        plainPassword TEXT,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
        date TEXT,
        shift TEXT,
        attendant TEXT,
        fuelType TEXT,
        nozzleName TEXT,
        unitPrice REAL,
        openingMeter REAL,
        closingMeter REAL,
        testing REAL,
        liters REAL,
        total REAL,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS tanks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER UNIQUE,
        petrolStock REAL DEFAULT 15000,
        dieselStock REAL DEFAULT 20000
    )`);
});

function toExactDecimal(num) {
    const parsed = Number(num);
    if (!Number.isFinite(parsed)) return 0;
    return Math.round((parsed + Number.EPSILON) * 100) / 100;
}

function authenticateToken(req, res, next) {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    if (!token) return res.status(401).json({ success: false, error: 'Unauthorized' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || !decoded) return res.status(403).json({ success: false, error: 'Session expired' });
        req.user = { stationId: Number(decoded.stationId), username: decoded.username };
        next();
    });
}

app.post('/api/register', (req, res) => {
    const { ownerName, email, password, pumpName } = req.body;
    const username = (ownerName || 'USER').toUpperCase().replace(/\s+/g, '') + 'FILLING';
    const cleanEmail = (email || '').trim().toLowerCase();
    const passwordHash = bcrypt.hashSync(password || 'password123', bcrypt.genSaltSync(10));

    db.run(`INSERT INTO users (username, email, passwordHash, ownerName, pumpName, plainPassword) VALUES (?, ?, ?, ?, ?, ?)`,
        [username, cleanEmail, passwordHash, ownerName, pumpName || 'Petro App Station', password], function(err) {
        if (err) return res.status(400).json({ success: false, error: 'User already exists or invalid data.' });
        const newId = this.lastID;
        db.run(`INSERT OR IGNORE INTO tanks (stationId, petrolStock, dieselStock) VALUES (?, 15000, 20000)`, [newId]);
        res.json({ success: true, username, ownerName, password });
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const cleanUser = (username || '').trim().toUpperCase();

    db.get(`SELECT * FROM users WHERE username = ? OR email = ?`, [cleanUser, cleanUser.toLowerCase()], (err, user) => {
        if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
            return res.status(401).json({ success: false, error: 'Invalid Username or Password!' });
        }
        const token = jwt.sign({ stationId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, token, ownerName: user.ownerName, username: user.username });
    });
});

app.get('/api/dashboard', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;
    db.get(`SELECT COALESCE(SUM(total), 0) AS totalRev,
            COALESCE(SUM(CASE WHEN fuelType = 'Petrol' THEN liters ELSE 0 END), 0) AS petrolLiters,
            COALESCE(SUM(CASE WHEN fuelType = 'Diesel' THEN liters ELSE 0 END), 0) AS dieselLiters
            FROM records WHERE stationId = ?`, [stationId], (err, sales) => {
        db.get(`SELECT * FROM tanks WHERE stationId = ?`, [stationId], (e2, tank) => {
            res.json({
                totalRevenue: toExactDecimal(sales.totalRev),
                petrolLiters: toExactDecimal(sales.petrolLiters),
                dieselLiters: toExactDecimal(sales.dieselLiters),
                petrolStock: tank ? tank.petrolStock : 15000,
                dieselStock: tank ? tank.dieselStock : 20000
            });
        });
    });
});

app.post('/api/records', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;
    const { date, shift, attendant, fuelType, nozzleName, unitPrice, openingMeter, closingMeter, testing } = req.body;
    const open = toExactDecimal(openingMeter), close = toExactDecimal(closingMeter), test = toExactDecimal(testing || 0), rate = toExactDecimal(unitPrice);
    if (close < open) return res.status(400).json({ error: 'Closing meter cannot be less than opening.' });

    const saleable = toExactDecimal((close - open) - test);
    const total = toExactDecimal(saleable * rate);
    const col = fuelType === 'Petrol' ? 'petrolStock' : 'dieselStock';

    db.serialize(() => {
        db.run(`BEGIN IMMEDIATE TRANSACTION`);
        db.run(`INSERT INTO records (stationId, date, shift, attendant, fuelType, nozzleName, unitPrice, openingMeter, closingMeter, testing, liters, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [stationId, date, shift, attendant, fuelType, nozzleName || 'Nozzle 1', rate, open, close, test, saleable, total], () => {
            db.run(`UPDATE tanks SET ${col} = MAX(0, ROUND(${col} - ?, 2)) WHERE stationId = ?`, [saleable, stationId], () => {
                db.run(`COMMIT`, () => { res.json({ success: true, liters: saleable, total }); });
            });
        });
    });
});

app.post('/api/ai-chat', authenticateToken, (req, res) => {
    const { message } = req.body;
    let reply = "Hello! I am your Petro App AI Assistant. All your tank levels and shift readings are operating at peak efficiency.";
    const lower = (message || '').toLowerCase();
    if (lower.includes('profit') || lower.includes('revenue')) {
        reply = "Your station is generating healthy daily margins. Check your morning and evening shift collections!";
    } else if (lower.includes('stock') || lower.includes('tank')) {
        reply = "Underground fuel tanks are well balanced. Keep track of nozzle readings regularly.";
    }
    res.json({ success: true, reply });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Petro App running on port ${PORT}`);
});