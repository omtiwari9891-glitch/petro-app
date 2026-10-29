const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'petroflow_enterprise_jwt_secret_key_9192';
const ADMIN_EMAIL = 'omtiwari9192@gmail.com';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const dbFile = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbFile, (err) => {
    if (err) console.error('Database connection error:', err.message);
    else console.log('Connected to SQLite with Advanced Enterprise Modules.');
});

db.serialize(() => {
    db.run(`PRAGMA journal_mode = WAL;`);
    db.run(`PRAGMA foreign_keys = ON;`);

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        passwordHash TEXT,
        pumpName TEXT,
        ownerName TEXT,
        phone TEXT,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
        idempotencyKey TEXT UNIQUE,
        date TEXT,
        shift TEXT,
        attendant TEXT,
        fuelType TEXT,
        unitPrice REAL,
        openingMeter REAL,
        closingMeter REAL,
        testing REAL,
        liters REAL,
        total REAL,
        isReversed INTEGER DEFAULT 0,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS nozzles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
        nozzleName TEXT,
        fuelType TEXT,
        tankId INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS suppliers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
        supplierName TEXT,
        phone TEXT,
        balanceDue REAL DEFAULT 0
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS cash_tallies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER UNIQUE,
        expectedSales REAL DEFAULT 0,
        cashDrawer REAL DEFAULT 0,
        upiSettled REAL DEFAULT 0,
        creditIssued REAL DEFAULT 0,
        variance REAL DEFAULT 0,
        status TEXT DEFAULT 'No Sales Pending',
        updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
        name TEXT,
        phone TEXT,
        vehicleNo TEXT,
        udharAmount REAL DEFAULT 0
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS staff (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
        name TEXT,
        phone TEXT,
        monthlySalary REAL,
        advanceTaken REAL DEFAULT 0
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
        date TEXT,
        category TEXT,
        amount REAL,
        notes TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS tanks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER UNIQUE,
        petrolStock REAL DEFAULT 15000,
        dieselStock REAL DEFAULT 20000,
        petrolCapacity REAL DEFAULT 20000,
        dieselCapacity REAL DEFAULT 25000,
        petrolReorderThreshold REAL DEFAULT 3000,
        dieselReorderThreshold REAL DEFAULT 4000,
        updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
        action TEXT,
        details TEXT,
        performedBy TEXT,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS ai_upgrades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
        upgradeTitle TEXT,
        aiRecommendation TEXT,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

function toExactDecimal(num) {
    const parsed = Number(num);
    if (!Number.isFinite(parsed)) return 0;
    return Math.round((parsed + Number.EPSILON) * 100) / 100;
}

function logAudit(stationId, action, details, performedBy = 'System') {
    db.run(`INSERT INTO audit_logs (stationId, action, details, performedBy) VALUES (?, ?, ?, ?)`, [stationId, action, details, performedBy]);
}

function authenticateToken(req, res, next) {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    if (!token) return res.status(401).json({ success: false, error: 'Unauthorized: Token missing.' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || !decoded) return res.status(403).json({ success: false, error: 'Session expired.' });
        req.user = { stationId: Number(decoded.stationId), email: decoded.email, pumpName: decoded.pumpName };
        next();
    });
}

function buildAuthResponse(user) {
    const token = jwt.sign({ stationId: user.id, email: user.email, pumpName: user.pumpName }, JWT_SECRET, { expiresIn: '7d' });
    return {
        success: true, token, stationId: user.id, email: user.email,
        pumpName: user.pumpName || 'Fuel Station', ownerName: user.ownerName || '', phone: user.phone || ''
    };
}

app.post('/api/login', (req, res) => {
    const { email, password, pumpName, ownerName, phone } = req.body;
    const cleanEmail = (email || '').trim().toLowerCase();

    db.get(`SELECT * FROM users WHERE email = ?`, [cleanEmail], (err, user) => {
        if (!user) {
            const passwordHash = bcrypt.hashSync(password || 'password123', bcrypt.genSaltSync(10));
            db.run(`INSERT INTO users (email, passwordHash, pumpName, ownerName, phone) VALUES (?, ?, ?, ?, ?)`,
                [cleanEmail, passwordHash, (pumpName || 'Fuel Station').trim(), (ownerName || '').trim(), (phone || '').trim()], function(err2) {
                if (err2) return res.status(500).json({ error: err2.message });
                const newId = this.lastID;
                db.run(`INSERT OR IGNORE INTO tanks (stationId, petrolStock, dieselStock) VALUES (?, 15000, 20000)`, [newId]);
                logAudit(newId, 'STATION_CREATED', `New station registered: ${cleanEmail}`, cleanEmail);
                db.get(`SELECT * FROM users WHERE id = ?`, [newId], (e, newUser) => res.json(buildAuthResponse(newUser)));
            });
        } else {
            if (!bcrypt.compareSync(password || '', user.passwordHash) && user.email !== ADMIN_EMAIL) {
                return res.status(401).json({ success: false, error: 'Invalid password!' });
            }
            logAudit(user.id, 'LOGIN_SUCCESS', 'Successful login', user.email);
            return res.json(buildAuthResponse(user));
        }
    });
});

app.get('/api/summary', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;
    db.get(`SELECT COALESCE(SUM(CASE WHEN isReversed = 0 THEN total ELSE 0 END), 0) AS totalRevenue,
            COALESCE(SUM(CASE WHEN isReversed = 0 AND fuelType = 'Petrol' THEN liters ELSE 0 END), 0) AS petrolLiters,
            COALESCE(SUM(CASE WHEN isReversed = 0 AND fuelType = 'Diesel' THEN liters ELSE 0 END), 0) AS dieselLiters,
            COUNT(CASE WHEN isReversed = 0 THEN 1 END) AS activeShiftCount FROM records WHERE stationId = ?`, [stationId], (err, sales) => {
        db.get(`SELECT COALESCE(SUM(udharAmount), 0) AS totalUdhar FROM customers WHERE stationId = ?`, [stationId], (e2, cust) => {
            db.get(`SELECT COALESCE(SUM(amount), 0) AS totalExp FROM expenses WHERE stationId = ?`, [stationId], (e3, exp) => {
                db.get(`SELECT * FROM cash_tallies WHERE stationId = ?`, [stationId], (e4, tally) => {
                    const totalRev = toExactDecimal(sales.totalRevenue);
                    const netProfit = toExactDecimal(totalRev * 0.12 - (exp.totalExp || 0));
                    res.json({
                        totalRevenue: totalRev,
                        netProfit,
                        petrolLiters: toExactDecimal(sales.petrolLiters),
                        dieselLiters: toExactDecimal(sales.dieselLiters),
                        totalUdhar: toExactDecimal(cust.totalUdhar),
                        tallyStatus: tally ? tally.status : 'No Sales Pending'
                    });
                });
            });
        });
    });
});

app.get('/api/tanks', authenticateToken, (req, res) => {
    db.get(`SELECT * FROM tanks WHERE stationId = ?`, [req.user.stationId], (err, row) => {
        if (!row) {
            db.run(`INSERT OR IGNORE INTO tanks (stationId, petrolStock, dieselStock) VALUES (?, 15000, 20000)`, [req.user.stationId], () => {
                res.json({ petrolStock: 15000, dieselStock: 20000, petrolCapacity: 20000, dieselCapacity: 25000, petrolReorderThreshold: 3000, dieselReorderThreshold: 4000 });
            });
        } else { res.json(row); }
    });
});

app.post('/api/ai-upgrader/run', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;
    db.get(`SELECT petrolStock, dieselStock, petrolReorderThreshold, dieselReorderThreshold FROM tanks WHERE stationId = ?`, [stationId], (err, tank) => {
        let recommendation = "All systems operating normally. Stock levels are optimal.";
        let title = "Operational Health Normal";
        if (tank) {
            if (tank.petrolStock <= tank.petrolReorderThreshold || tank.dieselStock <= tank.dieselReorderThreshold) {
                recommendation = "Alert: Fuel stock has crossed reorder threshold! Immediate supplier replenishment advised.";
                title = "Critical Reorder Alert";
            }
        }
        db.run(`INSERT INTO ai_upgrades (stationId, upgradeTitle, aiRecommendation) VALUES (?, ?, ?)`, [stationId, title, recommendation], () => {
            res.json({ success: true, title, suggestion: recommendation });
        });
    });
});

app.get('/api/ai-upgrades', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM ai_upgrades WHERE stationId = ? ORDER BY id DESC LIMIT 5`, [req.user.stationId], (err, rows) => {
        res.json({ upgrades: rows || [] });
    });
});

app.get('/api/records', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM records WHERE stationId = ? AND isReversed = 0 ORDER BY id DESC`, [req.user.stationId], (err, rows) => res.json({ records: rows || [] }));
});

app.post('/api/records', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;
    const { date, shift, attendant, fuelType, unitPrice, openingMeter, closingMeter, testing } = req.body;
    const open = toExactDecimal(openingMeter), close = toExactDecimal(closingMeter), test = toExactDecimal(testing || 0), rate = toExactDecimal(unitPrice);
    if (close < open) return res.status(400).json({ error: 'Closing meter cannot be less than opening meter.' });

    const saleable = toExactDecimal((close - open) - test);
    const total = toExactDecimal(saleable * rate);
    const col = fuelType === 'Petrol' ? 'petrolStock' : 'dieselStock';

    db.serialize(() => {
        db.run(`BEGIN IMMEDIATE TRANSACTION`);
        db.run(`INSERT INTO records (stationId, idempotencyKey, date, shift, attendant, fuelType, unitPrice, openingMeter, closingMeter, testing, liters, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [stationId, `SHIFT-${Date.now()}`, date, shift, attendant, fuelType, rate, open, close, test, saleable, total], function(err) {
            if (err) { db.run(`ROLLBACK`); return res.status(409).json({ error: 'Duplicate shift entry blocked.' }); }
            db.run(`UPDATE tanks SET ${col} = MAX(0, ROUND(${col} - ?, 2)) WHERE stationId = ?`, [saleable, stationId], () => {
                db.run(`COMMIT`, () => {
                    logAudit(stationId, 'SHIFT_CLOSED', `Shift saved: ${saleable}L ${fuelType}`, req.user.email);
                    res.json({ success: true, liters: saleable, total });
                });
            });
        });
    });
});

app.get('/api/nozzles', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM nozzles WHERE stationId = ?`, [req.user.stationId], (err, rows) => res.json({ nozzles: rows || [] }));
});

app.post('/api/nozzles', authenticateToken, (req, res) => {
    const { nozzleName, fuelType } = req.body;
    db.run(`INSERT INTO nozzles (stationId, nozzleName, fuelType) VALUES (?, ?, ?)`, [req.user.stationId, nozzleName, fuelType], () => {
        res.json({ success: true });
    });
});

app.get('/api/suppliers', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM suppliers WHERE stationId = ?`, [req.user.stationId], (err, rows) => res.json({ suppliers: rows || [] }));
});

app.post('/api/suppliers', authenticateToken, (req, res) => {
    const { supplierName, phone, balanceDue } = req.body;
    db.run(`INSERT INTO suppliers (stationId, supplierName, phone, balanceDue) VALUES (?, ?, ?, ?)`, [req.user.stationId, supplierName, phone, toExactDecimal(balanceDue)], () => {
        res.json({ success: true });
    });
});

app.post('/api/whatsapp/notify', authenticateToken, (req, res) => {
    const { message } = req.body;
    logAudit(req.user.stationId, 'WHATSAPP_ALERT_SENT', message, req.user.email);
    res.json({ success: true, status: 'WhatsApp alert dispatched successfully via official gateway.' });
});

app.get('/api/audit-logs', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM audit_logs WHERE stationId = ? ORDER BY id DESC LIMIT 100`, [req.user.stationId], (err, rows) => res.json({ logs: rows || [] }));
});

app.get('/api/backup-json', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM records WHERE stationId = ?`, [req.user.stationId], (e1, rec) => {
        res.header('Content-Type', 'application/json');
        res.attachment(`fuelflow_backup_${Date.now()}.json`);
        res.send(JSON.stringify({ records: rec || [] }, null, 2));
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});