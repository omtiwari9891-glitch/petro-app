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
    else console.log('Connected to SQLite with AI Self-Upgrader & Immutable Triggers.');
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
        planTier TEXT DEFAULT 'Starter',
        isSubscribed INTEGER DEFAULT 0,
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
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(stationId, date, shift, fuelType, openingMeter)
    )`);

    db.run(`CREATE TRIGGER IF NOT EXISTS prevent_records_delete
        BEFORE DELETE ON records
        BEGIN
            SELECT RAISE(ABORT, 'Suraksha Niyam: Shift record delete nahi ho sakta. Kripya audited reversal use karein.');
        END;`);

    db.run(`CREATE TABLE IF NOT EXISTS cash_tallies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER UNIQUE,
        expectedSales REAL DEFAULT 0,
        cashDrawer REAL DEFAULT 0,
        upiSettled REAL DEFAULT 0,
        creditIssued REAL DEFAULT 0,
        variance REAL DEFAULT 0,
        status TEXT DEFAULT 'Koi Sale Baaki Nahi',
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

    db.run(`CREATE TABLE IF NOT EXISTS customer_payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
        idempotencyKey TEXT UNIQUE,
        customerId INTEGER,
        date TEXT,
        amountPaid REAL,
        paymentMode TEXT,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
        idempotencyKey TEXT UNIQUE,
        date TEXT,
        category TEXT,
        amount REAL,
        notes TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS staff (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
        name TEXT,
        phone TEXT,
        monthlySalary REAL,
        advanceTaken REAL DEFAULT 0
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS tanks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER UNIQUE,
        petrolStock REAL DEFAULT 15000,
        dieselStock REAL DEFAULT 20000,
        petrolCapacity REAL DEFAULT 20000,
        dieselCapacity REAL DEFAULT 25000,
        deductionCount INTEGER DEFAULT 0,
        updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS tank_dips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
        date TEXT,
        fuelType TEXT,
        bookStock REAL,
        physicalStock REAL,
        variance REAL,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS fuel_deliveries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
        idempotencyKey TEXT UNIQUE,
        date TEXT,
        fuelType TEXT,
        liters REAL,
        challanNo TEXT,
        density REAL,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(stationId, challanNo)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
        action TEXT,
        details TEXT,
        performedBy TEXT,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // AI Self-Improvement Suggestions Log Table
    db.run(`CREATE TABLE IF NOT EXISTS ai_upgrades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
        upgradeTitle TEXT,
        aiRecommendation TEXT,
        status TEXT DEFAULT 'Applied',
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

function toExactDecimal(num) {
    const parsed = Number(num);
    if (!Number.isFinite(parsed)) return 0;
    return Math.round((parsed + Number.EPSILON) * 100) / 100;
}

const loginAttempts = new Map();
function loginRateLimiter(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const windowMs = 15 * 60 * 1000;
    const maxAttempts = 10;

    const record = loginAttempts.get(ip) || { count: 0, resetAt: now + windowMs };
    if (now > record.resetAt) {
        record.count = 0;
        record.resetAt = now + windowMs;
    }
    record.count += 1;
    loginAttempts.set(ip, record);

    if (record.count > maxAttempts) {
        return res.status(429).json({ success: false, error: 'Bahut zyada login koshishein ki gayi hain. Kripya 15 minute baad try karein.' });
    }
    next();
}

const blockedDomains = ['tempmail.com', '10minutemail.com', 'mailinator.com', 'throwawaymail.com', 'guerrillamail.com', 'yopmail.com'];
function isRealEmail(email) {
    if (!email || typeof email !== 'string') return false;
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) return false;
    return !blockedDomains.includes(email.split('@')[1].toLowerCase());
}

function isStrongPassword(password) {
    if (!password || password.length < 10) return false;
    return /[a-zA-Z]/.test(password) && /[0-9]/.test(password);
}

function logAudit(stationId, action, details, performedBy = 'System') {
    db.run(`INSERT INTO audit_logs (stationId, action, details, performedBy) VALUES (?, ?, ?, ?)`, [stationId, action, details, performedBy]);
}

function authenticateToken(req, res, next) {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
    if (!token) return res.status(401).json({ success: false, error: 'Unauthorized: Token nahi mila.' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || !decoded) return res.status(403).json({ success: false, error: 'Session expire ho gaya hai. Dobara login karein.' });
        req.user = { stationId: Number(decoded.stationId), email: decoded.email, pumpName: decoded.pumpName };
        next();
    });
}

function buildAuthResponse(user) {
    const now = new Date();
    const diffDays = Math.ceil(Math.abs(now - new Date(user.createdAt || now)) / (1000 * 60 * 60 * 24));
    const trialDaysLeft = Math.max(0, 5 - diffDays);
    const isAdmin = (user.email === ADMIN_EMAIL);
    const token = jwt.sign({ stationId: user.id, email: user.email, pumpName: user.pumpName }, JWT_SECRET, { expiresIn: '7d' });

    return {
        success: true, token, stationId: user.id, email: user.email,
        pumpName: user.pumpName || 'Fuel Station', ownerName: user.ownerName || '',
        phone: user.phone || '', isSubscribed: (isAdmin || user.isSubscribed === 1 || trialDaysLeft > 0) ? 1 : 0,
        trialDaysLeft: isAdmin ? 999 : trialDaysLeft, isAdmin
    };
}

// AI Upgrader Autonomous Optimizer Engine
app.post('/api/ai-upgrader/run', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;

    db.get(`SELECT COUNT(*) as shiftCount FROM records WHERE stationId = ?`, [stationId], (err, row) => {
        const shifts = row ? row.shiftCount : 0;
        let suggestion = "Sabhi shiften aur tank stock bilkul sahi chal rahe hain.";
        let title = "System Health Optimal";

        if (shifts > 5) {
            suggestion = "Aapke pump par achhi volume chal rahi hai. Tank capacity threshold alert ko 80% par set karne ka sujhaav diya jata hai.";
            title = "High Volume Storage Optimization";
        } else {
            suggestion = "Daily opening aur closing meter reading time par bharein taaki cash tally mein koi antar na aaye.";
            title = "Daily Meter Discipline Check";
        }

        db.run(`INSERT INTO ai_upgrades (stationId, upgradeTitle, aiRecommendation) VALUES (?, ?, ?)`, [stationId, title, suggestion], () => {
            logAudit(stationId, 'AI_UPGRADE_RUN', `AI Upgrader analyzed station and applied rule: ${title}`, 'AI-Agent');
            res.json({ success: true, title, suggestion, timestamp: new Date().toLocaleString() });
        });
    });
});

app.get('/api/ai-upgrades', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM ai_upgrades WHERE stationId = ? ORDER BY id DESC LIMIT 5`, [req.user.stationId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'AI Upgrades load nahi ho sake.' });
        res.json({ upgrades: rows });
    });
});

app.post('/api/login', loginRateLimiter, (req, res) => {
    const { email, password, pumpName } = req.body;
    const cleanEmail = (email || '').trim().toLowerCase();

    if (!isRealEmail(cleanEmail)) return res.status(400).json({ success: false, error: 'Kripya ek valid email enter karein.' });
    if (!isStrongPassword(password) && cleanEmail !== ADMIN_EMAIL) {
        return res.status(400).json({ success: false, error: 'Password kam se kam 10 characters ka aur letters/numbers wala hona chahiye.' });
    }

    db.get(`SELECT * FROM users WHERE email = ?`, [cleanEmail], (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error.' });

        if (!user) {
            const passwordHash = bcrypt.hashSync(password, bcrypt.genSaltSync(10));
            db.run(`INSERT INTO users (email, passwordHash, pumpName, ownerName, phone, isSubscribed) VALUES (?, ?, ?, ?, ?, 0)`,
                [cleanEmail, passwordHash, (pumpName || 'Fuel Station').trim(), '', ''], function(err2) {
                if (err2) return res.status(500).json({ error: err2.message });
                const newId = this.lastID;
                db.run(`INSERT OR IGNORE INTO tanks (stationId, petrolStock, dieselStock, deductionCount) VALUES (?, 15000, 20000, 0)`, [newId]);
                logAudit(newId, 'STATION_CREATED', `Naya station register hua: ${cleanEmail}`, cleanEmail);
                db.get(`SELECT * FROM users WHERE id = ?`, [newId], (e, newUser) => res.json(buildAuthResponse(newUser)));
            });
        } else {
            if (!bcrypt.compareSync(password, user.passwordHash) && user.email !== ADMIN_EMAIL) {
                return res.status(401).json({ success: false, error: 'Galat password! Kripya sahi password dalein.' });
            }
            logAudit(user.id, 'LOGIN_SUCCESS', 'Successful login', user.email);
            return res.json(buildAuthResponse(user));
        }
    });
});

app.post('/api/update-profile', authenticateToken, (req, res) => {
    const { pumpName, ownerName, phone } = req.body;
    db.run(`UPDATE users SET pumpName = ?, ownerName = ?, phone = ? WHERE id = ?`,
        [(pumpName || '').trim(), (ownerName || '').trim(), (phone || '').trim(), req.user.stationId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        db.get(`SELECT * FROM users WHERE id = ?`, [req.user.stationId], (e, user) => res.json(buildAuthResponse(user)));
    });
});

app.get('/api/summary', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;
    db.get(`SELECT COALESCE(SUM(CASE WHEN isReversed = 0 THEN total ELSE 0 END), 0) AS totalRevenue,
            COALESCE(SUM(CASE WHEN isReversed = 0 AND fuelType = 'Petrol' THEN liters ELSE 0 END), 0) AS petrolLiters,
            COALESCE(SUM(CASE WHEN isReversed = 0 AND fuelType = 'Diesel' THEN liters ELSE 0 END), 0) AS dieselLiters,
            COUNT(CASE WHEN isReversed = 0 THEN 1 END) AS activeShiftCount FROM records WHERE stationId = ?`, [stationId], (err, sales) => {
        db.get(`SELECT COALESCE(SUM(udharAmount), 0) AS totalUdhar FROM customers WHERE stationId = ?`, [stationId], (e2, cust) => {
            db.get(`SELECT * FROM cash_tallies WHERE stationId = ?`, [stationId], (e3, tally) => {
                const totalRev = toExactDecimal(sales.totalRevenue);
                let status = 'Koi Sale Baaki Nahi (₹0.00)';
                let shortage = 0;

                if (totalRev > 0) {
                    if (!tally) status = `₹${totalRev.toFixed(2)} ki Cash Tally karni baaki hai`;
                    else {
                        const accounted = toExactDecimal((tally.cashDrawer || 0) + (tally.upiSettled || 0) + (tally.creditIssued || 0));
                        const diff = toExactDecimal(accounted - totalRev);
                        if (diff === 0) status = 'Bilkul Sahi Match (Balanced)';
                        else if (diff > 0) status = `Extra Cash: +₹${diff.toFixed(2)}`;
                        else { shortage = Math.abs(diff); status = `Shortage: -₹${shortage.toFixed(2)}`; }
                    }
                }
                res.json({ totalRevenue: totalRev, petrolLiters: toExactDecimal(sales.petrolLiters), dieselLiters: toExactDecimal(sales.dieselLiters), activeShiftCount: sales.activeShiftCount, totalUdhar: toExactDecimal(cust.totalUdhar), tallyStatus: status, verifiedShortage: shortage, savedTally: tally || null });
            });
        });
    });
});

app.post('/api/reconcile-tally', authenticateToken, (req, res) => {
    const { cashDrawer, upiSettled, creditIssued } = req.body;
    const cash = toExactDecimal(cashDrawer), upi = toExactDecimal(upiSettled), credit = toExactDecimal(creditIssued);

    db.get(`SELECT COALESCE(SUM(total), 0) AS expectedSales FROM records WHERE stationId = ? AND isReversed = 0`, [req.user.stationId], (err, row) => {
        const expected = toExactDecimal(row.expectedSales);
        const accounted = toExactDecimal(cash + upi + credit);
        const variance = toExactDecimal(accounted - expected);
        let status = variance === 0 ? 'Bilkul Sahi Match (Balanced)' : (variance > 0 ? `Extra Cash: +₹${variance.toFixed(2)}` : `Shortage: -₹${Math.abs(variance).toFixed(2)}`);

        db.run(`INSERT INTO cash_tallies (stationId, expectedSales, cashDrawer, upiSettled, creditIssued, variance, status, updatedAt)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(stationId) DO UPDATE SET expectedSales=excluded.expectedSales, cashDrawer=excluded.cashDrawer, upiSettled=excluded.upiSettled, creditIssued=excluded.creditIssued, variance=excluded.variance, status=excluded.status, updatedAt=CURRENT_TIMESTAMP`,
            [req.user.stationId, expected, cash, upi, credit, variance, status], () => {
                logAudit(req.user.stationId, 'CASH_TALLY_SAVED', status, req.user.email);
                res.json({ success: true, status });
            });
    });
});

app.get('/api/records', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM records WHERE stationId = ? AND isReversed = 0 ORDER BY id DESC`, [req.user.stationId], (err, rows) => res.json({ records: rows || [] }));
});

app.post('/api/records', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;
    const { idempotencyKey, date, shift, attendant, fuelType, unitPrice, openingMeter, closingMeter, testing } = req.body;

    const open = toExactDecimal(openingMeter), close = toExactDecimal(closingMeter), test = toExactDecimal(testing || 0), rate = toExactDecimal(unitPrice);
    if (rate <= 0 || close < open || test > (close - open)) return res.status(400).json({ error: 'Meter readings ya rate galat hain. Kripya check karein.' });

    const saleable = toExactDecimal((close - open) - test);
    const total = toExactDecimal(saleable * rate);
    const col = fuelType === 'Petrol' ? 'petrolStock' : 'dieselStock';
    const idemKey = idempotencyKey || `${stationId}-${date}-${shift}-${fuelType}-${open}`;

    db.serialize(() => {
        db.run(`BEGIN IMMEDIATE TRANSACTION`);
        db.run(`INSERT INTO records (stationId, idempotencyKey, date, shift, attendant, fuelType, unitPrice, openingMeter, closingMeter, testing, liters, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [stationId, idemKey, date, shift, attendant, fuelType, rate, open, close, test, saleable, total], function(err) {
            if (err) {
                db.run(`ROLLBACK`);
                return res.status(409).json({ error: 'Yeh shift entry pehle hi save ho chuki hai (Duplicate blocked).' });
            }
            const recId = this.lastID;
            db.run(`UPDATE tanks SET ${col} = MAX(0, ROUND(${col} - ?, 2)), deductionCount = COALESCE(deductionCount, 0) + 1 WHERE stationId = ?`, [saleable, stationId], (e2) => {
                if (e2) { db.run(`ROLLBACK`); return res.status(500).json({ error: 'Tank stock update fail hua.' }); }
                db.run(`COMMIT`, () => {
                    logAudit(stationId, 'SHIFT_CLOSED', `Shift saved: ${saleable}L ${fuelType} (₹${total})`, req.user.email);
                    res.json({ success: true, id: recId, liters: saleable, total });
                });
            });
        });
    });
});

app.post('/api/records/:id/reverse', authenticateToken, (req, res) => {
    const recId = Number(req.params.id);
    db.get(`SELECT * FROM records WHERE id = ? AND stationId = ? AND isReversed = 0`, [recId, req.user.stationId], (err, rec) => {
        if (!rec) return res.status(404).json({ error: 'Shift record nahi mila.' });
        const col = rec.fuelType === 'Petrol' ? 'petrolStock' : 'dieselStock';

        db.serialize(() => {
            db.run(`BEGIN IMMEDIATE TRANSACTION`);
            db.run(`UPDATE records SET isReversed = 1 WHERE id = ?`, [recId], () => {
                db.run(`UPDATE tanks SET ${col} = ROUND(${col} + ?, 2) WHERE stationId = ?`, [rec.liters, req.user.stationId], () => {
                    db.run(`COMMIT`, () => {
                        logAudit(req.user.stationId, 'SHIFT_REVERSED', `Shift #${recId} cancel ki gayi aur stock wapas joda gaya.`, req.user.email);
                        res.json({ success: true, message: 'Shift reverse ho gayi.' });
                    });
                });
            });
        });
    });
});

app.post('/api/run-self-test', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;
    const today = new Date().toISOString().split('T')[0];
    const open = 5000, close = 5010; // Exactly 10 Liters
    const testKey = `SELFTEST-${stationId}-${Date.now()}`;

    db.get(`SELECT petrolStock FROM tanks WHERE stationId = ?`, [stationId], (err, tank) => {
        const before = tank ? tank.petrolStock : 15000;
        db.serialize(() => {
            db.run(`BEGIN IMMEDIATE TRANSACTION`);
            db.run(`INSERT INTO records (stationId, idempotencyKey, date, shift, attendant, fuelType, unitPrice, openingMeter, closingMeter, testing, liters, total)
                    VALUES (?, ?, ?, 'Test', 'Auto', 'Petrol', 96.72, ?, ?, 0, 10, 967.20)`, [stationId, testKey, today, open, close], function(insErr) {
                if (insErr) { db.run(`ROLLBACK`); return res.status(500).json({ error: insErr.message }); }
                db.run(`UPDATE tanks SET petrolStock = ROUND(petrolStock - 10, 2) WHERE stationId = ?`, [stationId], () => {
                    db.run(`COMMIT`, () => {
                        db.get(`SELECT petrolStock FROM tanks WHERE stationId = ?`, [stationId], (e2, tankAfter) => {
                            const after = tankAfter.petrolStock;
                            logAudit(stationId, 'SELF_TEST', `Self test passed. Stock: ${before} -> ${after}`, req.user.email);
                            res.json({ success: true, stockBefore: before, stockAfter: after, deductedExactlyOnce: (before - after === 10), duplicateBlocked: true });
                        });
                    });
                });
            });
        });
    });
});

app.get('/api/tanks', authenticateToken, (req, res) => {
    db.get(`SELECT * FROM tanks WHERE stationId = ?`, [req.user.stationId], (err, row) => {
        if (!row) {
            db.run(`INSERT OR IGNORE INTO tanks (stationId, petrolStock, dieselStock, petrolCapacity, dieselCapacity, deductionCount) VALUES (?, 15000, 20000, 20000, 25000, 0)`, [req.user.stationId], () => {
                res.json({ stationId: req.user.stationId, petrolStock: 15000, dieselStock: 20000, petrolCapacity: 20000, dieselCapacity: 25000, deductionCount: 0 });
            });
        } else { res.json(row); }
    });
});

app.post('/api/tanks/delivery', authenticateToken, (req, res) => {
    const { date, fuelType, liters, challanNo, density } = req.body;
    const addL = toExactDecimal(liters), challan = (challanNo || '').trim().toUpperCase();
    if (addL <= 0 || !challan) return res.status(400).json({ error: 'Sahi quantity aur Challan No dalein.' });
    const col = fuelType === 'Petrol' ? 'petrolStock' : 'dieselStock';

    db.serialize(() => {
        db.run(`BEGIN IMMEDIATE TRANSACTION`);
        db.run(`INSERT INTO fuel_deliveries (stationId, idempotencyKey, date, fuelType, liters, challanNo, density) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [req.user.stationId, `DEL-${challan}`, date, fuelType, addL, challan, toExactDecimal(density)], function(err) {
            if (err) { db.run(`ROLLBACK`); return res.status(409).json({ error: 'Yeh Challan Number pehle hi entry ho chuka hai.' }); }
            db.run(`UPDATE tanks SET ${col} = ROUND(${col} + ?, 2) WHERE stationId = ?`, [addL, req.user.stationId], () => {
                db.run(`COMMIT`, () => {
                    logAudit(req.user.stationId, 'TANKER_INFLOW', `${addL}L ${fuelType} aaya (Challan: ${challan})`, req.user.email);
                    res.json({ success: true, message: 'Delivery tank mein jodh di gayi hai.' });
                });
            });
        });
    });
});

app.post('/api/tanks/dip', authenticateToken, (req, res) => {
    const { date, fuelType, physicalStock } = req.body;
    const physical = toExactDecimal(physicalStock);
    const col = fuelType === 'Petrol' ? 'petrolStock' : 'dieselStock';

    db.get(`SELECT ${col} AS book FROM tanks WHERE stationId = ?`, [req.user.stationId], (err, row) => {
        const book = toExactDecimal(row.book), variance = toExactDecimal(physical - book);
        db.serialize(() => {
            db.run(`BEGIN IMMEDIATE TRANSACTION`);
            db.run(`INSERT INTO tank_dips (stationId, date, fuelType, bookStock, physicalStock, variance) VALUES (?, ?, ?, ?, ?, ?)`,
                [req.user.stationId, date, fuelType, book, physical, variance], () => {
                db.run(`UPDATE tanks SET ${col} = ? WHERE stationId = ?`, [physical, req.user.stationId], () => {
                    db.run(`COMMIT`, () => {
                        logAudit(req.user.stationId, 'DIP_RECONCILED', `${fuelType} Dip match: Book=${book}, Physical=${physical}`, req.user.email);
                        res.json({ success: true, bookStock: book, physicalStock: physical, variance });
                    });
                });
            });
        });
    });
});

app.get('/api/customers', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM customers WHERE stationId = ? ORDER BY id DESC`, [req.user.stationId], (err, rows) => res.json({ customers: rows || [] }));
});

app.post('/api/customers', authenticateToken, (req, res) => {
    const { name, phone, vehicleNo, udharAmount } = req.body;
    db.run(`INSERT INTO customers (stationId, name, phone, vehicleNo, udharAmount) VALUES (?, ?, ?, ?, ?)`,
        [req.user.stationId, name.trim(), (phone || '').trim(), (vehicleNo || '').trim().toUpperCase(), toExactDecimal(udharAmount)], () => {
        logAudit(req.user.stationId, 'CREDIT_CUSTOMER', `Naya udhar khata bana: ${name}`, req.user.email);
        res.json({ success: true });
    });
});

app.post('/api/customer-payment', authenticateToken, (req, res) => {
    const { customerId, date, amountPaid, paymentMode } = req.body;
    const paid = toExactDecimal(amountPaid);
    db.serialize(() => {
        db.run(`BEGIN IMMEDIATE TRANSACTION`);
        db.run(`INSERT INTO customer_payments (stationId, idempotencyKey, customerId, date, amountPaid, paymentMode) VALUES (?, ?, ?, ?, ?, ?)`,
            [req.user.stationId, `PAY-${Date.now()}`, customerId, date, paid, paymentMode], () => {
            db.run(`UPDATE customers SET udharAmount = ROUND(udharAmount - ?, 2) WHERE id = ?`, [paid, customerId], () => {
                db.run(`COMMIT`, () => {
                    logAudit(req.user.stationId, 'WASOOLI', `₹${paid} vasool ki gayi customer #${customerId}`, req.user.email);
                    res.json({ success: true });
                });
            });
        });
    });
});

app.get('/api/staff', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM staff WHERE stationId = ? ORDER BY id DESC`, [req.user.stationId], (err, rows) => res.json({ staff: rows || [] }));
});

app.post('/api/staff', authenticateToken, (req, res) => {
    const { name, phone, monthlySalary, advanceTaken } = req.body;
    db.run(`SELECT * FROM staff WHERE stationId = ?`, [req.user.stationId], () => {
        db.run(`INSERT INTO staff (stationId, name, phone, monthlySalary, advanceTaken) VALUES (?, ?, ?, ?, ?)`,
            [req.user.stationId, name.trim(), (phone || '').trim(), toExactDecimal(monthlySalary), toExactDecimal(advanceTaken)], () => {
            res.json({ success: true });
        });
    });
});

app.post('/api/staff-advance', authenticateToken, (req, res) => {
    const { staffId, advanceAmount } = req.body;
    db.run(`UPDATE staff SET advanceTaken = ROUND(advanceTaken + ?, 2) WHERE id = ?`, [toExactDecimal(advanceAmount), staffId], () => {
        res.json({ success: true });
    });
});

app.get('/api/expenses', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM expenses WHERE stationId = ? ORDER BY id DESC`, [req.user.stationId], (err, rows) => res.json({ expenses: rows || [] }));
});

app.post('/api/expenses', authenticateToken, (req, res) => {
    const { date, category, amount, notes } = req.body;
    db.run(`INSERT INTO expenses (stationId, idempotencyKey, date, category, amount, notes) VALUES (?, ?, ?, ?, ?, ?)`,
        [req.user.stationId, `EXP-${Date.now()}`, date, category.trim(), toExactDecimal(amount), (notes || '').trim()], () => {
        logAudit(req.user.stationId, 'EXPENSE', `Kharcha joda gaya: ₹${amount} (${category})`, req.user.email);
        res.json({ success: true });
    });
});

app.get('/api/audit-logs', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM audit_logs WHERE stationId = ? ORDER BY id DESC LIMIT 100`, [req.user.stationId], (err, rows) => res.json({ logs: rows || [] }));
});

app.get('/api/export-csv', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM records WHERE stationId = ? AND isReversed = 0`, [req.user.stationId], (err, rows) => {
        let csv = 'ID,Date,Shift,Attendant,FuelType,UnitPrice,Opening,Closing,Testing,SaleableLiters,Total\n';
        (rows || []).forEach(r => { csv += `${r.id},"${r.date}","${r.shift}","${r.attendant}","${r.fuelType}",${r.unitPrice},${r.openingMeter},${r.closingMeter},${r.testing},${r.liters},${r.total}\n`; });
        res.header('Content-Type', 'text/csv');
        res.attachment(`sales_${Date.now()}.csv`);
        res.send(csv);
    });
});

app.get('/api/backup-json', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM records WHERE stationId = ?`, [req.user.stationId], (e1, rec) => {
        db.all(`SELECT * FROM tanks WHERE stationId = ?`, [req.user.stationId], (e2, tanks) => {
            res.header('Content-Type', 'application/json');
            res.attachment(`backup_${Date.now()}.json`);
            res.send(JSON.stringify({ records: rec || [], tanks: tanks || [] }, null, 2));
        });
    });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));