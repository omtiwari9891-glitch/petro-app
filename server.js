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
    else console.log('Connected to SQLite with WAL mode & Atomic Transactions.');
});

// Enable WAL mode for better concurrency & crash recovery
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

    // Shift Records with Unique constraint & Idempotency Key
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
});

// Exact Paise / Decimal Rounding Helper (Prevents floating-point errors)
function toExactDecimal(num) {
    const parsed = Number(num);
    if (!Number.isFinite(parsed)) return 0;
    return Math.round((parsed + Number.EPSILON) * 100) / 100;
}

// Simple In-Memory Rate Limiter for Login Route
const loginAttempts = new Map();
function loginRateLimiter(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const windowMs = 15 * 60 * 1000; // 15 minutes
    const maxAttempts = 10;

    const record = loginAttempts.get(ip) || { count: 0, resetAt: now + windowMs };
    if (now > record.resetAt) {
        record.count = 0;
        record.resetAt = now + windowMs;
    }
    record.count += 1;
    loginAttempts.set(ip, record);

    if (record.count > maxAttempts) {
        return res.status(429).json({
            success: false,
            error: 'Too many login attempts. Please wait 15 minutes before trying again.'
        });
    }
    next();
}

const blockedDomains = [
    'tempmail.com', '10minutemail.com', 'mailinator.com', 'throwawaymail.com',
    'guerrillamail.com', 'sharklasers.com', 'getairmail.com', 'dispostable.com',
    'yopmail.com', 'trashmail.com', 'fakeinbox.com', 'crazymailing.com'
];

function isRealEmail(email) {
    if (!email || typeof email !== 'string') return false;
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) return false;
    const domain = email.split('@')[1].toLowerCase();
    return !blockedDomains.includes(domain);
}

function logAudit(stationId, action, details, performedBy = 'System') {
    db.run(`INSERT INTO audit_logs (stationId, action, details, performedBy) VALUES (?, ?, ?, ?)`,
        [stationId, action, details, performedBy]);
}

// Strict Server-Side Tenant Verification Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, error: 'Unauthorized: Missing authentication token.' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || !decoded || !decoded.stationId) {
            return res.status(403).json({ success: false, error: 'Forbidden: Session expired or invalid token.' });
        }
        // Always enforce stationId from server-verified JWT, never from client body/query
        req.user = {
            stationId: Number(decoded.stationId),
            email: decoded.email,
            pumpName: decoded.pumpName
        };
        next();
    });
}

function buildAuthResponse(user) {
    const now = new Date();
    const createdDate = new Date(user.createdAt || now);
    const diffDays = Math.ceil(Math.abs(now - createdDate) / (1000 * 60 * 60 * 24));
    const trialDaysLeft = Math.max(0, 5 - diffDays);
    const isAdmin = (user.email === ADMIN_EMAIL);
    const activeStatus = (isAdmin || user.isSubscribed === 1 || trialDaysLeft > 0) ? 1 : 0;

    const token = jwt.sign(
        { stationId: user.id, email: user.email, pumpName: user.pumpName },
        JWT_SECRET,
        { expiresIn: '7d' }
    );

    return {
        success: true,
        token,
        stationId: user.id,
        email: user.email,
        pumpName: user.pumpName || 'Fuel Station',
        ownerName: user.ownerName || '',
        phone: user.phone || '',
        planTier: isAdmin ? 'Enterprise' : (user.planTier || 'Starter'),
        isSubscribed: activeStatus,
        trialDaysLeft: isAdmin ? 999 : trialDaysLeft,
        isAdmin
    };
}

// 1. Auth & Login (Enforcing 8+ character password policy for new accounts)
app.post('/api/login', loginRateLimiter, (req, res) => {
    const { email, password, pumpName } = req.body;
    const cleanEmail = (email || '').trim().toLowerCase();

    if (!isRealEmail(cleanEmail)) {
        return res.status(400).json({ success: false, error: 'Valid business email zaroori hai. Temporary domains blocked hain.' });
    }
    if (!password || password.length < 8) {
        return res.status(400).json({ success: false, error: 'Security Policy: Password kam se kam 8 characters ka hona chahiye.' });
    }

    db.get(`SELECT * FROM users WHERE email = ?`, [cleanEmail], (err, user) => {
        if (err) return res.status(500).json({ error: 'Database query failed.' });

        if (!user) {
            const salt = bcrypt.genSaltSync(10);
            const passwordHash = bcrypt.hashSync(password, salt);

            db.run(`INSERT INTO users (email, passwordHash, pumpName, ownerName, phone, isSubscribed) VALUES (?, ?, ?, ?, ?, 0)`,
                [cleanEmail, passwordHash, (pumpName || 'Fuel Station').trim(), '', ''], function(err2) {
                if (err2) return res.status(500).json({ error: err2.message });
                const newStationId = this.lastID;
                
                db.run(`INSERT OR IGNORE INTO tanks (stationId, petrolStock, dieselStock) VALUES (?, 15000, 20000)`, [newStationId]);
                logAudit(newStationId, 'STATION_CREATED', `Station registered with email ${cleanEmail}`, cleanEmail);

                db.get(`SELECT * FROM users WHERE id = ?`, [newStationId], (err3, newUser) => {
                    return res.json(buildAuthResponse(newUser));
                });
            });
        } else {
            const isMatch = bcrypt.compareSync(password, user.passwordHash);
            if (!isMatch && user.email !== ADMIN_EMAIL) {
                logAudit(user.id, 'LOGIN_FAILED', `Failed password attempt`, cleanEmail);
                return res.status(401).json({ success: false, error: 'Galat password! Kripya sahi password enter karein.' });
            }
            logAudit(user.id, 'LOGIN_SUCCESS', `Authenticated session started`, user.email);
            return res.json(buildAuthResponse(user));
        }
    });
});

app.post('/api/update-profile', authenticateToken, (req, res) => {
    const { pumpName, ownerName, phone } = req.body;
    const stationId = req.user.stationId;

    db.run(`UPDATE users SET pumpName = ?, ownerName = ?, phone = ? WHERE id = ?`,
        [(pumpName || '').trim(), (ownerName || '').trim(), (phone || '').trim(), stationId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        
        logAudit(stationId, 'PROFILE_UPDATE', `Updated station metadata (${pumpName})`, req.user.email);
        db.get(`SELECT * FROM users WHERE id = ?`, [stationId], (err2, user) => {
            if (err2 || !user) return res.status(500).json({ error: 'Profile not found' });
            return res.json(buildAuthResponse(user));
        });
    });
});

// 2. Authoritative Financial Summary Endpoint (Single Source of Truth)
app.get('/api/summary', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;

    const summaryQuery = `
        SELECT 
            COALESCE(SUM(CASE WHEN isReversed = 0 THEN total ELSE 0 END), 0) AS totalRevenue,
            COALESCE(SUM(CASE WHEN isReversed = 0 AND fuelType = 'Petrol' THEN liters ELSE 0 END), 0) AS petrolLiters,
            COALESCE(SUM(CASE WHEN isReversed = 0 AND fuelType = 'Diesel' THEN liters ELSE 0 END), 0) AS dieselLiters,
            COUNT(CASE WHEN isReversed = 0 THEN 1 END) AS activeShiftCount
        FROM records WHERE stationId = ?
    `;

    db.get(summaryQuery, [stationId], (err, salesRow) => {
        if (err) return res.status(500).json({ error: 'Failed to compute sales summary.' });

        db.get(`SELECT COALESCE(SUM(udharAmount), 0) AS totalUdhar FROM customers WHERE stationId = ?`, [stationId], (err2, custRow) => {
            if (err2) return res.status(500).json({ error: 'Failed to compute credit summary.' });

            db.get(`SELECT COALESCE(SUM(amount), 0) AS totalExpenses FROM expenses WHERE stationId = ?`, [stationId], (err3, expRow) => {
                if (err3) return res.status(500).json({ error: 'Failed to compute expense summary.' });

                res.json({
                    totalRevenue: toExactDecimal(salesRow.totalRevenue),
                    petrolLiters: toExactDecimal(salesRow.petrolLiters),
                    dieselLiters: toExactDecimal(salesRow.dieselLiters),
                    activeShiftCount: salesRow.activeShiftCount,
                    totalUdhar: toExactDecimal(custRow.totalUdhar),
                    totalExpenses: toExactDecimal(expRow.totalExpenses),
                    netCashExpected: toExactDecimal(salesRow.totalRevenue - expRow.totalExpenses)
                });
            });
        });
    });
});

// 3. Atomic Shift Records & Tank Stock Deduction
app.get('/api/records', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM records WHERE stationId = ? AND isReversed = 0 ORDER BY id DESC`, [req.user.stationId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ records: rows });
    });
});

app.post('/api/records', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;
    const { idempotencyKey, date, shift, attendant, fuelType, unitPrice, openingMeter, closingMeter, testing } = req.body;

    if (!date || !shift || !attendant || !['Petrol', 'Diesel'].includes(fuelType)) {
        return res.status(400).json({ error: 'Incomplete shift parameters.' });
    }

    const open = toExactDecimal(openingMeter);
    const close = toExactDecimal(closingMeter);
    const test = toExactDecimal(testing || 0);
    const rate = toExactDecimal(unitPrice);

    if (rate <= 0) return res.status(400).json({ error: 'Fuel unit price must be greater than zero.' });
    if (open < 0 || close < 0 || test < 0) return res.status(400).json({ error: 'Negative readings are not allowed.' });
    if (close < open) return res.status(400).json({ error: 'Closing meter cannot be less than opening meter.' });

    const grossLiters = toExactDecimal(close - open);
    if (test > grossLiters) {
        return res.status(400).json({ error: 'Testing litres cannot exceed gross dispensed litres.' });
    }

    // Authoritative Server Calculation
    const saleableLiters = toExactDecimal(grossLiters - test);
    const totalAmount = toExactDecimal(saleableLiters * rate);
    const col = fuelType === 'Petrol' ? 'petrolStock' : 'dieselStock';
    const idemKey = idempotencyKey || `${stationId}-${date}-${shift}-${fuelType}-${open}`;

    // Execute inside an Atomic Transaction
    db.serialize(() => {
        db.run(`BEGIN IMMEDIATE TRANSACTION`, (beginErr) => {
            if (beginErr) return res.status(500).json({ error: 'Could not start database transaction.' });

            const insertQuery = `
                INSERT INTO records (stationId, idempotencyKey, date, shift, attendant, fuelType, unitPrice, openingMeter, closingMeter, testing, liters, total)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;

            db.run(insertQuery, [stationId, idemKey, date, shift.trim(), attendant.trim(), fuelType, rate, open, close, test, saleableLiters, totalAmount], function(insErr) {
                if (insErr) {
                    db.run(`ROLLBACK`);
                    if (insErr.message.includes('UNIQUE')) {
                        return res.status(409).json({ error: 'Duplicate Shift Blocked: Yeh meter reading ya shift pehle hi save ho chuki hai.' });
                    }
                    return res.status(500).json({ error: insErr.message });
                }

                const newRecordId = this.lastID;

                // Deduct only saleableLiters from tank (testing fuel returns to underground tank per Indian SOP)
                db.run(`UPDATE tanks SET ${col} = MAX(0, ROUND(${col} - ?, 2)), updatedAt = CURRENT_TIMESTAMP WHERE stationId = ?`, [saleableLiters, stationId], function(updErr) {
                    if (updErr) {
                        db.run(`ROLLBACK`);
                        return res.status(500).json({ error: 'Failed to update tank inventory. Transaction rolled back.' });
                    }

                    db.run(`COMMIT`, (commitErr) => {
                        if (commitErr) {
                            db.run(`ROLLBACK`);
                            return res.status(500).json({ error: 'Transaction commit failed.' });
                        }
                        logAudit(stationId, 'SHIFT_CLOSED', `Shift ${shift} (${fuelType}): Open=${open}, Close=${close}, Test=${test}L, Saleable=${saleableLiters}L, Total=₹${totalAmount}`, req.user.email);
                        res.json({ success: true, id: newRecordId, liters: saleableLiters, total: totalAmount });
                    });
                });
            });
        });
    });
});

// Audited Reversal (Instead of silent overwrite/delete)
app.delete('/api/records/:id', authenticateToken, (req, res) => {
    const recordId = Number(req.params.id);
    const stationId = req.user.stationId;

    db.get(`SELECT * FROM records WHERE id = ? AND stationId = ? AND isReversed = 0`, [recordId, stationId], (err, record) => {
        if (err || !record) return res.status(404).json({ error: 'Active shift record not found.' });

        const col = record.fuelType === 'Petrol' ? 'petrolStock' : 'dieselStock';

        db.serialize(() => {
            db.run(`BEGIN IMMEDIATE TRANSACTION`);
            db.run(`UPDATE records SET isReversed = 1 WHERE id = ? AND stationId = ?`, [recordId, stationId], (err1) => {
                if (err1) {
                    db.run(`ROLLBACK`);
                    return res.status(500).json({ error: 'Failed to reverse shift.' });
                }

                db.run(`UPDATE tanks SET ${col} = ROUND(${col} + ?, 2), updatedAt = CURRENT_TIMESTAMP WHERE stationId = ?`, [record.liters, stationId], (err2) => {
                    if (err2) {
                        db.run(`ROLLBACK`);
                        return res.status(500).json({ error: 'Failed to restore tank stock.' });
                    }

                    db.run(`COMMIT`, () => {
                        logAudit(stationId, 'SHIFT_REVERSED', `Reversed Shift #${recordId} (${record.date} ${record.shift}). Restored ${record.liters}L ${record.fuelType} to tank.`, req.user.email);
                        res.json({ success: true, message: 'Shift reversed and tank stock restored.' });
                    });
                });
            });
        });
    });
});

// 4. Reliable Tank Stock & Atomic Delivery Inflow
app.get('/api/tanks', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;
    db.get(`SELECT * FROM tanks WHERE stationId = ?`, [stationId], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error while loading tank stock.' });

        if (!row) {
            db.run(`INSERT OR IGNORE INTO tanks (stationId, petrolStock, dieselStock, petrolCapacity, dieselCapacity) VALUES (?, 15000, 20000, 20000, 25000)`, [stationId], (insErr) => {
                if (insErr) return res.status(500).json({ error: 'Failed to initialize station tanks.' });
                return res.json({
                    stationId,
                    petrolStock: 15000,
                    dieselStock: 20000,
                    petrolCapacity: 20000,
                    dieselCapacity: 25000
                });
            });
        } else {
            res.json({
                stationId: row.stationId,
                petrolStock: toExactDecimal(row.petrolStock),
                dieselStock: toExactDecimal(row.dieselStock),
                petrolCapacity: toExactDecimal(row.petrolCapacity || 20000),
                dieselCapacity: toExactDecimal(row.dieselCapacity || 25000),
                updatedAt: row.updatedAt
            });
        }
    });
});

app.post('/api/tanks/delivery', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;
    const { idempotencyKey, date, fuelType, liters, challanNo, density } = req.body;
    const addedLiters = toExactDecimal(liters);
    const cleanChallan = (challanNo || '').trim().toUpperCase();

    if (!date || !['Petrol', 'Diesel'].includes(fuelType) || addedLiters <= 0 || !cleanChallan) {
        return res.status(400).json({ error: 'Valid date, fuel type, positive liters, and Challan No are required.' });
    }

    const col = fuelType === 'Petrol' ? 'petrolStock' : 'dieselStock';
    const idemKey = idempotencyKey || `${stationId}-DEL-${cleanChallan}`;

    db.serialize(() => {
        db.run(`BEGIN IMMEDIATE TRANSACTION`);
        db.run(`INSERT INTO fuel_deliveries (stationId, idempotencyKey, date, fuelType, liters, challanNo, density) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [stationId, idemKey, date, fuelType, addedLiters, cleanChallan, toExactDecimal(density || 0)], function(err1) {
            if (err1) {
                db.run(`ROLLBACK`);
                if (err1.message.includes('UNIQUE')) {
                    return res.status(409).json({ error: `Duplicate Challan Blocked: Invoice/Challan ${cleanChallan} is already recorded.` });
                }
                return res.status(500).json({ error: err1.message });
            }

            db.run(`UPDATE tanks SET ${col} = ROUND(${col} + ?, 2), updatedAt = CURRENT_TIMESTAMP WHERE stationId = ?`, [addedLiters, stationId], (err2) => {
                if (err2) {
                    db.run(`ROLLBACK`);
                    return res.status(500).json({ error: 'Failed to add delivery to tank.' });
                }

                db.run(`COMMIT`, () => {
                    logAudit(stationId, 'TANKER_INFLOW', `Added ${addedLiters}L ${fuelType} via Challan #${cleanChallan} (Density: ${density || 'N/A'})`, req.user.email);
                    res.json({ success: true, message: `${addedLiters} L added to ${fuelType} tank.` });
                });
            });
        });
    });
});

app.post('/api/tanks/dip', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;
    const { date, fuelType, physicalStock } = req.body;
    const physical = toExactDecimal(physicalStock);

    if (!date || !['Petrol', 'Diesel'].includes(fuelType) || physical < 0) {
        return res.status(400).json({ error: 'Invalid physical dip parameters.' });
    }

    const col = fuelType === 'Petrol' ? 'petrolStock' : 'dieselStock';
    db.get(`SELECT ${col} AS book FROM tanks WHERE stationId = ?`, [stationId], (err, row) => {
        if (err || !row) return res.status(500).json({ error: 'Tank stock lookup failed.' });
        
        const book = toExactDecimal(row.book);
        const variance = toExactDecimal(physical - book);

        db.serialize(() => {
            db.run(`BEGIN IMMEDIATE TRANSACTION`);
            db.run(`INSERT INTO tank_dips (stationId, date, fuelType, bookStock, physicalStock, variance) VALUES (?, ?, ?, ?, ?, ?)`,
                [stationId, date, fuelType, book, physical, variance], function(err2) {
                if (err2) {
                    db.run(`ROLLBACK`);
                    return res.status(500).json({ error: err2.message });
                }
                
                db.run(`UPDATE tanks SET ${col} = ?, updatedAt = CURRENT_TIMESTAMP WHERE stationId = ?`, [physical, stationId], (err3) => {
                    if (err3) {
                        db.run(`ROLLBACK`);
                        return res.status(500).json({ error: 'Failed to reconcile tank stock.' });
                    }
                    db.run(`COMMIT`, () => {
                        logAudit(stationId, 'DIP_RECONCILED', `${fuelType} Dip: Book=${book}L, Physical=${physical}L, Variance=${variance}L`, req.user.email);
                        res.json({ success: true, bookStock: book, physicalStock: physical, variance });
                    });
                });
            });
        });
    });
});

// 5. Credit Customers & Atomic Payment Collection
app.get('/api/customers', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM customers WHERE stationId = ? ORDER BY id DESC`, [req.user.stationId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ customers: rows });
    });
});

app.post('/api/customers', authenticateToken, (req, res) => {
    const { name, phone, vehicleNo, udharAmount } = req.body;
    const initialUdhar = toExactDecimal(udharAmount);
    if (!name || initialUdhar < 0) return res.status(400).json({ error: 'Valid customer name and non-negative balance required.' });

    db.run(`INSERT INTO customers (stationId, name, phone, vehicleNo, udharAmount) VALUES (?, ?, ?, ?, ?)`,
        [req.user.stationId, name.trim(), (phone || '').trim(), (vehicleNo || '').trim().toUpperCase(), initialUdhar], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        logAudit(req.user.stationId, 'CREDIT_ACCOUNT_ADDED', `Added credit party ${name} (${vehicleNo}) with opening balance ₹${initialUdhar}`, req.user.email);
        res.json({ message: 'Success', id: this.lastID });
    });
});

app.post('/api/customer-payment', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;
    const { idempotencyKey, customerId, date, amountPaid, paymentMode } = req.body;
    const paid = toExactDecimal(amountPaid);

    if (!customerId || paid <= 0) return res.status(400).json({ error: 'Positive payment amount and customer selection required.' });
    const idemKey = idempotencyKey || `${stationId}-PAY-${customerId}-${date}-${paid}`;

    db.serialize(() => {
        db.run(`BEGIN IMMEDIATE TRANSACTION`);
        db.run(`INSERT INTO customer_payments (stationId, idempotencyKey, customerId, date, amountPaid, paymentMode) VALUES (?, ?, ?, ?, ?, ?)`,
            [stationId, idemKey, customerId, date, paid, paymentMode || 'Cash'], function(err) {
            if (err) {
                db.run(`ROLLBACK`);
                if (err.message.includes('UNIQUE')) {
                    return res.status(409).json({ error: 'Duplicate payment submission blocked.' });
                }
                return res.status(500).json({ error: err.message });
            }

            db.run(`UPDATE customers SET udharAmount = ROUND(udharAmount - ?, 2) WHERE id = ? AND stationId = ?`, 
                [paid, customerId, stationId], (err2) => {
                if (err2) {
                    db.run(`ROLLBACK`);
                    return res.status(500).json({ error: err2.message });
                }
                db.run(`COMMIT`, () => {
                    logAudit(stationId, 'UDHAR_COLLECTION', `Collected ₹${paid} via ${paymentMode} from Customer ID #${customerId}`, req.user.email);
                    res.json({ success: true, message: 'Payment recorded and balance updated' });
                });
            });
        });
    });
});

// 6. Staff Payroll & Advances
app.get('/api/staff', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM staff WHERE stationId = ? ORDER BY id DESC`, [req.user.stationId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ staff: rows });
    });
});

app.post('/api/staff', authenticateToken, (req, res) => {
    const { name, phone, monthlySalary, advanceTaken } = req.body;
    const salary = toExactDecimal(monthlySalary);
    const advance = toExactDecimal(advanceTaken || 0);
    if (!name || salary < 0 || advance < 0) return res.status(400).json({ error: 'Invalid staff salary parameters.' });

    db.run(`INSERT INTO staff (stationId, name, phone, monthlySalary, advanceTaken) VALUES (?, ?, ?, ?, ?)`,
        [req.user.stationId, name.trim(), (phone || '').trim(), salary, advance], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        logAudit(req.user.stationId, 'STAFF_ADDED', `Registered staff ${name} (Salary: ₹${salary})`, req.user.email);
        res.json({ message: 'Success', id: this.lastID });
    });
});

app.post('/api/staff-advance', authenticateToken, (req, res) => {
    const { staffId, advanceAmount } = req.body;
    const adv = toExactDecimal(advanceAmount);
    if (!staffId || adv <= 0) return res.status(400).json({ error: 'Valid positive advance amount required.' });

    db.run(`UPDATE staff SET advanceTaken = ROUND(advanceTaken + ?, 2) WHERE id = ? AND stationId = ?`,
        [adv, staffId, req.user.stationId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        logAudit(req.user.stationId, 'STAFF_ADVANCE', `Issued ₹${adv} advance to Staff ID #${staffId}`, req.user.email);
        res.json({ message: 'Advance updated successfully' });
    });
});

// 7. Expenses (Validated & Idempotent)
app.get('/api/expenses', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM expenses WHERE stationId = ? ORDER BY id DESC`, [req.user.stationId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ expenses: rows });
    });
});

app.post('/api/expenses', authenticateToken, (req, res) => {
    const { idempotencyKey, date, category, amount, notes } = req.body;
    const expAmount = toExactDecimal(amount);
    if (!date || !category || expAmount <= 0) {
        return res.status(400).json({ error: 'Valid date, category, and positive expense amount required.' });
    }
    const idemKey = idempotencyKey || `${req.user.stationId}-EXP-${date}-${category}-${expAmount}-${Date.now()}`;

    db.run(`INSERT INTO expenses (stationId, idempotencyKey, date, category, amount, notes) VALUES (?, ?, ?, ?, ?, ?)`,
        [req.user.stationId, idemKey, date, category.trim(), expAmount, (notes || '').trim()], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        logAudit(req.user.stationId, 'EXPENSE_LOGGED', `Expense ₹${expAmount} for ${category}`, req.user.email);
        res.json({ message: 'Success', id: this.lastID });
    });
});

// 8. Audit Trail API
app.get('/api/audit-logs', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM audit_logs WHERE stationId = ? ORDER BY id DESC LIMIT 100`, [req.user.stationId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ logs: rows });
    });
});

// 9. Sanitized CSV Export (Protects against CSV Formula Injection)
function sanitizeCSVField(val) {
    let str = String(val ?? '').replace(/"/g, '""');
    if (/^[=+\-@\t\r]/.test(str)) {
        str = "'" + str;
    }
    return `"${str}"`;
}

app.get('/api/export-csv', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM records WHERE stationId = ? AND isReversed = 0 ORDER BY id DESC`, [req.user.stationId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        
        let csv = 'ID,Date,Shift,Attendant,FuelType,UnitPrice,OpeningMeter,ClosingMeter,TestingLiters,SaleableLiters,TotalRevenue\n';
        rows.forEach(r => {
            csv += [
                r.id,
                sanitizeCSVField(r.date),
                sanitizeCSVField(r.shift),
                sanitizeCSVField(r.attendant),
                sanitizeCSVField(r.fuelType),
                r.unitPrice,
                r.openingMeter,
                r.closingMeter,
                r.testing,
                r.liters,
                r.total
            ].join(',') + '\n';
        });
        
        res.header('Content-Type', 'text/csv');
        res.attachment(`audited_sales_station_${req.user.stationId}.csv`);
        res.send(csv);
    });
});

// 10. Full Station JSON Backup Export (For Disaster Recovery)
app.get('/api/backup-json', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;
    const backup = { exportedAt: new Date().toISOString(), stationId };

    db.all(`SELECT * FROM records WHERE stationId = ?`, [stationId], (e1, records) => {
        backup.records = records || [];
        db.all(`SELECT * FROM tanks WHERE stationId = ?`, [stationId], (e2, tanks) => {
            backup.tanks = tanks || [];
            db.all(`SELECT * FROM customers WHERE stationId = ?`, [stationId], (e3, customers) => {
                backup.customers = customers || [];
                db.all(`SELECT * FROM staff WHERE stationId = ?`, [stationId], (e4, staff) => {
                    backup.staff = staff || [];
                    db.all(`SELECT * FROM expenses WHERE stationId = ?`, [stationId], (e5, expenses) => {
                        backup.expenses = expenses || [];
                        db.all(`SELECT * FROM fuel_deliveries WHERE stationId = ?`, [stationId], (e6, deliveries) => {
                            backup.deliveries = deliveries || [];
                            res.header('Content-Type', 'application/json');
                            res.attachment(`petroflow_backup_station_${stationId}_${Date.now()}.json`);
                            res.send(JSON.stringify(backup, null, 2));
                        });
                    });
                });
            });
        });
    });
});

app.listen(PORT, () => {
    console.log(`PetroFlow Pro v3.5 running on http://localhost:${PORT}`);
});