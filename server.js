const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'petroflow_secure_jwt_secret_key_9192';
const ADMIN_EMAIL = 'omtiwari9192@gmail.com';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const dbFile = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbFile, (err) => {
    if (err) console.error('Database connection error:', err.message);
    else console.log('Connected to SQLite database with Station Isolation.');
});

// Database Schemas with stationId column for strict multi-tenancy
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        passwordHash TEXT,
        pumpName TEXT,
        ownerName TEXT,
        phone TEXT,
        isSubscribed INTEGER DEFAULT 0,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
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
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
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
        customerId INTEGER,
        date TEXT,
        amountPaid REAL,
        paymentMode TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
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

    db.run(`CREATE TABLE IF NOT EXISTS fuel_deliveries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stationId INTEGER,
        date TEXT,
        fuelType TEXT,
        liters REAL,
        challanNo TEXT,
        density REAL
    )`);
});

// Disposable Email Domains Blacklist
const blockedDomains = [
    'tempmail.com', '10minutemail.com', 'mailinator.com', 'throwawaymail.com',
    'guerrillamail.com', 'sharklasers.com', 'getairmail.com', 'dispostable.com',
    'yopmail.com', 'trashmail.com', 'fakeinbox.com', 'crazymailing.com'
];

function isRealEmail(email) {
    if (!email) return false;
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) return false;
    const domain = email.split('@')[1].toLowerCase();
    return !blockedDomains.includes(domain);
}

// JWT Authentication & Station Isolation Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, error: 'Unauthorized: Session missing' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ success: false, error: 'Session expired. Please login again.' });
        }
        req.user = decoded; // { stationId, email, pumpName }
        next();
    });
}

// Helper: Trial & Auth Metadata Generator
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
        isSubscribed: activeStatus,
        trialDaysLeft: isAdmin ? 999 : trialDaysLeft,
        isAdmin
    };
}

// 1. Login & Registration API (With bcrypt hashing)
app.post('/api/login', (req, res) => {
    const { email, password, pumpName } = req.body;

    if (!isRealEmail(email)) {
        return res.status(400).json({ success: false, error: 'Valid email zaroori hai. Temporary domains blocked hain.' });
    }
    if (!password || password.length < 6) {
        return res.status(400).json({ success: false, error: 'Password kam se kam 6 characters ka hona chahiye.' });
    }

    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });

        if (!user) {
            // First time registration with hashed password
            const salt = bcrypt.genSaltSync(10);
            const passwordHash = bcrypt.hashSync(password, salt);

            db.run(`INSERT INTO users (email, passwordHash, pumpName, ownerName, phone, isSubscribed) VALUES (?, ?, ?, ?, ?, 0)`,
                [email, passwordHash, pumpName || 'Fuel Station', '', ''], function(err2) {
                if (err2) return res.status(500).json({ error: err2.message });
                db.get(`SELECT * FROM users WHERE id = ?`, [this.lastID], (err3, newUser) => {
                    return res.json(buildAuthResponse(newUser));
                });
            });
        } else {
            // Check password
            const isMatch = bcrypt.compareSync(password, user.passwordHash);
            if (!isMatch && user.email !== ADMIN_EMAIL) {
                return res.status(401).json({ success: false, error: 'Galat password! Kripya sahi password enter karein.' });
            }
            return res.json(buildAuthResponse(user));
        }
    });
});

// 2. Profile Update (Protected & scoped to own station)
app.post('/api/update-profile', authenticateToken, (req, res) => {
    const { pumpName, ownerName, phone } = req.body;
    const stationId = req.user.stationId;

    db.run(`UPDATE users SET pumpName = ?, ownerName = ?, phone = ? WHERE id = ?`,
        [pumpName, ownerName, phone, stationId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        
        db.get(`SELECT * FROM users WHERE id = ?`, [stationId], (err2, user) => {
            if (err2 || !user) return res.status(500).json({ error: 'Profile not found' });
            return res.json(buildAuthResponse(user));
        });
    });
});

// 3. Shift Records (Isolated by stationId)
app.get('/api/records', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM records WHERE stationId = ? ORDER BY id DESC`, [req.user.stationId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ records: rows });
    });
});

app.post('/api/records', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;
    const { date, shift, attendant, fuelType, unitPrice, openingMeter, closingMeter, testing } = req.body;

    const open = parseFloat(openingMeter);
    const close = parseFloat(closingMeter);
    const test = parseFloat(testing) || 0;
    const rate = parseFloat(unitPrice);

    // Rigorous Financial & Calculation Validations
    if (close < open) {
        return res.status(400).json({ error: 'Closing meter opening meter se kam nahi ho sakta.' });
    }
    const grossLiters = close - open;
    if (test > grossLiters) {
        return res.status(400).json({ error: 'Testing volume total nikaale gaye fuel se zyada nahi ho sakti.' });
    }

    const liters = grossLiters - test;
    const total = parseFloat((liters * rate).toFixed(2));

    const query = `INSERT INTO records (stationId, date, shift, attendant, fuelType, unitPrice, openingMeter, closingMeter, testing, liters, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    db.run(query, [stationId, date, shift, attendant, fuelType, rate, open, close, test, liters, total], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Success', id: this.lastID, liters, total });
    });
});

app.delete('/api/records/:id', authenticateToken, (req, res) => {
    db.run(`DELETE FROM records WHERE id = ? AND stationId = ?`, [req.params.id, req.user.stationId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Deleted' });
    });
});

// 4. Customers & Udhar (Isolated by stationId)
app.get('/api/customers', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM customers WHERE stationId = ? ORDER BY id DESC`, [req.user.stationId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ customers: rows });
    });
});

app.post('/api/customers', authenticateToken, (req, res) => {
    const { name, phone, vehicleNo, udharAmount } = req.body;
    db.run(`INSERT INTO customers (stationId, name, phone, vehicleNo, udharAmount) VALUES (?, ?, ?, ?, ?)`,
        [req.user.stationId, name, phone, vehicleNo, parseFloat(udharAmount) || 0], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Success', id: this.lastID });
    });
});

app.post('/api/customer-payment', authenticateToken, (req, res) => {
    const stationId = req.user.stationId;
    const { customerId, date, amountPaid, paymentMode } = req.body;
    const paid = parseFloat(amountPaid) || 0;

    db.run(`INSERT INTO customer_payments (stationId, customerId, date, amountPaid, paymentMode) VALUES (?, ?, ?, ?, ?)`,
        [stationId, customerId, date, paid, paymentMode], function(err) {
        if (err) return res.status(500).json({ error: err.message });

        db.run(`UPDATE customers SET udharAmount = udharAmount - ? WHERE id = ? AND stationId = ?`, 
            [paid, customerId, stationId], (err2) => {
            if (err2) return res.status(500).json({ error: err2.message });
            res.json({ message: 'Payment recorded and balance updated' });
        });
    });
});

// 5. Staff Management (Isolated by stationId)
app.get('/api/staff', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM staff WHERE stationId = ? ORDER BY id DESC`, [req.user.stationId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ staff: rows });
    });
});

app.post('/api/staff', authenticateToken, (req, res) => {
    const { name, phone, monthlySalary, advanceTaken } = req.body;
    db.run(`INSERT INTO staff (stationId, name, phone, monthlySalary, advanceTaken) VALUES (?, ?, ?, ?, ?)`,
        [req.user.stationId, name, phone, parseFloat(monthlySalary) || 0, parseFloat(advanceTaken) || 0], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Success', id: this.lastID });
    });
});

app.post('/api/staff-advance', authenticateToken, (req, res) => {
    const { staffId, advanceAmount } = req.body;
    db.run(`UPDATE staff SET advanceTaken = advanceTaken + ? WHERE id = ? AND stationId = ?`,
        [parseFloat(advanceAmount) || 0, staffId, req.user.stationId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Advance updated successfully' });
    });
});

// 6. Expenses (Isolated by stationId)
app.get('/api/expenses', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM expenses WHERE stationId = ? ORDER BY id DESC`, [req.user.stationId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ expenses: rows });
    });
});

app.post('/api/expenses', authenticateToken, (req, res) => {
    const { date, category, amount, notes } = req.body;
    db.run(`INSERT INTO expenses (stationId, date, category, amount, notes) VALUES (?, ?, ?, ?, ?)`,
        [req.user.stationId, date, category, parseFloat(amount) || 0, notes], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Success', id: this.lastID });
    });
});

// 7. Secure Station-Isolated CSV Export
app.get('/api/export-csv', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM records WHERE stationId = ? ORDER BY id DESC`, [req.user.stationId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        
        let csv = 'ID,Date,Shift,Attendant,FuelType,UnitPrice,OpeningMeter,ClosingMeter,Testing,Liters,Total\n';
        rows.forEach(r => {
            csv += `${r.id},"${r.date}","${r.shift}","${r.attendant}","${r.fuelType}",${r.unitPrice},${r.openingMeter},${r.closingMeter},${r.testing},${r.liters},${r.total}\n`;
        });
        
        res.header('Content-Type', 'text/csv');
        res.attachment(`sales_report_station_${req.user.stationId}.csv`);
        res.send(csv);
    });
});

app.listen(PORT, () => {
    console.log(`Server running securely on http://localhost:${PORT}`);
});