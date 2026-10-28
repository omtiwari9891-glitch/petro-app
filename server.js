const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const dbFile = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbFile, (err) => {
    if (err) console.error('Database error: ', err.message);
    else console.log('Connected to SQLite database.');
});

// Database Schema
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT,
        shift TEXT,
        attendant TEXT,
        fuelType TEXT,
        unitPrice REAL,
        openingMeter REAL,
        closingMeter REAL,
        testing REAL,
        liters REAL,
        total REAL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT,
        pumpName TEXT,
        ownerName TEXT,
        phone TEXT,
        isSubscribed INTEGER DEFAULT 0,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        phone TEXT,
        vehicleNo TEXT,
        udharAmount REAL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS customer_payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customerId INTEGER,
        date TEXT,
        amountPaid REAL,
        paymentMode TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT,
        category TEXT,
        amount REAL,
        notes TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS staff (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        phone TEXT,
        monthlySalary REAL,
        advanceTaken REAL DEFAULT 0
    )`);
});

// Disposable Fake Email Domains Blacklist
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

const ADMIN_EMAIL = "omtiwari9192@gmail.com";

// Helper function to calculate trial days
function formatUserData(user) {
    const now = new Date();
    const createdDate = new Date(user.createdAt || now);
    const diffTime = Math.abs(now - createdDate);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    const trialDaysLeft = Math.max(0, 5 - diffDays);
    const isAdmin = (user.email === ADMIN_EMAIL);
    const activeStatus = (isAdmin || user.isSubscribed === 1 || trialDaysLeft > 0) ? 1 : 0;

    return {
        success: true,
        email: user.email,
        pumpName: user.pumpName || 'Fuel Station',
        ownerName: user.ownerName || '',
        phone: user.phone || '',
        isSubscribed: activeStatus,
        trialDaysLeft: isAdmin ? 999 : trialDaysLeft,
        isAdmin
    };
}

// 1. Login with Email & Password
app.post('/api/login', (req, res) => {
    const { email, password, pumpName } = req.body;

    if (!isRealEmail(email)) {
        return res.status(400).json({ success: false, error: "Valid email zaroori hai. Temporary emails allowed nahi hain." });
    }

    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });

        if (!user) {
            // First time auto-register
            db.run(`INSERT INTO users (email, password, pumpName, ownerName, phone, isSubscribed) VALUES (?, ?, ?, ?, ?, 0)`,
                [email, password || 'default123', pumpName || 'Royal Fuel Station', '', ''], function(err2) {
                if (err2) return res.status(500).json({ error: err2.message });
                db.get(`SELECT * FROM users WHERE id = ?`, [this.lastID], (err3, newUser) => {
                    return res.json(formatUserData(newUser));
                });
            });
        } else {
            // Password verification
            if (user.password && password && user.password !== password && user.email !== ADMIN_EMAIL) {
                return res.status(401).json({ success: false, error: "Galat password! Kripya sahi password enter karein." });
            }
            return res.json(formatUserData(user));
        }
    });
});

// 2. Google / Social One-Click Sign-In
app.post('/api/google-login', (req, res) => {
    const { email, name, pumpName } = req.body;

    if (!isRealEmail(email)) {
        return res.status(400).json({ success: false, error: "Invalid Google account email." });
    }

    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });

        if (!user) {
            db.run(`INSERT INTO users (email, password, pumpName, ownerName, isSubscribed) VALUES (?, ?, ?, ?, 0)`,
                [email, 'oauth_google', pumpName || (name + ' Station'), name || ''], function(err2) {
                if (err2) return res.status(500).json({ error: err2.message });
                db.get(`SELECT * FROM users WHERE id = ?`, [this.lastID], (err3, newUser) => {
                    return res.json(formatUserData(newUser));
                });
            });
        } else {
            return res.json(formatUserData(user));
        }
    });
});

// 3. Update User Profile (Email cannot be changed)
app.post('/api/update-profile', (req, res) => {
    const { email, pumpName, ownerName, phone } = req.body;

    db.run(`UPDATE users SET pumpName = ?, ownerName = ?, phone = ? WHERE email = ?`,
        [pumpName, ownerName, phone, email], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        
        db.get(`SELECT * FROM users WHERE email = ?`, [email], (err2, user) => {
            if (err2 || !user) return res.status(500).json({ error: "Failed to reload user profile" });
            return res.json(formatUserData(user));
        });
    });
});

// Shift Records APIs
app.get('/api/records', (req, res) => {
    db.all(`SELECT * FROM records ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ records: rows });
    });
});

app.post('/api/records', (req, res) => {
    const { date, shift, attendant, fuelType, unitPrice, openingMeter, closingMeter, testing, liters, total } = req.body;
    const query = `INSERT INTO records (date, shift, attendant, fuelType, unitPrice, openingMeter, closingMeter, testing, liters, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    db.run(query, [date, shift, attendant, fuelType, unitPrice, openingMeter, closingMeter, testing, liters, total], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Success', id: this.lastID });
    });
});

app.delete('/api/records/:id', (req, res) => {
    db.run(`DELETE FROM records WHERE id = ?`, req.params.id, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Deleted' });
    });
});

// Credit Customers APIs
app.get('/api/customers', (req, res) => {
    db.all(`SELECT * FROM customers ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ customers: rows });
    });
});

app.post('/api/customers', (req, res) => {
    const { name, phone, vehicleNo, udharAmount } = req.body;
    db.run(`INSERT INTO customers (name, phone, vehicleNo, udharAmount) VALUES (?, ?, ?, ?)`, 
        [name, phone, vehicleNo, udharAmount], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Success', id: this.lastID });
    });
});

app.post('/api/customer-payment', (req, res) => {
    const { customerId, date, amountPaid, paymentMode } = req.body;
    db.run(`INSERT INTO customer_payments (customerId, date, amountPaid, paymentMode) VALUES (?, ?, ?, ?)`,
        [customerId, date, amountPaid, paymentMode], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        db.run(`UPDATE customers SET udharAmount = udharAmount - ? WHERE id = ?`, [amountPaid, customerId], (err2) => {
            if (err2) return res.status(500).json({ error: err2.message });
            res.json({ message: 'Payment recorded and balance updated' });
        });
    });
});

// Expenses APIs
app.get('/api/expenses', (req, res) => {
    db.all(`SELECT * FROM expenses ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ expenses: rows });
    });
});

app.post('/api/expenses', (req, res) => {
    const { date, category, amount, notes } = req.body;
    db.run(`INSERT INTO expenses (date, category, amount, notes) VALUES (?, ?, ?, ?)`, 
        [date, category, amount, notes], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Success', id: this.lastID });
    });
});

// Staff Salary & Advance APIs
app.get('/api/staff', (req, res) => {
    db.all(`SELECT * FROM staff ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ staff: rows });
    });
});

app.post('/api/staff', (req, res) => {
    const { name, phone, monthlySalary, advanceTaken } = req.body;
    db.run(`INSERT INTO staff (name, phone, monthlySalary, advanceTaken) VALUES (?, ?, ?, ?)`, 
        [name, phone, monthlySalary, advanceTaken || 0], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Success', id: this.lastID });
    });
});

app.post('/api/staff-advance', (req, res) => {
    const { staffId, advanceAmount } = req.body;
    db.run(`UPDATE staff SET advanceTaken = advanceTaken + ? WHERE id = ?`, [advanceAmount, staffId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Advance updated successfully' });
    });
});

// CSV Export API
app.get('/api/export-csv', (req, res) => {
    db.all(`SELECT * FROM records ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        
        let csv = 'ID,Date,Shift,Attendant,FuelType,UnitPrice,OpeningMeter,ClosingMeter,Testing,Liters,Total\n';
        rows.forEach(r => {
            csv += `${r.id},${r.date},${r.shift},${r.attendant},${r.fuelType},${r.unitPrice},${r.openingMeter},${r.closingMeter},${r.testing},${r.liters},${r.total}\n`;
        });
        
        res.header('Content-Type', 'text/csv');
        res.attachment('petroflow_sales_report.csv');
        res.send(csv);
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});