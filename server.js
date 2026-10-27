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

// Database Schema including Staff and Advance Salary tables
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
        pumpName TEXT,
        isSubscribed INTEGER,
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

// API: Login with Admin Bypass & 5-Day Trial Calculation
app.post('/api/login', (req, res) => {
    const { email, pumpName } = req.body;
    const adminEmail = "omtiwari9192@gmail.com"; 

    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        
        const now = new Date();

        if (!user) {
            db.run(`INSERT INTO users (email, pumpName, isSubscribed) VALUES (?, ?, 0)`, 
                [email, pumpName], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ 
                    success: true, 
                    email, 
                    pumpName, 
                    isSubscribed: 0, 
                    trialDaysLeft: 5,
                    isAdmin: (email === adminEmail)
                });
            });
        } else {
            const createdDate = new Date(user.createdAt || now);
            const diffTime = Math.abs(now - createdDate);
            const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
            const trialDaysLeft = Math.max(0, 5 - diffDays);
            
            const isAdmin = (email === adminEmail);
            const activeStatus = (isAdmin || user.isSubscribed === 1 || trialDaysLeft > 0) ? 1 : 0;

            res.json({ 
                success: true, 
                email: user.email, 
                pumpName: user.pumpName, 
                isSubscribed: activeStatus,
                trialDaysLeft: isAdmin ? 999 : trialDaysLeft,
                isAdmin
            });
        }
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

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});