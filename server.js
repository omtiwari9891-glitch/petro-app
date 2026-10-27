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

// Database Tables for Petrobyte-like features
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
        liters REAL,
        total REAL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        pumpName TEXT,
        isSubscribed INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        phone TEXT,
        vehicleNo TEXT,
        udharAmount REAL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT,
        category TEXT,
        amount REAL,
        notes TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS tanks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fuelType TEXT,
        capacity REAL,
        currentStock REAL
    )`);
});

// API: Login with Admin Bypass
app.post('/api/login', (req, res) => {
    const { email, pumpName } = req.body;
    const adminEmail = "omtiwari9192@gmail.com"; 
    const isSubscribed = (email === adminEmail) ? 1 : 0;

    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        
        if (!user) {
            db.run(`INSERT INTO users (email, pumpName, isSubscribed) VALUES (?, ?, ?)`, 
                [email, pumpName, isSubscribed], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ success: true, email, pumpName, isSubscribed });
            });
        } else {
            const activeStatus = (email === adminEmail) ? 1 : user.isSubscribed;
            res.json({ success: true, email: user.email, pumpName: user.pumpName, isSubscribed: activeStatus });
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
    const { date, shift, attendant, fuelType, unitPrice, openingMeter, closingMeter, liters, total } = req.body;
    const query = `INSERT INTO records (date, shift, attendant, fuelType, unitPrice, openingMeter, closingMeter, liters, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    db.run(query, [date, shift, attendant, fuelType, unitPrice, openingMeter, closingMeter, liters, total], function(err) {
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

// Credit/Udhar Customers APIs
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

// Daily Expenses APIs
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

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});