const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'wealthwise_super_secret_key_change_in_production'; // Simple secret for local dev

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // Serve frontend files

// Database Setup
let db;
(async () => {
    db = await open({
        filename: path.join(__dirname, 'database.sqlite'),
        driver: sqlite3.Database
    });

    // Enable foreign keys
    await db.run('PRAGMA foreign_keys = ON');

    // Create Tables
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            income REAL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            date TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    `);
    console.log('Connected to SQLite database.');
})();

// Auth Middleware to protect routes
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: Bearer <token>

    if (token == null) return res.status(401).json({ error: 'Unauthorized: No token provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Forbidden: Invalid or expired token' });
        req.user = user;
        next();
    });
};

// --- AUTH API ---

// Sign Up
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

        const existingUser = await db.get('SELECT * FROM users WHERE email = ?', [email]);
        if (existingUser) return res.status(400).json({ error: 'User already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const name = req.body.name || email.split('@')[0];

        const result = await db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword]);
        
        // Generate JWT token
        const token = jwt.sign({ id: result.lastID, email }, JWT_SECRET, { expiresIn: '24h' });
        res.status(201).json({ 
            token, 
            user: { id: result.lastID, name, email, income: 0 } 
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});

// Log In
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

        const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) return res.status(400).json({ error: 'Invalid credentials' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid credentials' });

        // Generate JWT token
        const token = jwt.sign({ id: user.id, email }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ 
            token, 
            user: { id: user.id, name: user.name, email: user.email, income: user.income } 
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error', details: err.message });
    }
});

// --- USER API ---

// Get User Profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await db.get('SELECT id, name, email, income FROM users WHERE id = ?', [req.user.id]);
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ user });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Update Profile (Income)
app.post('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { income } = req.body;
        if (income === undefined || isNaN(income)) return res.status(400).json({ error: 'Valid income required' });

        await db.run('UPDATE users SET income = ? WHERE id = ?', [income, req.user.id]);
        res.json({ message: 'Profile updated successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// --- EXPENSES API ---

// Get all expenses
app.get('/api/expenses', authenticateToken, async (req, res) => {
    try {
        const expenses = await db.all('SELECT * FROM expenses WHERE user_id = ? ORDER BY date DESC, id DESC', [req.user.id]);
        res.json({ expenses });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Add new expense
app.post('/api/expenses', authenticateToken, async (req, res) => {
    try {
        const { amount, category, description, date } = req.body;
        if (!amount || !category || !date) return res.status(400).json({ error: 'Amount, category, and date are required' });

        const result = await db.run(
            'INSERT INTO expenses (user_id, amount, category, description, date) VALUES (?, ?, ?, ?, ?)',
            [req.user.id, amount, category, description, date]
        );
        
        const newExpense = await db.get('SELECT * FROM expenses WHERE id = ?', [result.lastID]);
        res.status(201).json({ expense: newExpense });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete expense
app.delete('/api/expenses/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await db.run('DELETE FROM expenses WHERE id = ? AND user_id = ?', [id, req.user.id]);
        if (result.changes === 0) return res.status(404).json({ error: 'Expense not found or unauthorized' });
        
        res.json({ message: 'Expense deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
