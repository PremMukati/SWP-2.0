// Backend: Express.js with MongoDB for Password-Based Authentication & Role-Based Access
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/school_erp', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const UserSchema = new mongoose.Schema({
    mobile: { type: String, unique: true },
    password: String,
    role: String // 'admin', 'teacher', 'student'
});
const User = mongoose.model('User', UserSchema);

// Middleware for Role-Based Access
const authenticate = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'Access Denied' });
    try {
        const verified = jwt.verify(token.split(' ')[1], 'secretKey');
        req.user = verified;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid Token' });
    }
};

const authorize = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Permission Denied' });
        }
        next();
    };
};

// Register User (Only Admin Can Register Users)
app.post('/register', authenticate, authorize(['admin']), async (req, res) => {
    const { mobile, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const user = new User({ mobile, password: hashedPassword, role });
        await user.save();
        res.json({ success: true, message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Error registering user' });
    }
});

// Login Route
app.post('/login', async (req, res) => {
    const { mobile, password } = req.body;
    const user = await User.findOne({ mobile });
    if (!user) return res.status(400).json({ error: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign({ mobile: user.mobile, role: user.role }, 'secretKey', { expiresIn: '1h' });
    res.json({ success: true, token, role: user.role });
});

// Role-Specific Routes
app.get('/admin', authenticate, authorize(['admin']), (req, res) => {
    res.json({ message: 'Welcome Admin! You have full access.' });
});

app.get('/teacher', authenticate, authorize(['teacher', 'admin']), (req, res) => {
    res.json({ message: 'Welcome Teacher! You can manage students and classes.' });
});

app.get('/student', authenticate, authorize(['student', 'teacher', 'admin']), (req, res) => {
    res.json({ message: 'Welcome Student! You can view your schedule and grades.' });
});

// Start Server
app.listen(5000, () => console.log('Server running on port 5000'));

document.getElementById('login').addEventListener('click', async () => {
    const mobile = document.getElementById('mobile').value;
    const password = document.getElementById('password').value;
    try {
        const response = await fetch('http://localhost:5000/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mobile, password })
        });
        const data = await response.json();
        if (data.success) {
            alert('Login Successful! Role: ' + data.role);
            localStorage.setItem('token', data.token);
        } else {
            alert('Invalid credentials');
        }
    } catch (error) {
        alert('Error logging in');
    }
});;

console.log("HTML File:", htmlContent);
console.log("CSS File:", cssContent);
console.log("JavaScript File:", jsContent);
