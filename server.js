// server.js
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// ---- Persistence (users.json) ----
const DB_FILE = path.join(__dirname, 'users.json');
let users = [];
if (fs.existsSync(DB_FILE)) {
  try {
    users = JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
  } catch (e) {
    users = [];
  }
}
function saveUsers() {
  fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}

// ---- Helpers ----
function digitsOnly(s) { return (s || '').replace(/\D/g, ''); }

// from phone to 10-digit account number:
// - If 11 digits and starts with 0 (e.g. 08123456789) => drop the 0 -> 8123456789
// - Else take the last 10 digits
function accountNumberFromPhone(phone) {
  const d = digitsOnly(phone);
  if (d.length === 11 && d.startsWith('0')) return d.slice(1);
  return d.slice(-10);
}

function findUserById(id) { return users.find(u => u.id === id); }
function findUserByAccount(acc) { return users.find(u => u.accountNumber === acc); }

function isUnique({ username, email, phone, accountNumber }) {
  const u = users.find(u =>
    u.username.toLowerCase() === username.toLowerCase() ||
    u.email.toLowerCase() === email.toLowerCase() ||
    u.phone === phone ||
    u.accountNumber === accountNumber
  );
  return !u;
}

function nextId() {
  return users.length ? Math.max(...users.map(u => u.id)) + 1 : 1;
}

// ---- ROUTES ----

// Register
// body: { username, email, phone, password }
app.post('/register', (req, res) => {
  const { username, email, phone, password } = req.body || {};
  if (!username || !email || !phone || !password) {
    return res.status(400).json({ message: 'All fields are required: username, email, phone, password' });
  }

  const accountNumber = accountNumberFromPhone(phone);
  if (accountNumber.length !== 10) {
    return res.status(400).json({ message: 'Invalid phone number. Could not derive a 10-digit account number.' });
  }

  if (!isUnique({ username, email, phone, accountNumber })) {
    return res.status(400).json({ message: 'Username, email, phone or account number already in use' });
  }

  const user = {
    id: nextId(),
    username,
    email,
    phone: digitsOnly(phone),
    accountNumber,
    password,                // NOTE: plain text for demo only
    balance: 0,
    transactions: []         // {type, amount, timestamp, details}
  };

  users.push(user);
  saveUsers();

  // Return safe user (no password)
  const { password: _, ...safeUser } = user;
  res.json({ message: 'Registration successful', user: safeUser });
});

// Login
// body: { email, password }
app.post('/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }
  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase() && u.password === password);
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });

  const { password: _, ...safeUser } = user;
  res.json({ message: 'Login successful', user: safeUser });
});

// Add Money
// body: { userId, amount }
app.post('/update-balance', (req, res) => {
  const { userId, amount } = req.body || {};
  const amt = Number(amount);
  const user = findUserById(Number(userId));
  if (!user) return res.status(400).json({ message: 'User not found' });
  if (isNaN(amt) || amt <= 0) return res.status(400).json({ message: 'Amount must be a positive number' });

  user.balance += amt;
  user.transactions.push({
    type: 'add',
    amount: amt,
    timestamp: new Date().toISOString(),
    details: 'Wallet top-up'
  });
  saveUsers();
  res.json({ message: 'Money added successfully!', balance: user.balance });
});

// Send to another wallet by accountNumber
// body: { senderId, receiverAccountNumber, amount }
app.post('/send', (req, res) => {
  const { senderId, receiverAccountNumber, amount } = req.body || {};
  const amt = Number(amount);
  const sender = findUserById(Number(senderId));
  const receiver = findUserByAccount(String(receiverAccountNumber));

  if (!sender) return res.status(400).json({ message: 'Sender not found' });
  if (!receiver) return res.status(400).json({ message: 'Receiver not found' });
  if (sender.id === receiver.id) return res.status(400).json({ message: 'Cannot send to your own account' });
  if (isNaN(amt) || amt <= 0) return res.status(400).json({ message: 'Amount must be a positive number' });
  if (sender.balance < amt) return res.status(400).json({ message: 'Insufficient balance' });

  sender.balance -= amt;
  receiver.balance += amt;

  const now = new Date().toISOString();
  sender.transactions.push({
    type: 'send',
    amount: amt,
    timestamp: now,
    details: `Sent to ${receiver.username} (${receiver.accountNumber})`
  });
  receiver.transactions.push({
    type: 'receive',
    amount: amt,
    timestamp: now,
    details: `Received from ${sender.username} (${sender.accountNumber})`
  });

  saveUsers();
  // return sender's updated balance
  res.json({ message: `Sent ₦${amt} to ${receiver.username}!`, balance: sender.balance });
});

// Transfer to bank (deduct only)
// body: { userId, amount }
app.post('/transfer', (req, res) => {
  const { userId, amount } = req.body || {};
  const amt = Number(amount);
  const user = findUserById(Number(userId));
  if (!user) return res.status(400).json({ message: 'User not found' });
  if (isNaN(amt) || amt <= 0) return res.status(400).json({ message: 'Amount must be a positive number' });
  if (user.balance < amt) return res.status(400).json({ message: 'Insufficient balance' });

  user.balance -= amt;
  user.transactions.push({
    type: 'transfer',
    amount: amt,
    timestamp: new Date().toISOString(),
    details: 'Transfer to bank'
  });
  saveUsers();
  res.json({ message: `Transferred ₦${amt} to bank!`, balance: user.balance });
});

// Airtime (deduct only)
// body: { userId, amount }
app.post('/airtime', (req, res) => {
  const { userId, amount } = req.body || {};
  const amt = Number(amount);
  const user = findUserById(Number(userId));
  if (!user) return res.status(400).json({ message: 'User not found' });
  if (isNaN(amt) || amt <= 0) return res.status(400).json({ message: 'Amount must be a positive number' });
  if (user.balance < amt) return res.status(400).json({ message: 'Insufficient balance' });

  user.balance -= amt;
  user.transactions.push({
    type: 'airtime',
    amount: amt,
    timestamp: new Date().toISOString(),
    details: 'Airtime purchase'
  });
  saveUsers();
  res.json({ message: `Airtime ₦${amt} purchased!`, balance: user.balance });
});

// Resolve account name by 10-digit account number
app.get('/resolve-account/:accountNumber', (req, res) => {
  const acc = String(req.params.accountNumber || '').trim();
  if (acc.length !== 10) return res.status(400).json({ message: 'Account number must be 10 digits' });
  const user = findUserByAccount(acc);
  if (!user) return res.json({ exists: false, name: null });
  res.json({ exists: true, name: user.username });
});

// Get user profile by id (safe fields)
app.get('/user/:id', (req, res) => {
  const user = findUserById(Number(req.params.id));
  if (!user) return res.status(404).json({ message: 'User not found' });
  const { password, ...safeUser } = user;
  res.json(safeUser);
});

app.get('/', (_req, res) => res.send('PayMe API is running'));

app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));
