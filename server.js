const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// إعداد قاعدة البيانات
const db = new sqlite3.Database('./database/users.db');

// إنشاء جدول المستخدمين إذا لم يكن موجوداً
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )
`);

// إدراج مستخدم افتراضي (agent / 123456) إذا لم يكن موجوداً
const defaultUser = {
  username: 'agent',
  password: '123456'
};

db.get('SELECT * FROM users WHERE username = ?', [defaultUser.username], (err, row) => {
  if (!row) {
    bcrypt.hash(defaultUser.password, 10, (err, hash) => {
      if (!err) {
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', [defaultUser.username, hash]);
        console.log('✅ مستخدم افتراضي تم إنشاؤه: agent / 123456');
      }
    });
  }
});

// إعداد الـ session
app.use(session({
  secret: 'royal_army_secret_key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 } // ساعة واحدة
}));

// Middleware لتحليل JSON و form data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// تقديم الملفات الثابتة من مجلد public
app.use(express.static(path.join(__dirname, 'public')));

// التحقق من المصادقة (Middleware)
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    return next();
  }
  res.redirect('/');
}

// الصفحة الرئيسية (تسجيل الدخول)
app.get('/', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// لوحة التحكم (محمية)
app.get('/dashboard', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// نقطة نهاية لتسجيل الدخول (POST)
app.post('/login', (req, res) => {
  const { username, password, answer } = req.body;

  // التحقق من السؤال الأمني (2+5=7)
  if (parseInt(answer) !== 7) {
    return res.status(400).json({ success: false, message: 'إجابة السؤال الأمني غير صحيحة' });
  }

  // البحث عن المستخدم
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ success: false, message: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    }

    // مقارنة كلمة المرور المشفرة
    bcrypt.compare(password, user.password, (err, result) => {
      if (result) {
        req.session.userId = user.id;
        req.session.username = user.username;
        res.json({ success: true });
      } else {
        res.status(401).json({ success: false, message: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
      }
    });
  });
});

// تسجيل الخروج
app.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// API لجلب الإحصائيات (بيانات وهمية)
app.get('/api/stats', isAuthenticated, (req, res) => {
  const today = Math.floor(Math.random() * 50);
  const last7Days = Math.floor(Math.random() * 200);
  const last30Days = Math.floor(Math.random() * 800);

  // بيانات الرسم البياني لآخر 7 أيام (قيم وهمية)
  const chartData = {
    labels: ['16 Jun', '17 Jun', '18 Jun', '19 Jun', '20 Jun', '21 Jun', '22 Jun'],
    values: [1, 1, 1, 0, 0, 0, 0] // يمكن توليد عشوائي
  };

  res.json({
    today,
    last7Days,
    last30Days,
    chartData
  });
});

// بدء الخادم
app.listen(PORT, () => {
  console.log(`🚀 الخادم يعمل على http://localhost:${PORT}`);
});