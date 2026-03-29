// ==========================
// TrustDocs Backend Server
// ==========================

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;

// --------------------------
// Middleware
// --------------------------
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --------------------------
// MongoDB Connection
// --------------------------
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/trustdocs';

mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB:', MONGO_URI))
  .catch(err => {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  });

const db = mongoose.connection;

// --------------------------
// File Upload Setup
// --------------------------
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});

const upload = multer({ storage });

// --------------------------
// Test Routes
// --------------------------
app.get('/', (req, res) => {
  res.send('Hello from TrustDocs Backend! Server is running 😊');
});

app.get('/api/test', (req, res) => {
  res.json({ ok: true, msg: 'Backend alive' });
});

// --------------------------
// USER REGISTRATION
// --------------------------
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, role, institution } = req.body;

    if (!username || !email || !password || !role) {
      return res.status(400).json({ message: 'All fields required' });
    }

    const users = db.collection('users');

    const exists = await users.findOne({ $or: [{ username }, { email }] });
    if (exists) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await users.insertOne({
      username,
      email,
      password: hashedPassword,
      role,
      institution: institution || 'Not provided',
      createdAt: new Date()
    });

    res.status(201).json({ message: 'Registration successful' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// --------------------------
// LOGIN (Student / Issuer / Verifier)
// --------------------------
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await db.collection('users').findOne({ username });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: 'Invalid credentials' });

    res.json({
      message: 'Login successful',
      user: {
        username: user.username,
        role: user.role,
        institution: user.institution
      }
    });

  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// --------------------------
// UPLOAD DOCUMENT (STUDENT)
// --------------------------
app.post('/api/upload-document', upload.single('file'), async (req, res) => {
  try {
    const { username, fullName, email, institution, documentType } = req.body;
    const file = req.file;

    if (!username || !documentType || !file) {
      return res.status(400).json({ message: 'Missing fields' });
    }

    await db.collection('documents').insertOne({
      studentUsername: username,
      fullName,
      email,
      institution,
      documentType,
      documentName: file.originalname,
      status: 'pending',
      filePath: file.path,
      uploadedAt: new Date(),
      fileMetadata: {
        mimeType: file.mimetype,
        sizeBytes: file.size
      }
    });

    res.status(201).json({ message: 'Document uploaded successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Upload error' });
  }
});

// --------------------------
// GET STUDENT DOCUMENTS
// --------------------------
app.get('/api/student-documents', async (req, res) => {
  try {
    const { username } = req.query;

    const docs = await db.collection('documents')
      .find({ studentUsername: username })
      .toArray();

    res.json({ documents: docs });

  } catch (err) {
    res.status(500).json({ message: 'Error fetching documents' });
  }
});

// --------------------------
// ISSUER: GET PENDING DOCS
// --------------------------
app.get('/api/pending-documents', async (req, res) => {
  try {
    const { institution } = req.query;

    const docs = await db.collection('documents')
      .find({ institution, status: 'pending' })
      .toArray();

    res.json({ documents: docs });

  } catch (err) {
    res.status(500).json({ message: 'Error fetching pending docs' });
  }
});

// --------------------------
// ISSUER: UPDATE STATUS
// --------------------------
app.post('/api/update-document-status', async (req, res) => {
  try {
    const { documentId, status, issuerUsername } = req.body;

    await db.collection('documents').updateOne(
      { _id: new mongoose.Types.ObjectId(documentId) },
      {
        $set: {
          status,
          verifiedBy: issuerUsername,
          verifiedAt: new Date()
        }
      }
    );

    res.json({ message: 'Status updated' });

  } catch (err) {
    res.status(500).json({ message: 'Update failed' });
  }
});

// --------------------------
// GET SINGLE DOCUMENT (VIEW)
// --------------------------
app.get('/api/get-document', async (req, res) => {
  try {
    const { documentId } = req.query;

    const doc = await db.collection('documents').findOne({
      _id: new mongoose.Types.ObjectId(documentId)
    });

    if (!doc) return res.status(404).json({ message: 'Not found' });

    const fileData = fs.readFileSync(doc.filePath).toString('base64');

    res.json({
      document: {
        ...doc,
        fileData
      }
    });

  } catch (err) {
    res.status(500).json({ message: 'Error loading document' });
  }
});

// --------------------------
// START SERVER
// --------------------------
app.listen(PORT, () => {
  console.log(`🚀 TrustDocs backend running on http://localhost:${PORT}`);
});
