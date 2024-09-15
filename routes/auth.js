const express = require('express');
const multer = require('multer');
const { register, login } = require('../controllers/authController');
const router = express.Router();

// Setup file upload (for resume)
const upload = multer({ dest: 'uploads/' });

// User registration route with file upload for the resume
router.post('/register', upload.single('resume'), register);

// User login route
router.post('/login', login);

module.exports = router;
