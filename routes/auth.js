const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const User = require('../models/User');
const router = express.Router();
require('dotenv').config();

// Setup for file uploads (like resumes)
const upload = multer({ dest: 'uploads/' });

// Register User
router.post('/register', upload.single('resume'), async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  try {
    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: 'User already registered. Please log in.' });
    }

    // Create a new user
    user = new User({
      firstName,
      lastName,
      email,
      password: await bcrypt.hash(password, 10), // Hash the password
      resume: req.file ? req.file.path : null, // Save resume path
    });

    await user.save();

    // Generate token for the new user
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    return res.status(201).json({ message: 'User registered successfully!', token });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Login User
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    // Generate token on successful login
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    return res.status(200).json({ token, user });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
