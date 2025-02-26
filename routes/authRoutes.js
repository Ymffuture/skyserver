import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";
import dotenv from "dotenv";
import {forgotPassword , resetPassword} from '../control/Controller.js'
const router = express.Router();
dotenv.config();
const JWT_SECRET = process.env.SECRET_ACCESS_KEY;

// Register Route
router.post("/user-home-page/sign-up", async (req, res) => {
  const { email, password } = req.body;
  const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{6,16}$/; 
  const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; 

if (!emailRegex.test(email)) {
    return res.status(403).json({ error: `Invalid email Address` });
}


if (!passwordRegex.test(password)) {
    return res.status(403).json({ error: 'Password must contain ONE uppercase,lowercase,number,and special character, and minimum of 7 characters long.' });
}

if (!email.length) {
    return res.status(403).json({ error: 'Email must be at least 3 letters long' });
}

  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email is already in use" });
    }

    // Create new user
    const user = new User({ email, password });
    await user.save();

    res.status(201).json({ message: "Registered successfully" });
  } catch (error) {
    res.status(500).json({ error: ":::Can not register please check the internet connection", details: error.message });
  }
});

// Login Route
router.post("/user-home-page/sign-in", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    // Generate token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1h" });

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ error: "Our server is currently offline, please wait a moment while we fix the error", details: error.message });
  }
});
// recovery password Route..
router.post("/user-home-page/recover-password-getcode-page", async (req, res) => {
  const { email } = req.body;
  
  const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; 

  if (!emailRegex.test(email)) {
    return res.status(403).json({ error: `Invalid email::403 ` });
}
});

router.post('/forgot-password',forgotPassword);
router.post('/reset-password/:token',resetPassword);

export default router;

