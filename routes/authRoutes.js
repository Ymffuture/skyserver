import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";
import dotenv from "dotenv";
import { forgotPassword, resetPassword } from "../control/Controller.js"; // make sure both are implemented

dotenv.config();
const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET_KEY;

router.post("/user-home-page/sign-up", async (req, res) => {
  const { email, password } = req.body;

  const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
  if (!emailRegex.test(email)) {
    return res.status(403).json({ error: "Invalid email format" });
  }

  const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W)(?!.*\s).{8,20}$/;
  if (!passwordRegex.test(password)) {
    return res.status(403).json({ error: "Password must be 8-20 characters, contain uppercase, lowercase, number, and special character" });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: "Email is already in use" });

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({ email, password: hashedPassword });
    await user.save();

    res.status(201).json({ message: "Registered successfully" });
  } catch (error) {
    res.status(500).json({ error: "Registration error", details: error.message });
  }
});

router.post("/user-home-page/sign-in", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid email or password" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid email or password" });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "2h" });

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ error: "Login error", details: error.message });
  }
});
// route for subscribe 
router.post('/subscribe', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email is required' });

  try {
    const existing = await Subscriber.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Email already subscribed' });

    await Subscriber.create({ email });
    res.json({ message: 'Successfully subscribed!' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});
// Password recovery
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword); // <-- ADD THIS

export default router;
