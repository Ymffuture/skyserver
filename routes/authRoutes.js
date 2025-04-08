import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";
import dotenv from "dotenv";
import { forgotPassword } from "../control/Controller.js";

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
    res.status(500).json({ error: "Registration error", details: error.message });
  }
});

// 🔹 Login User
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

    // Generate JWT Token
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "2h" });

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ error: "Login error", details: error.message });
  }
});

// 🔹 Password Recovery Routes
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token");

export default router;
