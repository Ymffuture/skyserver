import express from "express";
import passport from "../config/passport.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import User from "../models/User.js";
import Subscriber from "../models/Subscriber.js";
import { forgotPassword, resetPassword } from "../control/Controller.js";

dotenv.config();
const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET_KEY;

// Google OAuth routes
router.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

router.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/user-home-page/sign-in" }),
  (req, res) => res.redirect("/")
);

// Sign-up
router.post("/user-home-page/sign-up", async (req, res) => {
  const { email, password, fname } = req.body;
  try {
    // validate email/password...
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: "Email in use" });
    const hash = await bcrypt.hash(password, 12);
    await User.create({ email, password: hash, fname });
    res.status(201).json({ message: "Registered successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Sign-in
router.post("/user-home-page/sign-in", async (req, res) => {
  const { email, password, fname} = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid creds" });
    const match = await user.comparePassword(password);
    if (!match) return res.status(400).json({ error: "Invalid creds" });
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "2h" });
    res.status(200).json({ message: "Login successful", token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Subscribe
router.post("/subscribe", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email required" });
  try {
    const exists = await Subscriber.findOne({ email });
    if (exists) return res.status(400).json({ message: "Already subscribed" });
    await Subscriber.create({ email });
    res.json({ message: "Successfully subscribed!" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Password recovery
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);

export default router;
