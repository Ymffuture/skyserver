import crypto from 'crypto';
import bcrypt from 'bcrypt';
import nodemailer from 'nodemailer';
import User from '../models/User.js';
import dotenv from 'dotenv';

dotenv.config();

// Function to generate a secure token hash
const generateResetToken = () => {
    const token = crypto.randomBytes(32).toString('hex'); // Generate token
    const hash = crypto.createHash('sha256').update(token).digest('hex'); // Hash token
    return { token, hash };
};

// Send password reset email
export const forgotPassword = async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(400).json({ message: 'Email not found, please register.' });

    // Generate and hash reset token
    const { token, hash } = generateResetToken();
    user.resetPasswordToken = hash; // Store the hashed token in the DB
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour expiration
    await user.save();

    // Secure Email Transport
    const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS, // ⚠️ Consider using OAuth2 for security
        },
    });

    const resetLink = `${process.env.VITE_FRONTEND_DOMAIN_URL_HTTPS}/reset-password/${token}`;

    await transporter.sendMail({
        to: email,
        subject: 'Password Reset',
        html: `<p>Click the link below to reset your password:</p>
               <a href="${resetLink}">${resetLink}</a>
               <p>This link is valid for 1 hour.</p>`,
    });

    res.json({ message: 'Password reset email sent' });
};
