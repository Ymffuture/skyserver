import crypto from 'crypto';
import bcrypt from 'bcrypt';
import nodemailer from 'nodemailer';
import User from '../models/User.js';
import dotenv from 'dotenv';

dotenv.config();

const generateResetToken = () => {
    const token = crypto.randomBytes(32).toString('hex');
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    return { token, hash };
};

export const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) return res.status(400).json({ message: 'Email not found.' });

        const { token, hash } = generateResetToken();
        user.resetPasswordToken = hash;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        // Optional: verify transporter
        await transporter.verify();

        const resetLink = `${process.env.VITE_FRONTEND_DOMAIN_URL_HTTPS}/reset-password/${token}`;

        const mailOptions = {
            to: email,
            subject: 'Password Reset Request',
            html: `
                <h2>Password Reset</h2>
                <p>Click below to reset your password. This link is valid for 1 hour.</p>
                <a href="${resetLink}" target="_blank" style="padding: 10px 15px; background-color: #1E90FF; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a>
                <p>If you did not request this, you can ignore this email.</p>
            `,
        };

        await transporter.sendMail(mailOptions);

        res.json({ message: 'Password reset email sent successfully' });

    } catch (error) {
        console.error('Error in forgotPassword:', error);
        res.status(500).json({ message: 'Server error. Could not send email.' });
    }
};
