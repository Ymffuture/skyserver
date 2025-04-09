import crypto from 'crypto';
import bcrypt from 'bcrypt';
import nodemailer from 'nodemailer';
import User from '../models/User.js';
import dotenv from 'dotenv';

dotenv.config();

// Generate Reset Token
const generateResetToken = () => {
    const token = crypto.randomBytes(32).toString('hex');
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    return { token, hash };
};

// Forgot Password Controller
export const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Email not found.' });

        const { token, hash } = generateResetToken();
        user.resetPasswordToken = hash;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour expiry
        await user.save();

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        await transporter.verify(); // Optional: validate SMTP

        const resetLink = `${process.env.VITE_FRONTEND_DOMAIN_URL_HTTPS}/reset-password/${token}`;

        const mailOptions = {
            to: email,
            subject: 'Password Reset Request',
            html: `
                <div style="font-family: Arial, sans-serif;">
                    <h2>Password Reset</h2>
                    <p>Click the button below to reset your password. This link is valid for <strong>1 hour</strong>.</p>
                    <a href="${resetLink}" target="_blank" 
                       style="padding: 10px 20px; background-color: #1E90FF; color: white; text-decoration: none; border-radius: 5px;">
                        Reset Password
                    </a>
                    <p style="margin-top: 20px;">If you did not request this, you can safely ignore this email.</p>
                </div>
            `,
        };

        await transporter.sendMail(mailOptions);

        res.json({ message: 'Password reset email sent successfully' });
    } catch (error) {
        console.error('Error in forgotPassword:', error);
        res.status(500).json({ message: 'Server error. Could not send email.' });
    }
};

// Reset Password Controller
export const resetPassword = async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    try {
        const user = await User.findOne({
            resetPasswordToken: hashedToken,
            resetPasswordExpires: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired token' });
        }

        const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W)(?!.*\s).{8,20}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({
                message: 'Password must be 8-20 characters, include uppercase, lowercase, number, and special character',
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        await user.save();

        res.status(200).json({ message: 'Password has been reset successfully' });
    } catch (error) {
        console.error('Error in resetPassword:', error);
        res.status(500).json({ message: 'Server error. Could not reset password.' });
    }
};
