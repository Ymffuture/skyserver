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
        user.resetPasswordExpires = Date.now() + 300000; // 5 minutes in milliseconds
 // 1 hour expiry
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
  subject: 'Reset Your Password - Action Required',
  html: `
    <div style="font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; background-color: #f0f8ff; padding: 20px;">
      <table width="100%" style="max-width: 600px; margin: auto; background: #fff; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.05); overflow: hidden;">
        <tr>
          <td style="background-color: #1E90FF; padding: 20px; text-align: center; color: white;">
            <h2 style="margin: 0;">Password Reset Request</h2>
          </td>
        </tr>
        <tr>
          <td style="padding: 30px; color: #333;">
            <p style="font-size: 16px;">Hi there,</p>
            <p style="font-size: 16px;">We received a request to reset your password. Click the button below to proceed. This link will expire in <strong>5 min</strong>.</p>
            <div style="text-align: center; margin: 30px 0;">
              <a href="${resetLink}" target="_blank"
                 style="padding: 12px 25px; background-color: #1E90FF; color: white; font-weight: bold; border-radius: 6px; text-decoration: none; display: inline-block;">
                Reset My Password
              </a>
            </div>
            <p style="font-size: 14px;">If the button doesn't work, copy and paste the following link into your browser:</p>
            <p style="font-size: 13px; word-break: break-all;"><a href="${resetLink}" target="_blank" style="color: #1E90FF;">${resetLink}</a></p>
            <hr style="margin: 30px 0;" />
            <p style="font-size: 12px; color: #888;">If you didn't request this, please ignore this message or contact support.</p>
            <p style="font-size: 12px; color: #888;">Thank you,<br/>The Quorvex Team</p>
          </td>
        </tr>
        <tr>
          <td style="background-color: #f4f4f4; text-align: center; padding: 15px; font-size: 12px; color: #666;">
            &copy; ${new Date().getFullYear()} Quorvex. All rights reserved.
          </td>
        </tr>
      </table>
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

        const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W)(?!.*\s).{6,16}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({
                message: 'Password must be 6-16 characters, include uppercase, lowercase, number, and special character',
            });
        }

        const hashedPassword = await bcrypt.hash(password, 15);
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
