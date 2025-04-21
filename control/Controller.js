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
    <div style="font-family: 'Roboto', 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; background-color: #f0f8ff; padding: 20px;">
      <table width="100%" style="max-width: 600px; margin: auto; background: #fff; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); overflow: hidden;">
        <tr>
          <td style="background-color: #1E90FF; padding: 20px; text-align: center;">
            <img src="https://quorvexinstitute.vercel.app/img/Logo.jpg" alt="Quorvex Logo" style="height: 50px; margin-bottom: 10px;" />
            <h2 style="margin: 0; color: white;">Password Reset Request</h2>
          </td>
        </tr>
        <tr>
          <td style="padding: 30px; color: #333;">
            <p style="font-size: 16px;">Hi there,</p>
            <p style="font-size: 16px;">We received a request to reset your password. Click the button below to proceed. This link will expire in <strong>5 minutes</strong>.</p>
            <div style="text-align: center; margin: 30px 0;">
              <a href="${resetLink}" target="_blank"
                 style="padding: 12px 30px; background-color: #1E90FF; color: white; font-weight: bold; border-radius: 6px; text-decoration: none;">
                Reset My Password
              </a>
            </div>
            <p style="font-size: 14px;">If the button doesn't work, copy and paste this link into your browser:</p>
            <p style="font-size: 13px; word-break: break-word;"><a href="${resetLink}" target="_blank" style="color: #1E90FF;">${resetLink}</a></p>
            <hr style="margin: 30px 0;" />
            <p style="font-size: 12px; color: #888;">If you didn’t request this, please ignore this email or contact support.</p>
            <p style="font-size: 12px; color: #888;">Thanks,<br/>The Quorvex Team</p>
          </td>
        </tr>
        <tr>
          <td style="background-color: #f4f4f4; padding: 20px; text-align: center; font-size: 12px; color: #666;">
            <p style="margin: 0 0 10px;">Follow us on</p>
            <div style="margin-bottom: 10px;">
              <a href="https://linkedin.com" style="margin: 0 8px;"><img src="https://cdn-icons-png.flaticon.com/24/174/174857.png" alt="LinkedIn" /></a>
              <a href="https://facebook.com" style="margin: 0 8px;"><img src="https://cdn-icons-png.flaticon.com/24/145/145802.png" alt="Facebook" /></a>
              <a href="https://twitter.com" style="margin: 0 8px;"><img src="https://cdn-icons-png.flaticon.com/24/733/733579.png" alt="Twitter" /></a>
              <a href="https://instagram.com" style="margin: 0 8px;"><img src="https://cdn-icons-png.flaticon.com/24/2111/2111463.png" alt="Instagram" /></a>
            </div>
            <p style="margin: 0;">&copy; ${new Date().getFullYear()} Quorvex. All rights reserved.</p>
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
