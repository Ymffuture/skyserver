// controllers/Controller.js
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import User from '../models/User.js';

dotenv.config();

// Helper: Capitalize first letter of name
const capitalize = (name) => {
  if (!name) return '';
  return name.charAt(0).toUpperCase() + name.slice(1).toLowerCase();
};

// Generate Reset Token
const generateResetToken = () => {
  const token = crypto.randomBytes(32).toString('hex');
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  return { token, hash };
};

// Configure transporter (Gmail SMTP)
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Optional: Verify transporter
transporter.verify()
  .then(() => console.log('✅ Email transporter ready'))
  .catch((error) => console.error('❌ Email transporter error:', error));

// Forgot Password Controller
export const forgotPassword = async (req, res) => {
  try {
    const { email, fname } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'Email is required.' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'No account with that email found.' });
    }

    const { token, hash } = generateResetToken();
    user.resetPasswordToken = hash;
    user.resetPasswordExpires = Date.now() + 5 * 60 * 1000; // 5 minutes
    await user.save();

    const resetLink = `${process.env.VITE_FRONTEND_DOMAIN_URL_HTTPS}/reset-password/${token}`;

    const mailOptions = {
      from: `"Quorvex Institute" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Reset Your Password - Action Required',
      html: `
        <div style="font-family: 'Roboto', 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; background-color: #f0f8ff; padding: 20px;">
          <table width="100%" style="max-width: 600px; margin: auto; background: #fff; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); overflow: hidden;">
            <tr>
              <td style="background-color: #f9f9f9; padding: 20px; text-align: center;">
                <img src="https://quorvexinstitute.vercel.app/img/intro-bg.jpg" alt="Quorvex Logo" style="height: 100px; margin-bottom: 10px;" />
                <h2 style="margin: 0; color: #3d2a00;">Password Reset Request</h2>
              </td>
            </tr>
            <tr>
              <td style="padding: 30px; color: #333;">
                <p style="font-size: 16px;">Hi, ${capitalize(fname) || 'there'},</p>
                <p style="font-size: 16px;">We received a request to reset your password. Click the button below. This link expires in <strong>5 minutes</strong>.</p>
                <div style="text-align: center; margin: 30px 0;">
                  <a href="${resetLink}" target="_blank" style="padding: 12px 30px; background-color: #1E90FF; color: white; font-weight: bold; border-radius: 50px; text-decoration: none;">
                    Reset My Password
                  </a>
                </div>
                <p style="font-size: 14px;">If the button doesn't work, copy this link into your browser:</p>
                <p style="font-size: 13px; word-break: break-word;"><a href="${resetLink}" target="_blank" style="color: #1E90FF;">${resetLink}</a></p>
                <hr style="margin: 30px 0;" />
                <p style="font-size: 12px; color: #888;">If you didn’t request this, ignore this email or contact support.</p>
                <p style="font-size: 12px; color: #888;">
                  Best regards,<br/>
                  <strong>Kgomotso Nkosi</strong><br/>
                  CEO of Quorvex Institute
                </p>
              </td>
            </tr>
            <tr>
              <td style="background-color: #f4f4f4; padding: 20px; text-align: center; font-size: 12px; color: #666;">
                <p style="margin: 0 0 10px;">Follow us on</p>
                <div style="margin-bottom: 10px;">
                  <a href="https://www.linkedin.com/in/kgomotsonkosi-l" style="margin: 0 8px;"><img src="https://cdn-icons-png.flaticon.com/24/174/174857.png" alt="LinkedIn" /></a>
                  <a href="https://www.facebook.com/QuorvexInstitute" style="margin: 0 8px;"><img src="https://cdn-icons-png.flaticon.com/24/145/145802.png" alt="Facebook" /></a>
                  <a href="https://x.com/futureFBG96" style="margin: 0 8px;"><img src="https://cdn-icons-png.flaticon.com/24/733/733579.png" alt="X" /></a>
                  <a href="https://instagram.com/ymffuture" style="margin: 0 8px;"><img src="https://cdn-icons-png.flaticon.com/24/2111/2111463.png" alt="Instagram" /></a>
                </div>
                <p style="margin: 0;">&copy; ${new Date().getFullYear()} Quorvex. All rights reserved.</p>
              </td>
            </tr>
          </table>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);
    console.log(`📧 Password reset email sent to ${email}`);

    res.json({ message: 'Password reset email sent successfully.' });

  } catch (error) {
    console.error('❌ Error in forgotPassword:', error);
    res.status(500).json({ message: 'Server error. Could not send email.' });
  }
};

// Reset Password Controller
export const resetPassword = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  if (!token || !password) {
    return res.status(400).json({ message: 'Token and new password are required.' });
  }

  try {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token.' });
    }

    // Strong password validation
    const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W)(?!.*\s).{6,16}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        message: 'Password must be 6-16 characters and include uppercase, lowercase, number, and special character.',
      });
    }

    const hashedPassword = await bcrypt.hash(password, 15);
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();

    res.status(200).json({ message: 'Password has been reset successfully.' });

  } catch (error) {
    console.error('❌ Error in resetPassword:', error);
    res.status(500).json({ message: 'Server error. Could not reset password.' });
  }
};

