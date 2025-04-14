import bcrypt from "bcrypt";
import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: function () {
        return !this.googleId; // Email required only if Google ID is not present
      },
      unique: true,
      lowercase: true, // Store all emails in lowercase
      trim: true, // Remove spaces
    },
    password: {
      type: String,
      required: function () {
        return !this.googleId; // Password required only if Google ID is not present
      },
      minlength: 6, // Ensure strong password
    },
    googleId: { type: String, unique: true, sparse: true }, // Sparse avoids unique conflict with null values
    name: { type: String, trim: true },
    avatar: { type: String, trim: true },

    // Password Reset Fields
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
  },
  { timestamps: true } // Add timestamps for createdAt & updatedAt
);

// 🔹 Hash password before saving
userSchema.pre("save", async function (next) {
  try {
    if (!this.isModified("password")) return next(); // Skip if password is unchanged
    this.password = await bcrypt.hash(this.password, 10); // Hash with optimal salt rounds
    next();
  } catch (error) {
    next(error);
  }
});

// 🔹 Compare Passwords
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};
// subscription page
const Subscriber = mongoose.model('Subscriber', new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  subscribedAt: { type: Date, default: Date.now },
}));

const User = mongoose.model("User", userSchema);

export default User;
