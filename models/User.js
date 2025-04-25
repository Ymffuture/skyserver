import bcrypt from "bcrypt";
import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: function () {
        return !this.googleId;
      },
      unique: true,
      lowercase: true,
      trim: true,
      match: [/.+@.+\..+/, "Invalid email format"], 
    },
    fname: {
      type: String,
      required: true,
      trim: true,
    },
    password: {
      type: String,
      required: function () {
        return !this.googleId;
      },
      minlength: [6, "Password must be at least 6 characters"],
    },
    googleId: {
      type: String,
      unique: true,
      sparse: true,
    },
    name: {
      type: String,
      trim: true,
    },
    avatar: {
      type: String,
      trim: true,
    },
    // 🔐 Password Reset
    resetPasswordToken: {
      type: String,
      select: false, // Exclude from normal queries
    },
    resetPasswordExpires: {
      type: Date,
    },
  },
  {
    timestamps: true,
  }
);

// 🧂 Pre-save password hashing
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  try {
    this.password = await bcrypt.hash(this.password, 10);
    next();
  } catch (err) {
    next(err);
  }
});

/
userSchema.methods.comparePassword = function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// ✅ Model export
const User = mongoose.model("User", userSchema);

// 📬 Subscriber model (💡 separate file recommended)
const Subscriber = mongoose.model(
  "Subscriber",
  new mongoose.Schema({
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      match: [/.+@.+\..+/, "Invalid email format"],
    },
    subscribedAt: {
      type: Date,
      default: Date.now,
    },
  })
);

export default User;
