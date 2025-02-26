import bcrypt from "bcrypt";
import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  googleId: { type: String, unique: true },
    name: String,
    avatar: String,
    resetPasswordToken:String,
    resetPasswordExpires:Date,
});

// Hash password before saving
userSchema.pre("save", async function (next) {
    try{
        if (!this.isModified("password")) return next();
        this.password = await bcrypt.hash(this.password, 15 );
        next();
    }catch(error){
        next(error)
    }
}
);
const User = mongoose.model("User", userSchema)

export default User;