import dotenv from "dotenv";
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import session from "express-session";
import passport from "passport";
import authRoutes from "./routes/authRoutes.js";
import "./config/passport.js";

dotenv.config();

const app = express();
const PORT = process.env.VITE_SERVER_PORT || process.env.VITE_SERVER_PORT_BACKUP;

// ✅ Check required environment variables
if (!process.env.MONGO_URI || !process.env.VITE_SERVER_PORT) {
  console.error("❌ Missing required environment variables!");
  process.exit(1);
}

// ✅ Middleware
app.use(cors({ origin: process.env.VITE_FRONTEND_DOMAIN_URL_HTTP, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ MongoDB Connection Handling
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch(err => {
    console.error("❌ MongoDB Connection Error:", err.message);
    process.exit(1);
  });

mongoose.connection.on("disconnected", () => console.log("⚠️ MongoDB Disconnected"));

// ✅ Session & Passport
app.use(session({
  secret: process.env.SESSION_SECRET || "default_secret",
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

app.use(passport.initialize());
app.use(passport.session());

// ✅ Routes
app.use("/api/auth", authRoutes);

app.get('/', (req, res) => {
  res.json({ message: "SKYFORDCCI: Server Home", status: "OK", documentation: "/server/api/data" });
});

app.get('/server/api/data', (req, res) => {
  res.json({ message: "Server Status", status: "OK", code: 200, domain: process.env.VITE_SERVER_DOMAIN });
});

// ✅ Start Server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
