import dotenv from "dotenv";
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bodyParser from "body-parser";
import authRoutes from "./routes/authRoutes.js";
import session from 'express-session';
import passport from 'passport';
import './config/passport.js';

dotenv.config();

const app = express();
const PORT = process.env.VITE_SERVER_PORT || process.env.VITE_SERVER_PORT_BACKUP;

// Middleware
app.use(cors({origin:"https://skyfordcci.vercel.app", credential:true}));
app.use(bodyParser.json());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("Connected to MongoDB :)"))
  .catch((err) => console.error("Error connecting to MongoDB ):", err.message));

// Routes
app.use("/api/auth", authRoutes);

app.use(session({ secret: 'Future_', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

app.get('/', (req,res)=>{
  res.send('SKYFORDCCI: This is server side Home-Page, Check the status on /server/api/data' )
})

app.get('/server/api/data', (req,res)=>{
  res.json({message:'This is server side:',status:"ok",code:'200' ,domain: process.env.VITE_SERVER_DOMAIN})
})

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);

});



