//entry point
import "dotenv/config"

import express from "express";
import { connectDB } from "./config/DB.js";
import authUser from "./routes/userRoutes.js"
import Admin from "./routes/adminRoutes.js"
import productRoute from "./routes/productRoute.js"
import cors from "cors";
import cookieParser from "cookie-parser";

const PORT = process.env.PORT || 5000;
const app = express();

//middlewares
app.use(express.json());
app.use(cors({
  origin: "http://localhost:5173",
  credentials: true
}));
app.use(cookieParser());

//routes
//user routes
app.use('/user', authUser);
//admin routes
app.use('/admin', Admin);
//Product routes
app.use('/products', productRoute);

const startServer = async () => {
  try {
    await connectDB();

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });

  } catch (error) {
    console.error("Server failed to start:", error.message);
    process.exit(1); // stop app if DB fails
  }
};

startServer();
