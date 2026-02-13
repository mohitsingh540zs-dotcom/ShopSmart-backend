//entry point
import "dotenv/config"

import express from "express";
import { connectDB } from "./config/DB.js";
import authUser from "./routes/userRoutes.js"
import Admin from "./routes/adminRoutes.js"
import productRoute from "./routes/productRoute.js"
import cors from "cors";
import cookieParser from "cookie-parser";

const PORT = process.env.PORT || 3000;
const app = express();

const allowedOrigins = ['http://localhost:5173', 'https://shop-smart-frontend-nine.vercel.app'];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization"]
};


//middlewares
app.use(express.json());
app.use(cors(corsOptions));
app.use(cookieParser());

//routes
//user routes
app.get("/", (req, res) => {
  res.send("Welcome to the ShopSmart Ecommerce Site");
})
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
