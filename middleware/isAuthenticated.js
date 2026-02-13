import { Users } from "../models/usersSchema.js";
import jwt from "jsonwebtoken";

export const isAuthenticated = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        //basic validation
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(400).json({
                success: false,
                message: "Access token is missing and invalid"
            });
        }

        const token = authHeader.split(" ")[1];
        let decoded;

        try {
            decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

        } catch (error) {
            if (error.name === "TokenExpiredError") {
                return res.status(400).json({
                    success: false,
                    message: "Token expired please get a new one"
                });
            }
        }

        const user = await Users.findById(decoded.id).select("-password");

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        req.user = user;
        req.id = user.id;
        next();

    } catch (error) {
        return res.status(500).json({
            succes: false,
            message: error.message
        });
    }
}

export const isAdmin = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: "Authentication required"
    });
  }

  if (req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Admin access only"
    });
  }

  next();
};
