import express from "express";
import { deleteUser, getUsers } from "../controllers/authController.js";
import { isAdmin, isAuthenticated } from "../middleware/isAuthenticated.js";
const router = express.Router();

//admin routes
router.get('/all-users', isAuthenticated, isAdmin, getUsers);
// router.put('/update-role/:id', isAuthenticated, isAdmin, updateRole);
// router.delete('/delete-user/:id',isAuthenticated, isAdmin, deleteUser);

export default router