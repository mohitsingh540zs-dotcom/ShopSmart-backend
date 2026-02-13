import express, { Router } from 'express';
import { addProducts, getAllProducts } from '../controllers/productsController.js';
import { isAuthenticated, isAdmin } from "../middleware/isAuthenticated.js";
import { multipleUpload } from '../middleware/multer.js';
const router = express.Router();

router.post('/create', isAuthenticated, isAdmin, multipleUpload, addProducts);
router.get('/get-all', getAllProducts);

export default router;