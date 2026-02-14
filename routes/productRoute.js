import express, { Router } from 'express';
import { addProducts, deleteProduct, getAllProducts, updateProduct } from '../controllers/productsController.js';
import { isAuthenticated, isAdmin } from "../middleware/isAuthenticated.js";
import { multipleUpload } from '../middleware/multer.js';
const router = express.Router();

router.post('/create', isAuthenticated, isAdmin, multipleUpload, addProducts);
router.get('/get-all', getAllProducts);
router.put('/update/:productId', isAuthenticated, isAdmin, updateProduct);
router.delete('/delete/:productId', isAuthenticated, isAdmin, deleteProduct);


export default router;