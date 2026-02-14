import { Products } from "../models/Products.js";
import cloudinary from "../utils/Cloudinary.js";
import getDataUri from "../utils/DataUri.js";

//add Products
export const addProducts = async (req, res) => {
    try {
        const { productName, productDesc, productPrice, category, brand } = req.body;
        const userId = req.id;

        //Basic validation 
        if (!productName || !productDesc || !productPrice || !category || !brand) {
            return res.status(400).json({
                success: false,
                message: "All fields required"
            });
        }
        //handle multiple images upload
        let productImg = [];

        if (req.files && req.files.length > 0) {
            for (let file of req.files) {
                const fileURI = getDataUri(file);
                const result = await cloudinary.uploader.upload(fileURI, {
                    folder: "mern_folder"
                });
                productImg.push({
                    url: result.secure_url,
                    publicId: result.public_id
                });
            }
        }

        //Create a product in db 
        const newProduct = await Products.create({
            userId,
            productName,
            productDesc,
            productPrice,
            category,
            brand,
            productImg
        });

        return res.status(200).json({
            success: true,
            message: "Product added Successfully",
            product: newProduct
        });

    } catch (error) {
        console.log(error);

        return res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }
}
//get all Products
export const getAllProducts = async (req, res) => {
    try {
        const products = await Products.find();
        if (!products) {
            return res.status(404).json({
                success: false,
                message: "No Product Available",
                products: []
            });
        }
        return res.status(200).json({
            success: true,
            message: "Products fetched Successfully",
            products
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }
}
//delete Products
export const deleteProduct = async (req, res) => {
    try {
        const { productId } = req.params;

        const product = await Products.findById(productId);
        if (!product) {
            return res.status(404).json({
                success: false,
                message: "Not product exists of this id"
            });
        }
        // Delete images from cloudinary 
        if (product.productImg && product.productImg.length > 0) {
            for (let img of product.productImg) {
                const result = await cloudinary.uploader.destroy(img.publicId);
            }
        }

        //delete product from mongo db
        await Products.findByIdAndDelete(productId);
        return res.status(200).json({
            success: true,
            message: "Product Deleted Successfully"
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }
}
//update Products
export const updateProduct = async (req, res) => {
    try {
        const { productId } = req.params;
        const { productName, productDesc, productPrice, category, brand, existingImages } = req.body;

        const product = await Products.findById(productId);

        if (!product) {
            return res.status(400).json({
                success: false,
                message: "Product not found"
            });
        }

        let updatedImages = [];
        //keep old images 
        if (existingImages) {
            const keepIds = JSON.parse(existingImages);
            updatedImages = product.productImg.filter((img) =>
                keepIds.includes(img.publicId)
            );
            //delete only removed images
            const removedImages = product.productImg.filter(
                (img) => !keepIds.includes(img.publicId)
            );

            for (let img of removedImages) {
                await cloudinary.uploader.destroy(img.publicId);
            }
        }
        else {
            updatedImages = product.productImg //keep all if nothing sent
        }

        //upload new images if any
        if (req.files && req.files.length > 0) {
            for (let file of req.files) {
                const filesuri = getDataUri(file);
                const result = await cloudinary.uploader.upload(fileuri, {
                    folder: "mern_products"
                });
                updatedImages.push({
                    url: result.secure_url,
                    public_id: result.public_id
                });
            }
        }

        // update product

        product.productName = productName || product.productName;
        product.productDesc = productDesc || product.productDesc;
        product.productPrice = productPrice || product.productPrice;
        product.category = catetgory || product.category;
        product.brand = brand || product.brand;
        product.productImg = updatedImages

        await product.save();

        return res.status(200).json({
            success:true,
            message:"Product Updated Successfully",
            product
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Internal Server Error"
        });
    }
}