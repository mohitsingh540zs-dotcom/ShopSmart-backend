import mongoose from "mongoose";

const productSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Users",
        required: true
    },
    productName: {
        type: String,
        required: true
    },
    productDesc: {
        type: String,
        required: true
    },

    productImg: [
        {
            url: { type: String, required: true },
            publicId: { type: String, required: true }
        }
    ],
    productPrice: {
        type: Number
    },
    category: {
        type: String
    },
    brand: {
        type: String
    }
},
    {
        collection: "Products",
        timestamps: true
    });

export const Products = mongoose.model("Products", productSchema);
