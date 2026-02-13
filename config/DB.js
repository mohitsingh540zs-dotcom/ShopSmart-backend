import mongoose from "mongoose";

export const connectDB = async()=>{
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('Connected to Mongodb Successfully');
    } catch (error) {
        console.log("Failed to establish connection with database",error);
    }
}