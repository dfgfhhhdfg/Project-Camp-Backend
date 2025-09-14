import mongoose from "mongoose";

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.error("✅ MongoDB connected");
  } catch (error) {
    console.error("❌ MongoDB connectioin error", error);
    process.exit(1);
  }
};

export default connectDB;
