import mongoose from 'mongoose';
import dotenv from 'dotenv';
import logger from './utils/logger.mjs';

dotenv.config();

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    logger.info('Connected to MongoDB');
  } catch (error) {
    logger.error('Error connecting to MongoDB:', error);
    process.exit(1); 
  }
};

export default connectDB;

