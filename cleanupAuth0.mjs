import mongoose from 'mongoose';
import User from './models/User.mjs';
import dotenv from 'dotenv';

dotenv.config();

(async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    const result = await User.updateMany({ auth0Id: null }, { $unset: { auth0Id: "" } });
    console.log('Cleaned up users with auth0Id: null:', result);

    mongoose.disconnect();
  } catch (err) {
    console.error('Error cleaning up database:', err);
    process.exit(1);
  }
})();
