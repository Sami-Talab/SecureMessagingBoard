import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  auth0Id: { type: String, sparse: true, unique: true },
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: function() { return !this.auth0Id; } },
  publicKey: { type: String, required: true },
  encryptedPrivateKey: { type: String, required: true },
  keyEncryptionPassword: { type: String, required: true },
  keyPasswordSet: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  friendRequests: [{
    from: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    status: { type: String, enum: ['pending', 'accepted', 'declined'], default: 'pending' }
  }],
});

userSchema.index({ auth0Id: 1 }, { sparse: true, unique: true });

export default mongoose.model('User', userSchema);

