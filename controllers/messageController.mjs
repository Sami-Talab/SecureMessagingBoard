import Message from '../models/Message.mjs';
import User from '../models/User.mjs';
import logger from '../utils/logger.mjs';
import CryptoJS from 'crypto-js';
import bcrypt from 'bcrypt';
import { decryptPrivateKey } from '../utils/cryptoUtils.mjs';

export const getAllMessages = async (req, res) => {
  try {
    const user = await User.findOne({ $or: [{ auth0Id: req.oidc?.user?.sub }, { _id: req.session?.user?.id }] });
    
    if (!user) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    const messages = await Message.find({
      $or: [
        { senderId: user._id },
        { recipientId: user._id }
      ]
    }).populate('senderId', 'username')
      .populate('recipientId', 'username')
      .sort({ timestamp: -1 });

    res.render('messages', { messages, user, title: 'Messages' });
  } catch (error) {
    logger.error("Error fetching messages:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};

export const showCreateMessageForm = async (req, res) => {
  try {
    const currentUser = await User.findOne({ auth0Id: req.oidc.user.sub });
    const users = await User.find({ _id: { $ne: currentUser._id } }, 'username');
    res.render('create-message', { users, title: 'New Message' });
  } catch (error) {
    logger.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};

export const createMessage = async (req, res) => {
  try {
    const { recipientUsername, content } = req.body;
    const sender = await User.findOne({ $or: [{ auth0Id: req.oidc?.user?.sub }, { _id: req.session?.user?.id }] });

    if (!sender) {
      return res.status(401).json({ error: 'Sender not authenticated' });
    }

    if (!sender.keyPasswordSet) {
      return res.status(400).json({ error: 'Please set your key password in your profile before sending messages' });
    }

    const recipient = await User.findOne({ username: recipientUsername });
    if (!recipient) {
      return res.status(400).json({ error: 'Recipient not found' });
    }

    if (!recipient.keyPasswordSet) {
      return res.status(400).json({ error: 'Recipient has not set their key password yet' });
    }

    // Generate a random symmetric key
    const symmetricKey = CryptoJS.lib.WordArray.random(32);

    // Encrypt the message content with the symmetric key
    const encryptedContent = CryptoJS.AES.encrypt(content, symmetricKey.toString()).toString();

    // Encrypt the symmetric key with the recipient's public key
    const encryptedSymmetricKey = CryptoJS.AES.encrypt(symmetricKey.toString(), recipient.publicKey).toString();

    const newMessage = new Message({
      senderId: sender._id,
      recipientId: recipient._id,
      contentEncrypted: encryptedContent,
      encryptedSymmetricKey,
    });

    await newMessage.save();
    res.json({ success: true, message: 'Message sent successfully' });
  } catch (error) {
    logger.error('Error creating message:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
};

export const showEditMessageForm = async (req, res) => {
  try {
    const message = await Message.findById(req.params.id);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    const sender = await User.findOne({ auth0Id: req.oidc.user.sub });
    if (message.senderId.toString() !== sender._id.toString()) {
      return res.status(403).json({ error: 'Not authorized to edit this message' });
    }
    res.render('edit-message', { message, title: 'Edit Message' });
  } catch (error) {
    logger.error('Error fetching message:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

export const updateMessage = async (req, res) => {
  try {
    const message = await Message.findById(req.params.id);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    const sender = await User.findOne({ auth0Id: req.oidc.user.sub });
    if (message.senderId.toString() !== sender._id.toString()) {
      return res.status(403).json({ error: 'Not authorized to edit this message' });
    }
    const { content } = req.body;
    
    const recipient = await User.findById(message.recipientId);
    
    // Generate a new symmetric key
    const symmetricKey = CryptoJS.lib.WordArray.random(32);

    // Encrypt the updated content with the new symmetric key
    const encryptedContent = CryptoJS.AES.encrypt(content, symmetricKey.toString()).toString();

    // Encrypt the new symmetric key with the recipient's public key
    const encryptedSymmetricKey = CryptoJS.AES.encrypt(symmetricKey.toString(), recipient.publicKey).toString();

    message.contentEncrypted = encryptedContent;
    message.encryptedSymmetricKey = encryptedSymmetricKey;
    await message.save();
    res.redirect('/messages');
  } catch (error) {
    logger.error('Error updating message:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

export const decryptMessage = async (req, res) => {
  try {
    const messageId = req.params.id;
    const { keyPassword } = req.body;
    
    if (!keyPassword) {
      return res.status(400).json({ error: 'Key password is required' });
    }

    const user = await User.findOne({ $or: [{ auth0Id: req.oidc?.user?.sub }, { _id: req.session?.user?.id }] });

    if (!user) {
      logger.error(`Decryption attempt failed: User not authenticated`);
      return res.status(401).json({ error: 'User not authenticated' });
    }

    if (!user.keyPasswordSet) {
      return res.status(400).json({ error: 'Please set your key password in your profile before decrypting messages' });
    }

    // Verify the key password
    const isKeyPasswordValid = await bcrypt.compare(keyPassword, user.keyEncryptionPassword);
    if (!isKeyPasswordValid) {
      return res.status(401).json({ error: 'Invalid key password' });
    }

    logger.info(`Decryption attempt for message ${messageId} by user ${user._id}`);

    const message = await Message.findById(messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    // Check if the user is the recipient of the message
    if (message.recipientId.toString() !== user._id.toString()) {
      logger.error(`Unauthorized decryption attempt: User ${user._id} tried to decrypt message ${messageId} intended for ${message.recipientId}`);
      return res.status(403).json({ error: 'Not authorized to decrypt this message' });
    }

    try {
      // Decrypt the user's private key
      const [encryptedPrivateKey, salt] = user.encryptedPrivateKey.split(':');
      const privateKey = decryptPrivateKey(encryptedPrivateKey, keyPassword, salt);

      // Decrypt the symmetric key using the user's private key
      const symmetricKey = CryptoJS.AES.decrypt(message.encryptedSymmetricKey, privateKey).toString(CryptoJS.enc.Utf8);

      // Decrypt the message content
      const decrypted = CryptoJS.AES.decrypt(message.contentEncrypted, symmetricKey).toString(CryptoJS.enc.Utf8);

      // Store the decrypted content in the session
      req.session.decryptedMessages = req.session.decryptedMessages || {};
      req.session.decryptedMessages[messageId] = decrypted;

      res.json({ success: true, decryptedContent: decrypted });
    } catch (decryptionError) {
      logger.error(`Decryption failed for message ${messageId}: ${decryptionError.message}`);
      return res.status(500).json({ error: 'Failed to decrypt message', details: decryptionError.message });
    }
  } catch (error) {
    logger.error('Error in decryptMessage:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
};

