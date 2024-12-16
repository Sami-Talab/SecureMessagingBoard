import express from 'express';
import pkg from 'express-openid-connect';
const { requiresAuth } = pkg;
import bcrypt from 'bcrypt';
import User from '../models/User.mjs';
import validator from '../middlewares/validator.mjs';
import logger from '../utils/logger.mjs';
import { generateKeyPair, encryptPrivateKey } from '../utils/cryptoUtils.mjs';
import CryptoJS from 'crypto-js';
import Message from '../models/Message.mjs'; // Import Message model

const router = express.Router();

// Middleware to fetch authenticated user
async function fetchAuthenticatedUser(req, res, next) {
  try {
    if (req.oidc && req.oidc.isAuthenticated()) {
      let user = await User.findOne({ auth0Id: req.oidc.user.sub }).populate('friends').populate('friendRequests.from');
      
      if (!user) {
        // If user doesn't exist, create a new one
        const { sub, email, nickname } = req.oidc.user;
        const keyPassword = CryptoJS.lib.WordArray.random(16).toString();
        const { privateKey, publicKey } = generateKeyPair();
        const { encryptedPrivateKey, salt } = encryptPrivateKey(privateKey, keyPassword);

        user = new User({
          auth0Id: sub,
          email,
          username: nickname || email,
          publicKey,
          encryptedPrivateKey: `${encryptedPrivateKey}:${salt}`,
          keyEncryptionPassword: await bcrypt.hash(keyPassword, 10),
        });

        await user.save();
        logger.info(`New Auth0 user created: ${user.username}, ${email}`);
      }

      req.user = user;
    } else if (req.session && req.session.user) {
      req.user = await User.findById(req.session.user.id).populate('friends').populate('friendRequests.from');
    }

    if (!req.user) {
      logger.warn('User not found after authentication');
    }

    next();
  } catch (error) {
    logger.error('Error fetching authenticated user:', error);
    res.status(500).json({ error: 'Failed to authenticate user.' });
  }
}

router.get('/login', (req, res) => {
  res.render('login', { title: 'Login' });
});

router.get('/signup', (req, res) => {
  res.render('signup', { title: 'Sign Up' });
});

// Login route for Auth0
router.get('/auth/login', (req, res) => {
  console.log('Initiating Auth0 login');
  res.oidc.login({
    returnTo: '/profile',
    authorizationParams: {
      response_type: 'code',
      scope: 'openid profile email'
    }
  });
});

// Auth0 callback route
router.get('/callback', async (req, res, next) => {
  try {
    console.log('Callback route hit');
    await new Promise((resolve, reject) => {
      req.oidc.callback({
        redirectUri: `${req.protocol}://${req.get('host')}/callback`,
      }, (err) => {
        if (err) {
          console.error('Callback error:', err);
          reject(err);
        } else {
          console.log('Callback successful');
          resolve();
        }
      });
    });

    if (req.oidc.isAuthenticated()) {
      console.log('User authenticated:', req.oidc.user);
      const { sub, email, nickname } = req.oidc.user;
      let user = await User.findOne({ auth0Id: sub });

      if (!user) {
        // Generate key pair and encrypt the private key
        const keyPassword = CryptoJS.lib.WordArray.random(16).toString();
        const { privateKey, publicKey } = generateKeyPair();
        const { encryptedPrivateKey, salt } = encryptPrivateKey(privateKey, keyPassword);

        user = new User({
          auth0Id: sub,
          email,
          username: nickname || email,
          publicKey,
          encryptedPrivateKey: `${encryptedPrivateKey}:${salt}`,
          keyEncryptionPassword: await bcrypt.hash(keyPassword, 10),
        });

        await user.save();
        logger.info(`New Auth0 user created: ${user.username}, ${email}`);
      }

      req.session.user = { id: user._id, username: user.username };
      await req.session.save();
      console.log('Session saved, redirecting to profile');
      return res.redirect('/profile');
    } else {
      console.log('User not authenticated after callback');
      return res.redirect('/login');
    }
  } catch (error) {
    console.error('Error in Auth0 callback:', error);
    next(error);
  }
});

// Profile route
router.get('/profile', fetchAuthenticatedUser, async (req, res) => {
  try {
    if (!req.user) {
      console.log('User not found, redirecting to login');
      return res.redirect('/login');
    }

    console.log('Rendering profile for user:', req.user.username);
    res.render('profile', { user: req.user, title: 'User Profile' });
  } catch (error) {
    logger.error('Error fetching profile:', error);
    res.status(500).render('error', { title: 'Error', message: 'Unable to fetch profile. Please try logging in again.' });
  }
});

// Manual login route
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    req.session.user = { id: user._id, username: user.username };
    await req.session.save();
    res.json({ success: true, redirectUrl: '/profile' });
  } catch (error) {
    logger.error('Error during manual login:', error);
    res.status(500).json({ error: 'Login error.' });
  }
});

// Signup route
router.post('/signup', async (req, res) => {
  try {
    const { username, email, password, keyPassword } = req.body;

    logger.info(`Signup attempt for username: ${username}, email: ${email}`);

    if (!username || !email || !password || !keyPassword) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email is already taken.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedKeyPassword = await bcrypt.hash(keyPassword, 10);

    // Generate key pair and encrypt private key
    const { privateKey, publicKey } = generateKeyPair();
    const { encryptedPrivateKey, salt } = encryptPrivateKey(privateKey, keyPassword);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      publicKey,
      encryptedPrivateKey: `${encryptedPrivateKey}:${salt}`,
      keyEncryptionPassword: hashedKeyPassword,
    });

    await newUser.save();

    logger.info(`New user created: ${username}, ${email}`);

    req.session.user = { id: newUser._id, username: newUser.username };
    await req.session.save();

    res.json({ success: true, message: 'User created successfully.', redirectUrl: '/profile' });
  } catch (error) {
    logger.error('Error during signup:', error);
    res.status(500).json({ error: 'Signup error: ' + error.message });
  }
});

// Logout route
router.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      logger.error('Error destroying session:', err);
      return res.status(500).render('error', { title: 'Error', message: 'Logout error.' });
    }

    res.oidc.logout({
      returnTo: process.env.BASE_URL || 'http://localhost:3000',
    });
  });
});

// Change username route
router.post('/change-username', requiresAuth(), async (req, res) => {
  try {
    const { newUsername } = req.body;
    const userId = req.oidc?.user?.sub || req.session?.user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    if (!newUsername || newUsername.trim() === '') {
      return res.status(400).json({ error: 'New username is required' });
    }

    const existingUser = await User.findOne({ username: newUsername });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already taken' });
    }

    const updatedUser = await User.findOneAndUpdate(
      { $or: [{ auth0Id: userId }, { _id: userId }] },
      { username: newUsername },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ success: true, message: 'Username updated successfully', newUsername });
  } catch (error) {
    logger.error('Error changing username:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Change key password route
router.post('/change-key-password', requiresAuth(), async (req, res) => {
  try {
    const { newKeyPassword } = req.body;
    const userId = req.oidc?.user?.sub || req.session?.user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    if (!newKeyPassword || newKeyPassword.trim() === '') {
      return res.status(400).json({ error: 'New key password is required' });
    }

    let user;
    if (req.oidc?.user?.sub) {
      // This is an Auth0 user
      user = await User.findOne({ auth0Id: userId });
    } else {
      // This is a manually registered user
      user = await User.findById(userId);
    }

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate new key pair
    const { privateKey, publicKey } = generateKeyPair();
    const { encryptedPrivateKey, salt } = encryptPrivateKey(privateKey, newKeyPassword);

    // Update user's key information
    user.publicKey = publicKey;
    user.encryptedPrivateKey = `${encryptedPrivateKey}:${salt}`;
    user.keyEncryptionPassword = await bcrypt.hash(newKeyPassword, 10);
    user.keyPasswordSet = true;

    // Delete all messages for this user
    await Message.deleteMany({ $or: [{ senderId: user._id }, { recipientId: user._id }] });

    await user.save();

    res.json({ success: true, message: 'Key password updated successfully' });
  } catch (error) {
    logger.error('Error changing key password:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;

