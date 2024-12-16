import express from 'express';
import pkg from 'express-openid-connect';
const { requiresAuth } = pkg;
import User from '../models/User.mjs';
import logger from '../utils/logger.mjs';

const router = express.Router();

// Search users
router.get('/search', requiresAuth(), async (req, res) => {
  try {
    const { query } = req.query;
    const currentUser = await User.findOne({ 
      $or: [
        { auth0Id: req.oidc?.user?.sub },
        { _id: req.session?.user?.id }
      ]
    });
    
    if (!currentUser) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    const users = await User.find(
      { 
        $and: [
          { $or: [
            { username: { $regex: query, $options: 'i' } },
            { email: { $regex: query, $options: 'i' } }
          ]},
          { _id: { $ne: currentUser._id } },
          { _id: { $nin: currentUser.friends } }
        ]
      },
      'username email'
    ).limit(10);

    res.json(users);
  } catch (error) {
    logger.error('Error searching users:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Friend list page
router.get('/list', requiresAuth(), async (req, res) => {
  try {
    const user = await User.findOne({ 
      $or: [
        { auth0Id: req.oidc?.user?.sub },
        { _id: req.session?.user?.id }
      ]
    })
      .populate('friends', 'username email')
      .populate('friendRequests.from', 'username email')
      .select('friends friendRequests');
    
    const friendCount = user.friends.length;
    const pendingRequests = user.friendRequests.filter(request => request.status === 'pending');

    res.render('friends', { 
      title: 'Friends',
      user,
      friends: user.friends,
      friendCount,
      pendingRequests
    });
  } catch (error) {
    logger.error('Error fetching friend list:', error);
    res.status(500).render('error', { title: 'Error', message: 'Unable to fetch friend list.' });
  }
});

// Send friend request
router.post('/send-request', requiresAuth(), async (req, res) => {
  try {
    const { recipientUsername } = req.body;
    const senderAuth0Id = req.oidc?.user?.sub;
    const senderId = req.session?.user?.id;

    const sender = await User.findOne({ $or: [{ auth0Id: senderAuth0Id }, { _id: senderId }] });
    const recipient = await User.findOne({ username: recipientUsername });

    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found' });
    }

    if (recipient.friendRequests.some(req => req.from.equals(sender._id))) {
      return res.status(400).json({ error: 'Friend request already sent' });
    }

    if (recipient.friends.includes(sender._id)) {
      return res.status(400).json({ error: 'User is already your friend' });
    }

    await User.findByIdAndUpdate(recipient._id, {
      $push: { friendRequests: { from: sender._id } }
    });

    res.json({ success: true, message: 'Friend request sent successfully' });
  } catch (error) {
    logger.error('Error sending friend request:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Accept friend request
router.post('/accept-request', requiresAuth(), async (req, res) => {
  try {
    const { requestId } = req.body;
    const recipientAuth0Id = req.oidc?.user?.sub;
    const recipientId = req.session?.user?.id;

    const recipient = await User.findOne({ $or: [{ auth0Id: recipientAuth0Id }, { _id: recipientId }] });
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found' });
    }

    const request = recipient.friendRequests.id(requestId);
    if (!request) {
      return res.status(404).json({ error: 'Friend request not found' });
    }

    if (request.status !== 'pending') {
      return res.status(400).json({ error: 'Friend request already processed' });
    }

    await User.findByIdAndUpdate(recipient._id, {
      $push: { friends: request.from },
      $set: { 'friendRequests.$[elem].status': 'accepted' }
    }, {
      arrayFilters: [{ 'elem._id': requestId }]
    });

    await User.findByIdAndUpdate(request.from, {
      $push: { friends: recipient._id }
    });

    res.json({ success: true, message: 'Friend request accepted successfully' });
  } catch (error) {
    logger.error('Error accepting friend request:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Decline friend request
router.post('/decline-request', requiresAuth(), async (req, res) => {
  try {
    const { requestId } = req.body;
    const recipientAuth0Id = req.oidc?.user?.sub;
    const recipientId = req.session?.user?.id;

    const recipient = await User.findOne({ $or: [{ auth0Id: recipientAuth0Id }, { _id: recipientId }] });
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found' });
    }

    const request = recipient.friendRequests.id(requestId);
    if (!request) {
      return res.status(404).json({ error: 'Friend request not found' });
    }

    if (request.status !== 'pending') {
      return res.status(400).json({ error: 'Friend request already processed' });
    }

    await User.findByIdAndUpdate(recipient._id, {
      $set: { 'friendRequests.$[elem].status': 'declined' }
    }, {
      arrayFilters: [{ 'elem._id': requestId }]
    });

    res.json({ success: true, message: 'Friend request declined successfully' });
  } catch (error) {
    logger.error('Error declining friend request:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;

