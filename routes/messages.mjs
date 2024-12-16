import express from 'express';
import pkg from 'express-openid-connect';
const { requiresAuth } = pkg;
import * as messageController from '../controllers/messageController.mjs';

const router = express.Router();

router.get('/', requiresAuth(), messageController.getAllMessages);
router.get('/create', requiresAuth(), messageController.showCreateMessageForm);
router.post('/create', requiresAuth(), messageController.createMessage);
router.get('/edit/:id', requiresAuth(), messageController.showEditMessageForm);
router.post('/edit/:id', requiresAuth(), messageController.updateMessage);

router.post('/decrypt/:id', requiresAuth(), messageController.decryptMessage);

export default router;

