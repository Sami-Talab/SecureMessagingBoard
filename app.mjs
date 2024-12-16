import express from 'express';
import { auth } from 'express-openid-connect';
import { engine } from 'express-handlebars';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import { allowInsecurePrototypeAccess } from '@handlebars/allow-prototype-access';
import Handlebars from 'handlebars';

import authRoutes from './routes/auth.mjs';
import messageRoutes from './routes/messages.mjs';
import friendRoutes from './routes/friends.mjs';
import connectDB from './db.mjs';
import rateLimiter from './middlewares/rateLimiter.mjs';
import errorHandler from './middlewares/errorHandler.mjs';
import logger from './utils/logger.mjs';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Connect to MongoDB
connectDB();

// Rate limiter
app.use(rateLimiter);

// Sessions
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }, // set to true if you're using https
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI, 
      collectionName: 'sessions',
    }),
  })
);

// Auth0 configuration
const config = {
  authRequired: false,
  auth0Logout: true,
  baseURL: process.env.BASE_URL || 'http://linserv1.cims.nyu.edu:35450',
  clientID: process.env.AUTH0_CLIENT_ID,
  issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}`,
  secret: process.env.AUTH0_CLIENT_SECRET,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  routes: {
    login: false,
    callback: '/callback'
  },
  authorizationParams: {
    response_type: 'code',
    scope: 'openid profile email'
  }
};

// Auth0 middleware
app.use(auth(config));

// Added debug logging
app.use((req, res, next) => {
  console.log('Auth0 User:', req.oidc.user);
  console.log('Is Authenticated:', req.oidc.isAuthenticated());
  next();
});

// Handlebars setup
app.engine(
  'hbs',
  engine({
    extname: '.hbs',
    defaultLayout: 'main',
    layoutsDir: path.join(__dirname, 'views', 'layouts'),
    partialsDir: path.join(__dirname, 'views', 'partials'),
    handlebars: allowInsecurePrototypeAccess(Handlebars),
    helpers: {
      eq: (v1, v2) => v1 === v2,
      formatDate: (date) => {
        return new Date(date).toLocaleString('en-US', {
          year: 'numeric',
          month: 'long',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        });
      }
    },
  })
);
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Parse JSON and form data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Authentication middleware
const isAuthenticated = (req, res, next) => {
  console.log('Checking authentication:', req.oidc.isAuthenticated(), req.session.user);
  if (req.oidc.isAuthenticated() || req.session.user) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Middleware to add user to res.locals
app.use((req, res, next) => {
  res.locals.user = req.oidc.isAuthenticated() ? req.oidc.user : req.session.user;
  next();
});

// Root route
app.get('/', (req, res) => {
  if (req.oidc.isAuthenticated() || req.session.user) {
    res.redirect('/profile');
  } else {
    res.render('welcome', { title: 'Welcome' });
  }
});

// Use routes
app.use('/', authRoutes);
app.use('/messages', isAuthenticated, messageRoutes);
app.use('/friends', isAuthenticated, friendRoutes);

// Error handling middleware
app.use(errorHandler);

// Start the server
const PORT = process.env.PORT || 35450;
app.listen(PORT, () => logger.info(`Server running on http://localhost:${PORT}`));

export default app;

