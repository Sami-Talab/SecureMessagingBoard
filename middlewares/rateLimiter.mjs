import rateLimit from 'express-rate-limit';

const rateLimiter = rateLimit({
  windowMs: 30 * 60 * 1000, // 30 minutes
  max: 200 // limit each IP to 200 requests per windowMs
});

export default rateLimiter;

