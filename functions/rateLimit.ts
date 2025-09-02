import rateLimit from "express-rate-limit";

const limiter = rateLimit({
  windowMs: 60 * 1000, 
  max: 100,             
  standardHeaders: true, 
  legacyHeaders: false, 
  message: "Too many requests, please try again later."
});

export default limiter;