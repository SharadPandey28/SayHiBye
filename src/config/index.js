import "dotenv/config";

export const config = {
  port: parseInt(process.env.PORT || "3001"),
  nodeEnv: process.env.NODE_ENV || "development",
  isDev: (process.env.NODE_ENV || "development") === "development",

  mongo: {
    uri: process.env.MONGO_URI || "mongodb://localhost:27017/dhsecurechat",
  },

  redis: {
    url: process.env.REDIS_URL || "redis://localhost:6379",
  },

  jwt: {
    secret: process.env.JWT_SECRET || "dev_secret_change_in_production",
    expiresIn: process.env.JWT_EXPIRES_IN || "7d",
  },

  admin: {
    password: process.env.ADMIN_PASSWORD || "admin123",
  },

  cors: {
    origin: process.env.ALLOWED_ORIGIN || "http://localhost:3001",
  },

  rateLimit: {
    windowMs: 15 * 60 * 1000,   // 15 minutes
    max: 100,                    // requests per window
    socketEventsPerSec: 15,      // socket events per second per socket
  },
};
