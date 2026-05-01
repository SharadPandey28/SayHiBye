FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package files first (better Docker layer caching)
COPY package*.json ./

# Install production dependencies only
RUN npm install --omit=dev

# Copy source code
COPY . .

# Expose port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3001/health || exit 1

# Start the server
CMD ["node", "src/server.js"]
