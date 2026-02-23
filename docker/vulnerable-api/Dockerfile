FROM node:14-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (with known vulnerabilities)
RUN npm install

# Copy application code
COPY server.js .

# Create files directory for path traversal testing
RUN mkdir -p /app/files && \
    echo "Public file content" > /app/files/public.txt && \
    echo "SECRET_API_KEY=sk_live_12345" > /app/files/../.env

EXPOSE 3000

CMD ["node", "server.js"]
