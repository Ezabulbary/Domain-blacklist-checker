# Deploy the Domain Blacklist Checker anywhere that runs Docker.
#
#   docker build -t blacklist-checker .
#   docker run -p 3000:3000 -e DBC_RESOLVERS=1.1.1.1 blacklist-checker
#
# For accurate Spamhaus results set DBC_DQS_KEY (free key, see .env.example).
# Only set DBC_TRUST_KEYED=true if you have paid/authorized access to the other
# key-required lists (Barracuda, Abusix, invaluement); otherwise leave it off.
FROM node:22-alpine

WORKDIR /app

# Install production dependencies first (better layer caching).
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

# App source. Owned by the unprivileged user so the app can write its
# calibration cache (.calibration.json) but nothing outside /app.
COPY --chown=node:node src ./src
COPY --chown=node:node public ./public
RUN chown node:node /app

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3000
EXPOSE 3000

# Never run the server as root. The stock node image ships a "node" user.
USER node

CMD ["node", "src/server.js"]
