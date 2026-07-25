# Deploy the Domain Blacklist Checker anywhere that runs Docker.
#
#   docker build -t blacklist-checker .
#   docker run -p 3000:3000 -e DBC_RESOLVERS=1.1.1.1 blacklist-checker
#
# For accurate results on key-required lists, point DBC_RESOLVERS at your own
# recursive resolver and set DBC_TRUST_KEYED=true (see SHARING.md / README).
FROM node:22-alpine

WORKDIR /app

# Install production dependencies first (better layer caching).
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

# App source.
COPY src ./src
COPY public ./public

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3000
EXPOSE 3000

CMD ["node", "src/server.js"]
