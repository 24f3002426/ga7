FROM node:22-alpine AS deps

WORKDIR /app

COPY package*.json ./

FROM node:22-alpine AS runtime

WORKDIR /app

COPY --from=deps /app/package*.json ./
COPY server.js ./
COPY server.test.js ./

RUN addgroup -S appgroup \
    && adduser -S appuser -G appgroup \
    && chown -R appuser:appgroup /app

USER appuser

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["node", "server.js"]
