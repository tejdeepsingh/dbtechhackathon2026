FROM node:22-alpine

WORKDIR /app

COPY server.mjs .

ENV PORT=8080
ENV OSV_API_BASE=https://api.osv.dev
ENV OSV_TIMEOUT_MS=30000

EXPOSE 8080

CMD ["node", "server.mjs"]
