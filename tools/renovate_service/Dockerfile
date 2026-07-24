FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    openssh-client \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g renovate

WORKDIR /app

COPY server.mjs .

ENV PORT=8080
ENV RENOVATE_PLATFORM=forgejo
ENV RENOVATE_ENDPOINT=http://forgejo:3000/api/v1
ENV RENOVATE_DRY_RUN=full
ENV RENOVATE_TIMEOUT_MS=300000

EXPOSE 8080

CMD ["node", "server.mjs"]
