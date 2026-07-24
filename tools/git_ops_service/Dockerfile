FROM node:22-alpine

WORKDIR /app

COPY server.mjs .

ENV PORT=8080
ENV GIT_PROVIDER=forgejo
ENV FORGEJO_BASE_URL=http://forgejo:3000

EXPOSE 8080

CMD ["node", "server.mjs"]
