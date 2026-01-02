FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache curl

COPY package.json .
RUN npm install --production

COPY web-server.js .

EXPOSE 8080

CMD ["node", "web-server.js"]
