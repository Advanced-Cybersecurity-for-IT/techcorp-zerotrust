# PEP
FROM node:20-alpine

LABEL maintainer="TechCorp Security Team"
LABEL description="PEP - Policy Enforcement Point"

WORKDIR /app

RUN apk add --no-cache curl postgresql-client

COPY package.json .
RUN npm install --production

COPY pep.js .

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["node", "pep.js"]
