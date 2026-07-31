FROM oven/bun:1.3.14-alpine
WORKDIR /app
COPY package.json ./
COPY src ./src
USER bun
EXPOSE 2525
CMD ["bun", "src/index.ts"]
