FROM node:24-alpine
WORKDIR /app
COPY server.mjs demo.json *.pdf fleet.csv ./
COPY portal/ ./portal/
USER node
ENV PORT=8080
EXPOSE 8080
CMD ["node", "server.mjs"]
