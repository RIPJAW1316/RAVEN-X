FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
    && python3 -m venv /opt/report-python \
    && /opt/report-python/bin/pip install --no-cache-dir 'reportlab==4.4.9' \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY server.mjs gemini.mjs reviews.mjs render_pdf.py fleet_pdf.py demo.json fleet.csv ./
COPY portal/ ./portal/
USER node
ENV PORT=8080 RAVENX_PDF_PYTHON=/opt/report-python/bin/python
EXPOSE 8080
CMD ["node", "server.mjs"]
