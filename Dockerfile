FROM python:3.12-slim

# System deps for Playwright, Node.js (Retire.js), and postgres client
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gnupg ca-certificates git \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Node dependencies (Retire.js)
COPY package.json package-lock.json* ./
RUN npm install --production

# Application source
COPY src/ src/
COPY api/ api/
COPY web/ web/
COPY scripts/ scripts/
COPY config.json.template config.json

# Create directories
RUN mkdir -p reports downloads

# Start script (migrations + uvicorn; uses PORT from env for Render)
RUN chmod +x scripts/start.sh

EXPOSE 8000
CMD ["sh", "scripts/start.sh"]
