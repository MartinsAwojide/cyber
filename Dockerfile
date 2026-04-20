# Build frontend
FROM node:20-alpine AS frontend-build
WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ .
RUN npm run build

# Production image
FROM python:3.12-slim
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv for Python package management
RUN pip install uv

# Copy Python dependencies and install
COPY backend/pyproject.toml backend/uv.lock* ./
RUN uv sync --frozen
# Copy backend source
COPY backend/ ./

# Copy Next.js static export (from 'out' directory)
COPY --from=frontend-build /app/out ./static

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port for Cloud Run / Azure Container Instances
EXPOSE 8000

# Secrets are not in this image. Pass them at run time (no compose file required).
#
# Build:
#   docker build -t cyber-analyzer .
#
# Run (replace values; never commit real keys):
#   docker run --rm -p 8000:8000 \
#     -e OPENROUTER_API_KEY="sk-or-v1-..." \
#     -e SEMGREP_APP_TOKEN="..." \
#     -e ENVIRONMENT=production \
#     cyber-analyzer
#
# Or use a host env file (keep .env out of the image and out of git):
#   docker run --rm -p 8000:8000 --env-file .env cyber-analyzer
#
# Optional: OPENROUTER_BASE_URL (defaults in app), OPENROUTER_MODEL, etc.
#
# Check a variable inside the running container:
#   docker exec <container_id> printenv OPENROUTER_API_KEY

# Start the FastAPI server
CMD ["uv", "run", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]