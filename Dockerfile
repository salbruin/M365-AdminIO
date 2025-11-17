# M365 OneDrive Security Scanner Docker Image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY scanner.py .
COPY config/ ./config/ 2>/dev/null || true

# Create directories for logs and reports
RUN mkdir -p /app/logs /app/reports

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Default command
CMD ["python", "scanner.py", "--help"]
