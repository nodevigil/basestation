FROM python:3.12-slim

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y \
    # Basic tools
    curl \
    wget \
    git \
    sudo \
    # Network and security scanning tools
    nmap \
    whatweb \
    ssl-cert \
    openssl \
    # Database client
    postgresql-client \
    # Build tools for Python packages
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create app user (non-root for security, but with sudo access for nmap)
RUN useradd -m -s /bin/bash appuser && \
    echo "appuser ALL=(ALL) NOPASSWD: /usr/bin/nmap" >> /etc/sudoers

# Set work directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Change ownership of app directory
RUN chown -R appuser:appuser /app

# Switch to app user
USER appuser

# Set Python path
ENV PYTHONPATH=/app

# Default command
CMD ["pgdn", "--help"]
