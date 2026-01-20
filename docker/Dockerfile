# docker/Dockerfile

# ==============================================================================
# CYBERGUARD DOCKERFILE - PRODUCTION-GRADE WEB SECURITY AI SYSTEM
# ==============================================================================

# Stage 1: Builder - For compiling dependencies and building the application
# ==============================================================================
FROM python:3.11-slim-bookworm AS builder

# ARG - Build arguments that can be passed during build time
ARG DEBIAN_FRONTEND=noninteractive
ARG USER_ID=1000
ARG GROUP_ID=1000
ARG APP_ENV=production
ARG GIT_COMMIT=unknown

# ENV - Environment variables available in the container
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_VERSION=1.6.1 \
    POETRY_HOME="/opt/poetry" \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    PATH="$POETRY_HOME/bin:$PATH" \
    APP_ENV=${APP_ENV} \
    GIT_COMMIT=${GIT_COMMIT}

# LABEL - Metadata for the image (visible with docker inspect)
LABEL maintainer="security@cyberguard.ai" \
      org.label-schema.name="CyberGuard" \
      org.label-schema.description="Intelligent Web Threat Analysis & Defense Platform" \
      org.label-schema.version="1.0.0" \
      org.label-schema.build-date="${BUILD_DATE}" \
      org.label-schema.vcs-ref="${GIT_COMMIT}" \
      org.label-schema.vcs-url="https://github.com/cyberguard/cyberguard" \
      org.label-schema.schema-version="1.0"

# WORKDIR - Sets the working directory for subsequent commands
WORKDIR /app

# RUN - Executes commands in the container during build
# Update package list and install system dependencies
RUN apt-get update && apt-get upgrade -y && \
    # Install system dependencies required for Python packages and security tools
    apt-get install -y --no-install-recommends \
    # Compilation tools for building Python extensions
    gcc \
    g++ \
    # Database client libraries
    libpq-dev \
    libmariadb-dev \
    # SSL/TLS libraries
    libssl-dev \
    libffi-dev \
    # Compression libraries
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    llvm \
    libncurses5-dev \
    libncursesw5-dev \
    xz-utils \
    tk-dev \
    libgdbm-dev \
    libnss3-dev \
    libedit-dev \
    libc6-dev \
    # Networking tools
    curl \
    wget \
    netcat \
    iputils-ping \
    dnsutils \
    # Process monitoring
    procps \
    # Text processing
    vim \
    # Git for version control
    git \
    # Clean up apt cache to reduce image size
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry for dependency management
RUN curl -sSL https://install.python-poetry.org | python3 -

# Copy dependency files first (for better Docker layer caching)
COPY pyproject.toml poetry.lock ./

# Install Python dependencies with Poetry
RUN poetry install \
    --no-dev \
    --no-interaction \
    --no-ansi \
    --no-root \
    # Skip installing the project itself
    && rm -rf "$POETRY_HOME"

# Stage 2: Runtime - Minimal image for running the application
# ==============================================================================
FROM python:3.11-slim-bookworm AS runtime

# Security hardening: Run as non-root user
ARG USER_ID=1000
ARG GROUP_ID=1000
ARG APP_ENV=production

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/home/cyberguard/.local/bin:$PATH" \
    APP_ENV=${APP_ENV} \
    PYTHONPATH="/app/src:/app"

# Create a non-root user for security
RUN groupadd -g ${GROUP_ID} cyberguard && \
    useradd -m -u ${USER_ID} -g cyberguard -s /bin/bash cyberguard

WORKDIR /app

# Copy only necessary files from builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Install runtime system dependencies (minimal set)
RUN apt-get update && apt-get install -y --no-install-recommends \
    # SSL certificates for HTTPS requests
    ca-certificates \
    # Database client runtime libraries
    libpq5 \
    # Monitoring tools
    curl \
    # Clean up
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY --chown=cyberguard:cyberguard . .

# Create necessary directories with proper permissions
RUN mkdir -p logs/security logs/agent logs/audit && \
    mkdir -p data/threat_feeds data/cve_database data/attack_patterns data/quarantined && \
    mkdir -p models/trained models/checkpoints && \
    chown -R cyberguard:cyberguard /app && \
    chmod -R 755 /app && \
    # Make scripts executable
    chmod +x scripts/*.sh

# Switch to non-root user
USER cyberguard

# HEALTHCHECK - Container health monitoring
HEALTHCHECK --interval=30s \
            --timeout=3s \
            --start-period=10s \
            --retries=3 \
            CMD python -c "import requests; requests.get('http://localhost:8080/health', timeout=2)" || exit 1

# EXPOSE - Document which ports the container listens on
# Dashboard port
EXPOSE 8080 
# API port 
EXPOSE 8000  
# Database port (if running locally)
EXPOSE 5432  

# VOLUME - Define mount points for persistent data
VOLUME ["/app/logs", "/app/data", "/app/models"]

# ENTRYPOINT - Main command that runs when container starts
ENTRYPOINT ["python", "main.py"]

# CMD - Default arguments passed to ENTRYPOINT
CMD ["--mode", "api"]