# ============================================================================
# CyberGuard Web Security AI System - Build and Deployment Automation
# ============================================================================

# ----------------------------------------------------------------------------
# CONFIGURATION VARIABLES
# ----------------------------------------------------------------------------

# Python configuration
PYTHON = python3
PIP = pip3
VENV_DIR = venv
PYTHON_VERSION = $(shell $(PYTHON) --version | cut -d' ' -f2)

# Project directories
SRC_DIR = src
TESTS_DIR = tests
CONFIG_DIR = config
SCRIPTS_DIR = scripts
DOCKER_DIR = docker
DOCS_DIR = docs
MODELS_DIR = models
DATA_DIR = data
LOGS_DIR = logs

# Docker configuration
DOCKER_IMAGE = cyberguard/security-ai
DOCKER_TAG = latest
DOCKER_PORT_API = 8000
DOCKER_PORT_DASHBOARD = 8080

# Testing configuration
TEST_PATTERN = test_*.py
COVERAGE_THRESHOLD = 80

# ----------------------------------------------------------------------------
# PHONY TARGETS (Don't represent files)
# ----------------------------------------------------------------------------
.PHONY: all help setup install clean test lint format security-scan \
        build-docker run-docker stop-docker push-docker deploy-local \
        deploy-production update-feeds monitor logs backup restore \
        train-model serve-api serve-dashboard

# ----------------------------------------------------------------------------
# PRIMARY TARGETS
# ----------------------------------------------------------------------------

# Default target: Show help
all: help

# Display help information
help:
	@echo "╔══════════════════════════════════════════════════════════════════════════════╗"
	@echo "║                     CyberGuard Web Security AI System                        ║"
	@echo "╠══════════════════════════════════════════════════════════════════════════════╣"
	@echo "║ Available Commands:                                                          ║"
	@echo "╠══════════════════════════════════════════════════════════════════════════════╣"
	@echo "║                                                                              ║"
	@echo "║ Development:                                                                 ║"
	@echo "║   make setup          - Initialize development environment                   ║"
	@echo "║   make install        - Install Python dependencies                         ║"
	@echo "║   make clean          - Clean build artifacts and cache                     ║"
	@echo "║   make test           - Run all tests with coverage                        ║"
	@echo "║   make lint           - Check code quality with linters                     ║"
	@echo "║   make format         - Format code with black and isort                    ║"
	@echo "║                                                                              ║"
	@echo "║ Security:                                                                     ║"
	@echo "║   make security-scan  - Run security vulnerability scans                    ║"
	@echo "║   make update-feeds   - Update threat intelligence feeds                    ║"
	@echo "║                                                                              ║"
	@echo "║ Docker Operations:                                                           ║"
	@echo "║   make build-docker   - Build Docker image                                 ║"
	@echo "║   make run-docker     - Run CyberGuard in Docker                           ║"
	@echo "║   make stop-docker    - Stop Docker containers                             ║"
	@echo "║   make push-docker    - Push Docker image to registry                      ║"
	@echo "║                                                                              ║"
	@echo "║ Deployment:                                                                   ║"
	@echo "║   make deploy-local    - Deploy locally for testing                         ║"
	@echo "║   make deploy-production - Deploy to production                            ║"
	@echo "║   make serve-api       - Start REST API server                             ║"
	@echo "║   make serve-dashboard - Start security dashboard                          ║"
	@echo "║                                                                              ║"
	@echo "║ Machine Learning:                                                             ║"
	@echo "║   make train-model    - Train security detection models                     ║"
	@echo "║                                                                              ║"
	@echo "║ Monitoring & Maintenance:                                                    ║"
	@echo "║   make monitor        - Monitor system health and performance              ║"
	@echo "║   make logs           - View system logs                                   ║"
	@echo "║   make backup         - Create backup of configurations and data           ║"
	@echo "║   make restore        - Restore from backup                               ║"
	@echo "║                                                                              ║"
	@echo "║ Documentation:                                                                ║"
	@echo "║   make docs           - Generate documentation                            ║"
	@echo "║                                                                              ║"
	@echo "╚══════════════════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "System Information:"
	@echo "  Python Version: $(PYTHON_VERSION)"
	@echo "  Virtual Environment: $(VENV_DIR)"
	@echo "  Source Directory: $(SRC_DIR)"
	@echo "  Docker Image: $(DOCKER_IMAGE):$(DOCKER_TAG)"

# ----------------------------------------------------------------------------
# DEVELOPMENT TARGETS
# ----------------------------------------------------------------------------

# Setup development environment
setup: check-python create-venv install download-data create-dirs init-db
	@echo ""
	@echo "✅ CyberGuard development environment setup complete!"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Activate virtual environment: source $(VENV_DIR)/bin/activate"
	@echo "  2. Run tests: make test"
	@echo "  3. Start development server: make serve-api"
	@echo ""

# Check Python version compatibility
check-python:
	@echo "🔍 Checking Python version..."
	@if [ "$(PYTHON_VERSION)" \< "3.10" ]; then \
		echo "❌ Python 3.10 or higher is required. Found: $(PYTHON_VERSION)"; \
		exit 1; \
	else \
		echo "✅ Python $(PYTHON_VERSION) is compatible"; \
	fi

# Create Python virtual environment
create-venv:
	@echo "📦 Creating virtual environment..."
	@$(PYTHON) -m venv $(VENV_DIR)
	@echo "✅ Virtual environment created in $(VENV_DIR)"

# Install Python dependencies
install: requirements.txt
	@echo "📥 Installing Python dependencies..."
	@$(VENV_DIR)/bin/$(PIP) install --upgrade pip
	@$(VENV_DIR)/bin/$(PIP) install -r requirements.txt
	@$(VENV_DIR)/bin/$(PIP) install -e .
	@echo "✅ Dependencies installed"

# Clean build artifacts and cache
clean:
	@echo "🧹 Cleaning build artifacts..."
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete
	@find . -type f -name "*.pyo" -delete
	@find . -type f -name ".coverage" -delete
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".ipynb_checkpoints" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name "build" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name "dist" -exec rm -rf {} + 2>/dev/null || true
	@echo "✅ Cleanup complete"

# Run all tests with coverage
test:
	@echo "🧪 Running tests with coverage..."
	@$(VENV_DIR)/bin/pytest $(TESTS_DIR)/ \
		-v \
		--cov=$(SRC_DIR) \
		--cov-report=term \
		--cov-report=html:coverage_html \
		--cov-report=xml:coverage.xml \
		--cov-fail-under=$(COVERAGE_THRESHOLD)
	@echo "✅ Tests completed with coverage report"

# Run linting checks
lint:
	@echo "📋 Running code quality checks..."
	@echo "Running flake8..."
	@$(VENV_DIR)/bin/flake8 $(SRC_DIR) $(TESTS_DIR) --count --show-source --statistics
	@echo "Running black (check only)..."
	@$(VENV_DIR)/bin/black --check $(SRC_DIR) $(TESTS_DIR)
	@echo "Running isort (check only)..."
	@$(VENV_DIR)/bin/isort --check-only $(SRC_DIR) $(TESTS_DIR)
	@echo "Running mypy..."
	@$(VENV_DIR)/bin/mypy $(SRC_DIR)
	@echo "✅ Linting checks completed"

# Format code with black and isort
format:
	@echo "🎨 Formatting code..."
	@$(VENV_DIR)/bin/black $(SRC_DIR) $(TESTS_DIR)
	@$(VENV_DIR)/bin/isort $(SRC_DIR) $(TESTS_DIR)
	@echo "✅ Code formatting completed"

# ----------------------------------------------------------------------------
# SECURITY TARGETS
# ----------------------------------------------------------------------------

# Run security vulnerability scans
security-scan:
	@echo "🔒 Running security vulnerability scans..."
	@echo "Scanning Python dependencies with safety..."
	@$(VENV_DIR)/bin/safety check --full-report
	@echo "Scanning for secrets with detect-secrets..."
	@$(VENV_DIR)/bin/detect-secrets scan --all-files
	@echo "Scanning with bandit..."
	@$(VENV_DIR)/bin/bandit -r $(SRC_DIR) -f txt
	@echo "✅ Security scans completed"

# Update threat intelligence feeds
update-feeds:
	@echo "📡 Updating threat intelligence feeds..."
	@$(VENV_DIR)/bin/$(PYTHON) $(SCRIPTS_DIR)/update_threat_feeds.py
	@echo "✅ Threat intelligence feeds updated"

# ----------------------------------------------------------------------------
# DOCKER OPERATIONS
# ----------------------------------------------------------------------------

# Build Docker image
build-docker:
	@echo "🐳 Building Docker image..."
	@docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) -f $(DOCKER_DIR)/Dockerfile .
	@echo "✅ Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)"

# Run CyberGuard in Docker
run-docker: build-docker
	@echo "🚀 Starting CyberGuard in Docker..."
	@docker run -d \
		--name cyberguard \
		-p $(DOCKER_PORT_API):8000 \
		-p $(DOCKER_PORT_DASHBOARD):8080 \
		-v $(PWD)/$(DATA_DIR):/app/data \
		-v $(PWD)/$(LOGS_DIR):/app/logs \
		--env-file .env \
		$(DOCKER_IMAGE):$(DOCKER_TAG)
	@echo "✅ CyberGuard running in Docker"
	@echo "   API: http://localhost:$(DOCKER_PORT_API)/docs"
	@echo "   Dashboard: http://localhost:$(DOCKER_PORT_DASHBOARD)"

# Stop Docker containers
stop-docker:
	@echo "🛑 Stopping Docker containers..."
	@docker stop cyberguard 2>/dev/null || true
	@docker rm cyberguard 2>/dev/null || true
	@echo "✅ Docker containers stopped"

# Push Docker image to registry
push-docker: build-docker
	@echo "📤 Pushing Docker image to registry..."
	@docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	@echo "✅ Docker image pushed to registry"

# ----------------------------------------------------------------------------
# DEPLOYMENT TARGETS
# ----------------------------------------------------------------------------

# Deploy locally for testing
deploy-local: stop-docker run-docker
	@echo "🏠 Local deployment complete"
	@echo "   API Documentation: http://localhost:8000/docs"
	@echo "   Security Dashboard: http://localhost:8080"

# Deploy to production (simplified example)
deploy-production:
	@echo "🚀 Deploying to production..."
	@echo "1. Building production image..."
	@docker build -t $(DOCKER_IMAGE):prod -f $(DOCKER_DIR)/Dockerfile.prod .
	@echo "2. Pushing to registry..."
	@docker push $(DOCKER_IMAGE):prod
	@echo "3. Updating Kubernetes deployment..."
	@kubectl apply -f $(K8S_DIR)/deployment.yaml
	@kubectl rollout status deployment/cyberguard
	@echo "✅ Production deployment complete"

# Start REST API server
serve-api:
	@echo "🌐 Starting REST API server..."
	@$(VENV_DIR)/bin/$(PYTHON) -m uvicorn src.ui.api.rest_api:app \
		--host 0.0.0.0 \
		--port 8000 \
		--reload \
		--log-level info

# Start security dashboard
serve-dashboard:
	@echo "📊 Starting security dashboard..."
	@$(VENV_DIR)/bin/$(PYTHON) -m streamlit run src/ui/frontend/dashboard.py \
		--server.port 8080 \
		--server.address 0.0.0.0 \
		--server.headless true \
		--theme.base dark

# ----------------------------------------------------------------------------
# MACHINE LEARNING TARGETS
# ----------------------------------------------------------------------------

# Train security detection models
train-model:
	@echo "🧠 Training security detection models..."
	@$(VENV_DIR)/bin/$(PYTHON) $(SRC_DIR)/training/train_pipeline.py \
		--config $(CONFIG_DIR)/training_config.yaml \
		--data $(DATA_DIR)/training \
		--output $(MODELS_DIR)/trained
	@echo "✅ Model training completed"

# ----------------------------------------------------------------------------
# MONITORING & MAINTENANCE
# ----------------------------------------------------------------------------

# Monitor system health and performance
monitor:
	@echo "📈 Monitoring system health..."
	@echo "CPU Usage:"
	@top -bn1 | grep "Cpu(s)" | awk '{print "  " $2 "%"}'
	@echo ""
	@echo "Memory Usage:"
	@free -h | awk 'NR==2{print "  Total: " $2 ", Used: " $3 ", Free: " $4}'
	@echo ""
	@echo "Disk Usage:"
	@df -h . | awk 'NR==2{print "  Used: " $3 "/" $2 " (" $5 ")"}'
	@echo ""
	@echo "Active Docker Containers:"
	@docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "  Docker not running"

# View system logs
logs:
	@echo "📋 Viewing system logs..."
	@echo "=== Application Logs ==="
	@tail -20 $(LOGS_DIR)/application.log 2>/dev/null || echo "No application logs found"
	@echo ""
	@echo "=== Security Logs ==="
	@tail -20 $(LOGS_DIR)/security.log 2>/dev/null || echo "No security logs found"
	@echo ""
	@echo "=== Error Logs ==="
	@tail -20 $(LOGS_DIR)/error.log 2>/dev/null || echo "No error logs found"

# Create backup of configurations and data
backup:
	@echo "💾 Creating system backup..."
	@mkdir -p backups
	@timestamp=$$(date +%Y%m%d_%H%M%S); \
	backup_file="backups/cyberguard_backup_$$timestamp.tar.gz"; \
	tar -czf $$backup_file \
		$(CONFIG_DIR) \
		$(DATA_DIR)/cve_database \
		$(DATA_DIR)/threat_patterns \
		$(MODELS_DIR)/trained \
		.env.example \
		requirements.txt; \
	echo "✅ Backup created: $$backup_file"

# Restore from backup
restore:
	@echo "🔄 Restoring from backup..."
	@if [ -z "$(BACKUP_FILE)" ]; then \
		echo "Usage: make restore BACKUP_FILE=backups/backup_file.tar.gz"; \
		exit 1; \
	fi; \
	if [ ! -f "$(BACKUP_FILE)" ]; then \
		echo "❌ Backup file not found: $(BACKUP_FILE)"; \
		exit 1; \
	fi; \
	tar -xzf $(BACKUP_FILE); \
	echo "✅ Restore completed from $(BACKUP_FILE)"

# ----------------------------------------------------------------------------
# UTILITY TARGETS
# ----------------------------------------------------------------------------

# Create necessary directories
create-dirs:
	@echo "📁 Creating directory structure..."
	@mkdir -p $(CONFIG_DIR)
	@mkdir -p $(SRC_DIR)
	@mkdir -p $(TESTS_DIR)
	@mkdir -p $(SCRIPTS_DIR)
	@mkdir -p $(DOCKER_DIR)
	@mkdir -p $(DOCS_DIR)
	@mkdir -p $(MODELS_DIR)/trained
	@mkdir -p $(MODELS_DIR)/checkpoints
	@mkdir -p $(DATA_DIR)/threat_feeds
	@mkdir -p $(DATA_DIR)/cve_database
	@mkdir -p $(DATA_DIR)/attack_patterns
	@mkdir -p $(DATA_DIR)/quarantined
	@mkdir -p $(LOGS_DIR)/security
	@mkdir -p $(LOGS_DIR)/agent
	@mkdir -p $(LOGS_DIR)/audit
	@echo "✅ Directory structure created"

# Download sample data
download-data:
	@echo "📥 Downloading sample data..."
	@if [ ! -f "$(DATA_DIR)/cve_database/cve_latest.json" ]; then \
		echo "Downloading CVE database..."; \
		curl -s -o $(DATA_DIR)/cve_database/cve_latest.json \
			https://cve.circl.lu/api/last; \
	fi
	@echo "✅ Sample data downloaded"

# Initialize database
init-db:
	@echo "🗄️ Initializing database..."
	@$(VENV_DIR)/bin/$(PYTHON) $(SCRIPTS_DIR)/init_database.py
	@echo "✅ Database initialized"

# Generate documentation
docs:
	@echo "📚 Generating documentation..."
	@$(VENV_DIR)/bin/pdoc --html $(SRC_DIR) --output-dir $(DOCS_DIR)/api
	@echo "✅ Documentation generated in $(DOCS_DIR)/api"

# FILE DEPENDENCIES

# Ensure requirements.txt exists
requirements.txt:
	@if [ ! -f "requirements.txt" ]; then \
		echo "❌ requirements.txt not found"; \
		exit 1; \
	fi