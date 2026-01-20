#!/bin/bash
# scripts/setup_environment.sh

# ============================================================================
# CYBERGUARD WEB SECURITY AI - ENVIRONMENT SETUP SCRIPT
# ============================================================================
# This script sets up the complete development/production environment
# for the CyberGuard cybersecurity AI system.
#
# Features:
# - Python virtual environment creation
# - Dependency installation with version validation
# - Directory structure initialization
# - Threat intelligence feed download
# - Database initialization
# - Security configuration setup
# ============================================================================

set -e  # Exit immediately if any command fails
set -u  # Treat unset variables as errors

# Color codes for better output readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           CYBERGUARD ENVIRONMENT SETUP                       ║"
    echo "║           Web Security AI System                             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check if running as root (not recommended)
check_root() {
    if [ "$EUID" -eq 0 ]; then 
        log_warning "Running as root. It's recommended to run as a regular user."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Check system requirements
check_system_requirements() {
    log_info "Checking system requirements..."
    
    # Check if running on supported OS
    if [[ "$OSTYPE" != "linux-gnu"* ]] && [[ "$OSTYPE" != "darwin"* ]]; then
        log_error "Unsupported operating system: $OSTYPE"
        log_error "CyberGuard requires Linux or macOS"
        exit 1
    fi
    
    # Check available memory (minimum 4GB recommended)
    total_memory=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$total_memory" -lt 4 ]; then
        log_warning "Low memory detected: ${total_memory}GB"
        log_warning "CyberGuard recommends at least 4GB of RAM for optimal performance"
    fi
    
    # Check disk space (minimum 10GB free)
    free_space=$(df -BG . | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$free_space" -lt 10 ]; then
        log_warning "Low disk space: ${free_space}GB free"
        log_warning "At least 10GB free space is recommended"
    fi
    
    log_success "System requirements check passed"
}

# Check Python version and installation
check_python() {
    log_info "Checking Python installation..."
    
    # Check if Python 3 is installed
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        log_error "Please install Python 3.10 or higher"
        exit 1
    fi
    
    # Get Python version
    python_version=$(python3 --version 2>&1 | awk '{print $2}')
    required_version="3.10"
    
    # Compare versions
    if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
        log_error "Python $required_version or higher is required. Found: $python_version"
        exit 1
    fi
    
    # Check for required Python modules
    if ! python3 -c "import venv" 2>/dev/null; then
        log_error "Python venv module not available"
        log_error "Install python3-venv or equivalent package"
        exit 1
    fi
    
    log_success "Python $python_version detected (✓)"
}

# Create virtual environment
create_virtualenv() {
    log_info "Creating Python virtual environment..."
    
    # Check if venv already exists
    if [ -d "venv" ]; then
        log_warning "Virtual environment already exists"
        read -p "Recreate virtual environment? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Removing existing virtual environment..."
            rm -rf venv
        else
            log_info "Using existing virtual environment"
            return 0
        fi
    fi
    
    # Create new virtual environment
    python3 -m venv venv
    
    if [ $? -eq 0 ]; then
        log_success "Virtual environment created successfully"
    else
        log_error "Failed to create virtual environment"
        exit 1
    fi
}

# Activate virtual environment
activate_virtualenv() {
    log_info "Activating virtual environment..."
    
    # Different activation for different shells
    if [ -f "venv/bin/activate" ]; then
        source venv/bin/activate
        
        # Verify activation
        if [ -z "${VIRTUAL_ENV:-}" ]; then
            log_error "Virtual environment activation failed"
            exit 1
        fi
        
        log_success "Virtual environment activated (✓)"
        log_info "Python path: $(which python3)"
        log_info "Pip path: $(which pip3)"
    else
        log_error "Virtual environment activation script not found"
        exit 1
    fi
}

# Upgrade pip and setuptools
upgrade_pip() {
    log_info "Upgrading pip and setuptools..."
    
    # Upgrade pip
    pip3 install --upgrade pip --no-cache-dir
    
    # Upgrade setuptools and wheel
    pip3 install --upgrade setuptools wheel --no-cache-dir
    
    log_success "Pip and setuptools upgraded (✓)"
}

# Install dependencies
install_dependencies() {
    log_info "Installing dependencies from requirements.txt..."
    
    # Check if requirements file exists
    if [ ! -f "requirements.txt" ]; then
        log_error "requirements.txt not found"
        exit 1
    fi
    
    # Install dependencies
    pip3 install -r requirements.txt --no-cache-dir
    
    if [ $? -eq 0 ]; then
        log_success "Dependencies installed successfully (✓)"
    else
        log_error "Failed to install dependencies"
        exit 1
    fi
    
    # Verify critical packages
    log_info "Verifying critical packages..."
    
    critical_packages=("torch" "fastapi" "requests" "beautifulsoup4" "pydantic")
    
    for package in "${critical_packages[@]}"; do
        if pip3 show "$package" &> /dev/null; then
            log_success "  $package installed (✓)"
        else
            log_error "  $package not installed (✗)"
            exit 1
        fi
    done
}

# Create directory structure
create_directory_structure() {
    log_info "Creating directory structure..."
    
    # Main directories
    directories=(
        # Log directories
        "logs/security"
        "logs/agent"
        "logs/audit"
        "logs/system"
        
        # Data directories
        "data/threat_feeds"
        "data/cve_database"
        "data/attack_patterns"
        "data/quarantined"
        "data/cache"
        "data/embeddings"
        
        # Model directories
        "models/trained"
        "models/checkpoints"
        "models/pretrained"
        
        # Configuration directories
        "config/backups"
        "config/templates"
        
        # Test directories
        "tests/data"
        "tests/results"
        
        # Documentation directories
        "docs/images"
        "docs/api"
        
        # Temporary directories
        "tmp/uploads"
        "tmp/processing"
        "tmp/exports"
    )
    
    # Create each directory
    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            log_success "  Created: $dir"
        else
            log_info "  Exists: $dir"
        fi
    done
    
    # Set appropriate permissions (where needed)
    chmod 750 "logs/"
    chmod 750 "data/quarantined/"
    chmod 700 "tmp/"
    
    log_success "Directory structure created (✓)"
}

# Download threat intelligence feeds
download_threat_feeds() {
    log_info "Downloading threat intelligence feeds..."
    
    # Create threat feed directory if it doesn't exist
    mkdir -p data/threat_feeds
    
    # Threat feed URLs (publicly available security feeds)
    declare -A threat_feeds=(
        ["mitre_cve"]="https://cve.mitre.org/data/downloads/allitems.csv"
        ["exploit_db"]="https://raw.githubusercontent.com/vulnersCom/vulners-whitelist/master/exploitdb.csv"
        ["feodo_tracker"]="https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
        ["ssl_blacklist"]="https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
        ["malware_domain_list"]="https://www.malwaredomainlist.com/hostslist/hosts.txt"
        ["openphish"]="https://openphish.com/feed.txt"
        ["cybercrime_tracker"]="https://cybercrime-tracker.net/all.php"
        ["botvrij"]="https://www.botvrij.eu/data/ioclist.high"
    )
    
    # Download each feed with error handling
    for feed_name in "${!threat_feeds[@]}"; do
        url="${threat_feeds[$feed_name]}"
        output_file="data/threat_feeds/${feed_name}_$(date +%Y%m%d).csv"
        
        log_info "  Downloading: $feed_name"
        
        # Use curl with timeout and retry logic
        if curl -s --max-time 30 --retry 3 --retry-delay 5 -o "$output_file" "$url"; then
            # Check if file was actually downloaded (not empty or error page)
            if [ -s "$output_file" ]; then
                file_size=$(wc -c < "$output_file" | awk '{print $1}')
                log_success "    Downloaded: $feed_name ($((file_size/1024)) KB)"
                
                # Create symbolic link to latest version
                ln -sf "$output_file" "data/threat_feeds/${feed_name}_latest.csv"
            else
                log_warning "    Empty file downloaded for: $feed_name"
                rm -f "$output_file"
            fi
        else
            log_warning "    Failed to download: $feed_name"
        fi
        
        # Small delay to avoid overwhelming servers
        sleep 1
    done
    
    log_success "Threat intelligence feeds downloaded (✓)"
}

# Initialize database
initialize_database() {
    log_info "Initializing database..."
    
    # Check if initialization script exists
    if [ -f "scripts/init_database.py" ]; then
        log_info "  Running database initialization script..."
        
        # Run with error handling
        if python3 scripts/init_database.py; then
            log_success "  Database initialized successfully (✓)"
        else
            log_error "  Database initialization failed"
            exit 1
        fi
    else
        log_warning "  Database initialization script not found"
        log_info "  Creating basic database structure..."
        
        # Create basic SQLite database structure
        sqlite_file="data/cyberguard.db"
        
        if [ ! -f "$sqlite_file" ]; then
            cat > /tmp/create_db.sql << EOF
-- CyberGuard Database Schema
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    risk_score REAL,
    threat_level TEXT,
    vulnerabilities_count INTEGER,
    report_path TEXT
);

CREATE TABLE IF NOT EXISTS threats_detected (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    threat_type TEXT,
    severity TEXT,
    description TEXT,
    location TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan_results(id)
);

CREATE TABLE IF NOT EXISTS agent_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT,
    activity_type TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details TEXT
);

CREATE INDEX idx_scan_date ON scan_results(scan_date);
CREATE INDEX idx_threat_type ON threats_detected(threat_type);
CREATE INDEX idx_agent_activity ON agent_activity(agent_id, timestamp);
EOF
            
            if command -v sqlite3 &> /dev/null; then
                sqlite3 "$sqlite_file" < /tmp/create_db.sql
                log_success "  Basic database created: $sqlite_file"
            else
                log_warning "  sqlite3 not found, skipping database creation"
            fi
        fi
    fi
}

# Generate default configuration files
generate_default_configs() {
    log_info "Generating default configuration files..."
    
    # Check if config directory exists
    if [ ! -d "config" ]; then
        mkdir -p config
    fi
    
    # Generate enterprise configuration if it doesn't exist
    if [ ! -f "config/enterprise_config.yaml" ]; then
        cat > config/enterprise_config.yaml << 'EOF'
# CyberGuard Enterprise Configuration
# Auto-generated on $(date)

system:
  name: "CyberGuard Web Security AI System"
  version: "1.0.0"
  environment: "development"
  log_level: "INFO"

dashboard:
  port: 8080
  host: "127.0.0.1"
  auth_required: false
  ssl_enabled: false

api:
  port: 8000
  host: "127.0.0.1"
  rate_limit: "100/minute"
  cors_origins: ["http://localhost:8080"]

security:
  max_scan_depth: 2
  scan_timeout: 30
  request_timeout: 10
  user_agent: "CyberGuard-Security-Scanner/1.0"

agents:
  threat_detection:
    confidence_threshold: 0.6
    max_findings: 20
  
  traffic_anomaly:
    window_size: 100
    anomaly_threshold: 3.0

logging:
  console_level: "INFO"
  file_level: "DEBUG"
  max_file_size: "10MB"
  backup_count: 5
EOF
        log_success "  Created: config/enterprise_config.yaml"
    fi
    
    # Generate environment file template
    if [ ! -f ".env.example" ]; then
        cat > .env.example << 'EOF'
# CyberGuard Environment Variables
# Copy this file to .env and update the values

# API Keys (if using external services)
# OPENAI_API_KEY=sk-...
# VIRUSTOTAL_API_KEY=...
# ABUSEIPDB_API_KEY=...

# Database Configuration
DATABASE_URL=sqlite:///data/cyberguard.db
# DATABASE_URL=postgresql://user:password@localhost/cyberguard

# Redis Configuration (for caching)
REDIS_URL=redis://localhost:6379/0

# Security Configuration
SECRET_KEY=$(openssl rand -hex 32)  # Generate a secure key
JWT_SECRET_KEY=$(openssl rand -hex 32)

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=logs/cyberguard.log

# Server Configuration
HOST=0.0.0.0
PORT=8000
WORKERS=4

# Feature Flags
ENABLE_THREAT_FEEDS=true
ENABLE_REAL_TIME_SCANNING=true
ENABLE_AGENT_COORDINATION=true
EOF
        log_success "  Created: .env.example"
    fi
    
    # Copy example to .env if it doesn't exist
    if [ ! -f ".env" ]; then
        cp .env.example .env
        log_warning "  Created .env from template. Please update with your configuration."
    fi
}

# Run basic tests
run_basic_tests() {
    log_info "Running basic system tests..."
    
    # Check if pytest is installed
    if ! command -v pytest &> /dev/null; then
        log_warning "pytest not found, installing..."
        pip3 install pytest pytest-asyncio pytest-cov
    fi
    
    # Run a simple test to verify installation
    cat > /tmp/test_cyberguard.py << 'EOF'
#!/usr/bin/env python3
"""Basic CyberGuard system test"""

import sys
import os

def test_imports():
    """Test that critical modules can be imported"""
    modules = [
        'torch',
        'fastapi',
        'pydantic',
        'requests',
        'beautifulsoup4',
        'yaml',
        'json',
        'logging'
    ]
    
    for module in modules:
        try:
            __import__(module)
            print(f"✓ {module}")
        except ImportError as e:
            print(f"✗ {module}: {e}")
            return False
    
    return True

def test_directories():
    """Test that required directories exist"""
    required_dirs = [
        'config',
        'logs',
        'data',
        'models'
    ]
    
    for directory in required_dirs:
        if os.path.exists(directory):
            print(f"✓ Directory: {directory}")
        else:
            print(f"✗ Missing directory: {directory}")
            return False
    
    return True

if __name__ == "__main__":
    print("Running CyberGuard system tests...")
    print("-" * 50)
    
    success = True
    
    if not test_imports():
        success = False
    
    if not test_directories():
        success = False
    
    print("-" * 50)
    
    if success:
        print("All tests passed! ✓")
        sys.exit(0)
    else:
        print("Some tests failed! ✗")
        sys.exit(1)
EOF
    
    # Run the test
    if python3 /tmp/test_cyberguard.py; then
        log_success "Basic tests passed (✓)"
    else
        log_error "Basic tests failed"
        exit 1
    fi
}

# Display completion message
display_completion() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           SETUP COMPLETE!                                    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo ""
    echo "🚀 CyberGuard is ready to use!"
    echo ""
    echo "📋 Available commands:"
    echo "  source venv/bin/activate              # Activate virtual environment"
    echo "  python main.py --mode interactive     # Interactive console mode"
    echo "  python main.py --mode dashboard       # Start web dashboard"
    echo "  python main.py --mode api             # Start REST API"
    echo "  python scripts/run_security_scan.py   # Run security scan"
    echo ""
    echo "🌐 Dashboard: http://localhost:8080"
    echo "🔧 API Docs: http://localhost:8000/docs"
    echo ""
    echo "📁 Important directories:"
    echo "  config/          - Configuration files"
    echo "  logs/            - Log files"
    echo "  data/            - Data and threat feeds"
    echo "  models/          - Trained models"
    echo ""
    echo "⚠️  Next steps:"
    echo "  1. Review config/enterprise_config.yaml"
    echo "  2. Update .env with your API keys (if needed)"
    echo "  3. Run: python scripts/update_threat_feeds.sh (to update feeds)"
    echo ""
}

# Main execution flow
main() {
    print_banner
    check_root
    check_system_requirements
    check_python
    create_virtualenv
    activate_virtualenv
    upgrade_pip
    install_dependencies
    create_directory_structure
    download_threat_feeds
    initialize_database
    generate_default_configs
    run_basic_tests
    display_completion
}

# Run main function with error handling
if main; then
    exit 0
else
    log_error "Setup failed. Check the logs above for details."
    exit 1
fi