#!/bin/bash
# scripts/deploy_cyberguard.sh

# ============================================================================
# CYBERGUARD DEPLOYMENT SCRIPT
# ============================================================================
# This script handles deployment of CyberGuard in various environments:
# - Development (local)
# - Staging (test environment)
# - Production (live deployment)
#
# Features:
# - Environment-specific configuration
# - Docker container deployment
# - Database migrations
# - Security hardening
# - Rollback capability
# ============================================================================

set -e  # Exit immediately on error
set -u  # Treat unset variables as error

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color

# Configuration
DEPLOYMENT_DIR="/opt/cyberguard"
BACKUP_DIR="/opt/cyberguard_backups"
LOG_DIR="/var/log/cyberguard"
CONFIG_DIR="/etc/cyberguard"
VENV_PATH="$DEPLOYMENT_DIR/venv"

# Deployment environments
declare -A ENVIRONMENTS=(
    ["dev"]="Development"
    ["staging"]="Staging"
    ["prod"]="Production"
)

# Logging function
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "${BLUE}[$timestamp] [INFO]${NC} $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[$timestamp] [SUCCESS]${NC} $message"
            ;;
        "WARNING")
            echo -e "${YELLOW}[$timestamp] [WARNING]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[$timestamp] [ERROR]${NC} $message"
            ;;
    esac
    
    # Also log to file
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/deploy.log"
}

# Print usage information
print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Deploy CyberGuard Web Security AI System"
    echo ""
    echo "Options:"
    echo "  -e, --environment    Deployment environment (dev|staging|prod)"
    echo "  -m, --mode           Deployment mode (docker|systemd|manual)"
    echo "  -c, --config         Path to deployment configuration file"
    echo "  -b, --backup         Enable backup before deployment"
    echo "  -v, --version        Deploy specific version (git tag or commit)"
    echo "  -r, --rollback       Rollback to previous version"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -e dev -m docker           # Deploy dev environment using Docker"
    echo "  $0 -e prod -m systemd         # Deploy production with systemd"
    echo "  $0 -e staging -r              # Rollback staging environment"
    echo ""
}

# Validate command line arguments
validate_arguments() {
    local environment=$1
    local mode=$2
    
    # Validate environment
    if [[ ! "${!ENVIRONMENTS[@]}" =~ $environment ]]; then
        log "ERROR" "Invalid environment: $environment"
        log "ERROR" "Valid environments: ${!ENVIRONMENTS[*]}"
        exit 1
    fi
    
    # Validate deployment mode
    if [[ ! "$mode" =~ ^(docker|systemd|manual)$ ]]; then
        log "ERROR" "Invalid deployment mode: $mode"
        log "ERROR" "Valid modes: docker, systemd, manual"
        exit 1
    fi
    
    log "INFO" "Validated arguments: environment=$environment, mode=$mode"
}

# Check system requirements for deployment
check_deployment_requirements() {
    log "INFO" "Checking deployment requirements..."
    
    # Check if running as root (required for system deployments)
    if [ "$EUID" -ne 0 ] && [ "$DEPLOYMENT_MODE" != "docker" ]; then
        log "ERROR" "System deployments require root privileges"
        exit 1
    fi
    
    # Check required commands
    local required_commands=("git" "python3" "pip3")
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log "ERROR" "Required command not found: $cmd"
            exit 1
        fi
    done
    
    # Check Docker if using docker mode
    if [ "$DEPLOYMENT_MODE" = "docker" ]; then
        if ! command -v docker &> /dev/null; then
            log "ERROR" "Docker is required for docker deployment mode"
            exit 1
        fi
        
        if ! docker info &> /dev/null; then
            log "ERROR" "Docker daemon is not running"
            exit 1
        fi
    fi
    
    # Check disk space (minimum 5GB free)
    local free_space=$(df -BG "$DEPLOYMENT_DIR" 2>/dev/null | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ -n "$free_space" ] && [ "$free_space" -lt 5 ]; then
        log "WARNING" "Low disk space: ${free_space}GB free in $DEPLOYMENT_DIR"
    fi
    
    log "SUCCESS" "Deployment requirements satisfied"
}

# Create deployment directories
create_deployment_directories() {
    log "INFO" "Creating deployment directories..."
    
    # List of directories to create
    local directories=(
        "$DEPLOYMENT_DIR"
        "$BACKUP_DIR"
        "$LOG_DIR"
        "$CONFIG_DIR"
        "$DEPLOYMENT_DIR/data"
        "$DEPLOYMENT_DIR/models"
        "$DEPLOYMENT_DIR/logs"
        "$BACKUP_DIR/configs"
        "$BACKUP_DIR/databases"
    )
    
    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            chmod 755 "$dir"
            log "INFO" "  Created directory: $dir"
        fi
    done
    
    # Set ownership for web deployment
    if [ "$DEPLOYMENT_ENVIRONMENT" = "prod" ]; then
        if id "cyberguard" &>/dev/null; then
            chown -R cyberguard:cyberguard "$DEPLOYMENT_DIR"
            chown -R cyberguard:cyberguard "$LOG_DIR"
        fi
    fi
    
    log "SUCCESS" "Deployment directories created"
}

# Backup current deployment
backup_current_deployment() {
    if [ "$ENABLE_BACKUP" != "true" ]; then
        log "INFO" "Skipping backup (disabled)"
        return 0
    fi
    
    log "INFO" "Creating backup of current deployment..."
    
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local backup_path="$BACKUP_DIR/deployment_$timestamp"
    
    # Create backup directory
    mkdir -p "$backup_path"
    
    # Backup important directories
    local backup_items=(
        "$DEPLOYMENT_DIR/config"
        "$DEPLOYMENT_DIR/data"
        "$DEPLOYMENT_DIR/models"
        "$CONFIG_DIR"
    )
    
    for item in "${backup_items[@]}"; do
        if [ -d "$item" ]; then
            cp -r "$item" "$backup_path/"
            log "INFO" "  Backed up: $item"
        fi
    done
    
    # Backup database if exists
    if [ -f "$DEPLOYMENT_DIR/data/cyberguard.db" ]; then
        cp "$DEPLOYMENT_DIR/data/cyberguard.db" "$backup_path/cyberguard.db"
        log "INFO" "  Backed up database"
    fi
    
    # Create backup manifest
    cat > "$backup_path/backup_manifest.txt" << EOF
Backup created: $(date)
Environment: $DEPLOYMENT_ENVIRONMENT
Version: $DEPLOYMENT_VERSION
Backup ID: $timestamp
Items backed up: ${backup_items[*]}
EOF
    
    # Cleanup old backups (keep last 10)
    find "$BACKUP_DIR" -name "deployment_*" -type d | sort -r | tail -n +11 | xargs rm -rf
    
    log "SUCCESS" "Backup created: $backup_path"
}

# Clone or update repository
update_repository() {
    log "INFO" "Updating source code..."
    
    # Check if repository exists
    if [ -d "$DEPLOYMENT_DIR/.git" ]; then
        log "INFO" "Repository exists, updating..."
        
        cd "$DEPLOYMENT_DIR"
        
        # Stash any local changes
        if git status --porcelain | grep -q "."; then
            log "WARNING" "Local changes detected, stashing..."
            git stash save "Auto-stash before deployment $(date)"
        fi
        
        # Pull latest changes
        git pull origin main
        
        # Checkout specific version if specified
        if [ -n "$DEPLOYMENT_VERSION" ] && [ "$DEPLOYMENT_VERSION" != "latest" ]; then
            log "INFO" "Checking out version: $DEPLOYMENT_VERSION"
            git checkout "$DEPLOYMENT_VERSION"
        fi
        
    else
        log "INFO" "Cloning repository..."
        
        # Clone repository
        git clone https://github.com/your-org/cyberguard.git "$DEPLOYMENT_DIR"
        
        # Checkout specific version if specified
        if [ -n "$DEPLOYMENT_VERSION" ] && [ "$DEPLOYMENT_VERSION" != "latest" ]; then
            cd "$DEPLOYMENT_DIR"
            git checkout "$DEPLOYMENT_VERSION"
        fi
    fi
    
    # Get current commit hash
    cd "$DEPLOYMENT_DIR"
    CURRENT_COMMIT=$(git rev-parse --short HEAD)
    log "INFO" "Current commit: $CURRENT_COMMIT"
    
    log "SUCCESS" "Repository updated"
}

# Setup Python environment
setup_python_environment() {
    log "INFO" "Setting up Python environment..."
    
    cd "$DEPLOYMENT_DIR"
    
    # Check if virtual environment exists
    if [ ! -d "$VENV_PATH" ]; then
        log "INFO" "Creating virtual environment..."
        python3 -m venv "$VENV_PATH"
    fi
    
    # Activate virtual environment
    source "$VENV_PATH/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install dependencies
    log "INFO" "Installing dependencies..."
    
    # Install base requirements
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
    fi
    
    # Install environment-specific requirements
    local env_requirements="requirements-$DEPLOYMENT_ENVIRONMENT.txt"
    if [ -f "$env_requirements" ]; then
        pip install -r "$env_requirements"
    fi
    
    # Verify installation
    if python -c "import torch, fastapi, pydantic"; then
        log "SUCCESS" "Python environment setup complete"
    else
        log "ERROR" "Failed to verify Python packages"
        exit 1
    fi
}

# Apply environment-specific configuration
apply_environment_configuration() {
    log "INFO" "Applying $DEPLOYMENT_ENVIRONMENT configuration..."
    
    cd "$DEPLOYMENT_DIR"
    
    # Source environment-specific configuration
    local config_file="config/deploy_${DEPLOYMENT_ENVIRONMENT}.sh"
    
    if [ -f "$config_file" ]; then
        log "INFO" "Loading environment configuration: $config_file"
        source "$config_file"
    else
        log "WARNING" "No environment-specific configuration found: $config_file"
    fi
    
    # Update configuration files
    if [ -f "config/enterprise_config.yaml" ]; then
        # Update configuration based on environment
        sed -i "s/environment:.*/environment: \"$DEPLOYMENT_ENVIRONMENT\"/" config/enterprise_config.yaml
        
        if [ "$DEPLOYMENT_ENVIRONMENT" = "prod" ]; then
            sed -i "s/auth_required:.*/auth_required: true/" config/enterprise_config.yaml
            sed -i "s/ssl_enabled:.*/ssl_enabled: true/" config/enterprise_config.yaml
            sed -i "s/log_level:.*/log_level: \"WARNING\"/" config/enterprise_config.yaml
        fi
    fi
    
    # Generate secrets if needed
    if [ ! -f ".env" ] && [ -f ".env.example" ]; then
        log "INFO" "Generating environment file from template..."
        cp .env.example .env
        
        # Generate secure secrets
        sed -i "s/SECRET_KEY=.*/SECRET_KEY=$(openssl rand -hex 32)/" .env
        sed -i "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$(openssl rand -hex 32)/" .env
    fi
    
    log "SUCCESS" "Configuration applied for $DEPLOYMENT_ENVIRONMENT"
}

# Run database migrations
run_database_migrations() {
    log "INFO" "Running database migrations..."
    
    cd "$DEPLOYMENT_DIR"
    source "$VENV_PATH/bin/activate"
    
    # Check if migration script exists
    if [ -f "scripts/migrate_database.py" ]; then
        log "INFO" "Running database migration script..."
        
        if python scripts/migrate_database.py; then
            log "SUCCESS" "Database migrations completed"
        else
            log "ERROR" "Database migration failed"
            exit 1
        fi
    else
        log "INFO" "No migration script found, skipping migrations"
    fi
}

# Deploy using Docker
deploy_with_docker() {
    log "INFO" "Deploying with Docker..."
    
    cd "$DEPLOYMENT_DIR"
    
    # Check if Docker Compose file exists
    if [ ! -f "docker-compose.yml" ] && [ ! -f "docker-compose.yaml" ]; then
        log "ERROR" "Docker Compose file not found"
        exit 1
    fi
    
    # Build Docker images
    log "INFO" "Building Docker images..."
    
    # Build with environment tag
    docker-compose build --build-arg ENVIRONMENT="$DEPLOYMENT_ENVIRONMENT"
    
    # Stop existing containers
    log "INFO" "Stopping existing containers..."
    docker-compose down || true
    
    # Start new containers
    log "INFO" "Starting containers..."
    docker-compose up -d
    
    # Wait for services to be ready
    log "INFO" "Waiting for services to be ready..."
    sleep 30
    
    # Check container status
    if docker-compose ps | grep -q "Up"; then
        log "SUCCESS" "Docker deployment successful"
        
        # Show container status
        docker-compose ps
    else
        log "ERROR" "Docker deployment failed"
        docker-compose logs
        exit 1
    fi
}

# Deploy using systemd
deploy_with_systemd() {
    log "INFO" "Deploying with systemd..."
    
    # Create systemd service file
    local service_file="/etc/systemd/system/cyberguard.service"
    
    cat > "$service_file" << EOF
[Unit]
Description=CyberGuard Web Security AI System
After=network.target
Requires=network.target

[Service]
Type=exec
User=cyberguard
Group=cyberguard
WorkingDirectory=$DEPLOYMENT_DIR
Environment=PATH=$VENV_PATH/bin:/usr/local/bin:/usr/bin:/bin
Environment=PYTHONPATH=$DEPLOYMENT_DIR
ExecStart=$VENV_PATH/bin/python main.py --mode api
Restart=on-failure
RestartSec=10
StandardOutput=append:$LOG_DIR/cyberguard.log
StandardError=append:$LOG_DIR/cyberguard-error.log

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$DEPLOYMENT_DIR/data $LOG_DIR
PrivateDevices=true
ProtectHome=true

# Resource limits
LimitNOFILE=65536
LimitNPROC=65536

[Install]
WantedBy=multi-user.target
EOF
    
    # Create system user if it doesn't exist
    if ! id "cyberguard" &>/dev/null; then
        useradd -r -s /bin/false cyberguard
        log "INFO" "Created system user: cyberguard"
    fi
    
    # Set permissions
    chown -R cyberguard:cyberguard "$DEPLOYMENT_DIR"
    chown -R cyberguard:cyberguard "$LOG_DIR"
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable and start service
    systemctl enable cyberguard.service
    systemctl restart cyberguard.service
    
    # Check service status
    if systemctl is-active --quiet cyberguard.service; then
        log "SUCCESS" "Systemd service started successfully"
        
        # Show service status
        systemctl status cyberguard.service --no-pager
    else
        log "ERROR" "Failed to start systemd service"
        journalctl -u cyberguard.service -n 50
        exit 1
    fi
}

# Deploy manually (for development)
deploy_manually() {
    log "INFO" "Deploying manually (development mode)..."
    
    cd "$DEPLOYMENT_DIR"
    source "$VENV_PATH/bin/activate"
    
    # Check if already running
    if pgrep -f "main.py" > /dev/null; then
        log "WARNING" "CyberGuard is already running, stopping..."
        pkill -f "main.py"
        sleep 2
    fi
    
    # Start in background
    log "INFO" "Starting CyberGuard..."
    
    # Start API server
    nohup python main.py --mode api > "$LOG_DIR/api.log" 2>&1 &
    API_PID=$!
    
    # Start dashboard
    nohup python main.py --mode dashboard > "$LOG_DIR/dashboard.log" 2>&1 &
    DASHBOARD_PID=$!
    
    # Save PIDs to file
    echo "$API_PID" > "$DEPLOYMENT_DIR/api.pid"
    echo "$DASHBOARD_PID" > "$DEPLOYMENT_DIR/dashboard.pid"
    
    # Wait a moment and check if processes are running
    sleep 5
    
    if kill -0 "$API_PID" 2>/dev/null && kill -0 "$DASHBOARD_PID" 2>/dev/null; then
        log "SUCCESS" "Manual deployment successful"
        log "INFO" "API PID: $API_PID, Dashboard PID: $DASHBOARD_PID"
        log "INFO" "Check logs: $LOG_DIR/api.log and $LOG_DIR/dashboard.log"
    else
        log "ERROR" "Failed to start processes"
        exit 1
    fi
}

# Verify deployment
verify_deployment() {
    log "INFO" "Verifying deployment..."
    
    local max_retries=10
    local retry_delay=5
    local api_url="http://localhost:8000/health"
    local dashboard_url="http://localhost:8080"
    
    for i in $(seq 1 $max_retries); do
        log "INFO" "Verification attempt $i/$max_retries..."
        
        # Check API health
        if curl -s -f "$api_url" > /dev/null; then
            log "SUCCESS" "API is responding"
            
            # Check dashboard if applicable
            if [ "$DEPLOYMENT_MODE" != "docker" ] || [ "$DEPLOYMENT_ENVIRONMENT" != "prod" ]; then
                if curl -s -f "$dashboard_url" > /dev/null; then
                    log "SUCCESS" "Dashboard is responding"
                    return 0
                else
                    log "WARNING" "Dashboard not responding yet"
                fi
            else
                return 0
            fi
        else
            log "WARNING" "API not responding yet"
        fi
        
        sleep $retry_delay
    done
    
    log "ERROR" "Deployment verification failed after $max_retries attempts"
    return 1
}

# Perform rollback
perform_rollback() {
    log "INFO" "Performing rollback..."
    
    # Find latest backup
    local latest_backup=$(find "$BACKUP_DIR" -name "deployment_*" -type d | sort -r | head -1)
    
    if [ -z "$latest_backup" ]; then
        log "ERROR" "No backups found for rollback"
        exit 1
    fi
    
    log "INFO" "Rolling back to: $latest_backup"
    
    # Stop current deployment
    case $DEPLOYMENT_MODE in
        "docker")
            docker-compose down || true
            ;;
        "systemd")
            systemctl stop cyberguard.service || true
            ;;
        "manual")
            pkill -f "main.py" || true
            ;;
    esac
    
    # Restore from backup
    log "INFO" "Restoring from backup..."
    
    # Restore configuration
    if [ -d "$latest_backup/config" ]; then
        rm -rf "$DEPLOYMENT_DIR/config"
        cp -r "$latest_backup/config" "$DEPLOYMENT_DIR/"
    fi
    
    # Restore data
    if [ -d "$latest_backup/data" ]; then
        rm -rf "$DEPLOYMENT_DIR/data"
        cp -r "$latest_backup/data" "$DEPLOYMENT_DIR/"
    fi
    
    # Restore database
    if [ -f "$latest_backup/cyberguard.db" ]; then
        cp "$latest_backup/cyberguard.db" "$DEPLOYMENT_DIR/data/"
    fi
    
    # Start deployment
    case $DEPLOYMENT_MODE in
        "docker")
            deploy_with_docker
            ;;
        "systemd")
            deploy_with_systemd
            ;;
        "manual")
            deploy_manually
            ;;
    esac
    
    log "SUCCESS" "Rollback completed successfully"
}

# Cleanup temporary files
cleanup() {
    log "INFO" "Cleaning up temporary files..."
    
    # Remove temporary Python files
    find "$DEPLOYMENT_DIR" -name "*.pyc" -delete
    find "$DEPLOYMENT_DIR" -name "__pycache__" -type d -delete
    find "$DEPLOYMENT_DIR" -name ".pytest_cache" -type d -delete
    
    # Clear Python cache
    python -m py_compile "$DEPLOYMENT_DIR" 2>/dev/null || true
    
    log "INFO" "Cleanup completed"
}

# Main deployment function
main_deployment() {
    log "INFO" "Starting CyberGuard deployment..."
    log "INFO" "Environment: $DEPLOYMENT_ENVIRONMENT"
    log "INFO" "Mode: $DEPLOYMENT_MODE"
    log "INFO" "Version: $DEPLOYMENT_VERSION"
    
    # Check if rollback requested
    if [ "$ROLLBACK" = "true" ]; then
        perform_rollback
        exit 0
    fi
    
    # Execute deployment steps
    check_deployment_requirements
    create_deployment_directories
    backup_current_deployment
    update_repository
    setup_python_environment
    apply_environment_configuration
    run_database_migrations
    
    # Choose deployment method
    case $DEPLOYMENT_MODE in
        "docker")
            deploy_with_docker
            ;;
        "systemd")
            deploy_with_systemd
            ;;
        "manual")
            deploy_manually
            ;;
    esac
    
    # Verify deployment
    if verify_deployment; then
        cleanup
        log "SUCCESS" "🎉 CyberGuard deployment completed successfully!"
        
        # Display deployment info
        echo ""
        echo "╔══════════════════════════════════════════════════════╗"
        echo "║               DEPLOYMENT SUMMARY                     ║"
        echo "╠══════════════════════════════════════════════════════╣"
        echo "║ Environment: $DEPLOYMENT_ENVIRONMENT"
        echo "║ Mode:        $DEPLOYMENT_MODE"
        echo "║ Version:     $DEPLOYMENT_VERSION"
        echo "║ Commit:      $CURRENT_COMMIT"
        echo "║ Date:        $(date)"
        echo "╠══════════════════════════════════════════════════════╣"
        echo "║ API:         http://localhost:8000"
        echo "║ Dashboard:   http://localhost:8080"
        echo "║ Docs:        http://localhost:8000/docs"
        echo "║ Logs:        $LOG_DIR"
        echo "╚══════════════════════════════════════════════════════╝"
        echo ""
        
    else
        log "ERROR" "Deployment verification failed"
        exit 1
    fi
}

# Parse command line arguments
parse_arguments() {
    # Default values
    DEPLOYMENT_ENVIRONMENT="dev"
    DEPLOYMENT_MODE="manual"
    DEPLOYMENT_VERSION="latest"
    ENABLE_BACKUP="true"
    ROLLBACK="false"
    CONFIG_FILE=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                DEPLOYMENT_ENVIRONMENT="$2"
                shift 2
                ;;
            -m|--mode)
                DEPLOYMENT_MODE="$2"
                shift 2
                ;;
            -v|--version)
                DEPLOYMENT_VERSION="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -b|--backup)
                ENABLE_BACKUP="true"
                shift
                ;;
            -r|--rollback)
                ROLLBACK="true"
                shift
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                log "ERROR" "Unknown argument: $1"
                print_usage
                exit 1
                ;;
        esac
    done
    
    # Validate arguments
    validate_arguments "$DEPLOYMENT_ENVIRONMENT" "$DEPLOYMENT_MODE"
    
    # Load configuration file if specified
    if [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ]; then
        log "INFO" "Loading configuration from: $CONFIG_FILE"
        source "$CONFIG_FILE"
    fi
}

# Main execution
main() {
    # Create log directory if it doesn't exist
    mkdir -p "$LOG_DIR"
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Run main deployment
    main_deployment
}

# Run main function
main "$@"