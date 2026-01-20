#!/bin/bash
# scripts/update_threat_feeds.sh

# ============================================================================
# CYBERGUARD THREAT INTELLIGENCE FEED UPDATER
# ============================================================================
# This script updates all threat intelligence feeds used by CyberGuard.
# It downloads from multiple sources, validates the data, and updates
# the local database.
#
# Features:
# - Multi-source threat intelligence aggregation
# - Data validation and sanitization
# - Deduplication and merging
# - Update notification and logging
# - Error handling and retry logic
# ============================================================================

set -e  # Exit on error
set -u  # Treat unset variables as error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$PROJECT_ROOT/data"
THREAT_FEEDS_DIR="$DATA_DIR/threat_feeds"
LOG_DIR="$PROJECT_ROOT/logs"
LOCK_FILE="/tmp/cyberguard_threat_feeds.lock"
MAX_RETRIES=3
RETRY_DELAY=5

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color

# Threat intelligence feed configurations
declare -A THREAT_FEEDS=(
    # Format: [feed_name]="URL|type|refresh_hours|description"
    
    # CVE and Vulnerability Feeds
    ["mitre_cve"]="https://cve.mitre.org/data/downloads/allitems.csv|csv|24|MITRE CVE Database"
    ["nvd_cve"]="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz|json|24|NIST NVD CVE Feed"
    ["exploit_db"]="https://raw.githubusercontent.com/vulnersCom/vulners-whitelist/master/exploitdb.csv|csv|12|Exploit Database"
    
    # Malware and Threat Feeds
    ["feodo_tracker"]="https://feodotracker.abuse.ch/downloads/ipblocklist.csv|csv|6|Feodo Tracker Botnet C2"
    ["ssl_blacklist"]="https://sslbl.abuse.ch/blacklist/sslblacklist.csv|csv|6|SSL Certificate Blacklist"
    ["malware_domain_list"]="https://www.malwaredomainlist.com/hostslist/hosts.txt|text|12|Malware Domain List"
    ["urlhaus"]="https://urlhaus.abuse.ch/downloads/csv_online/"|csv|6|URLhaus Malware URLs"
    
    # Phishing and Fraud
    ["openphish"]="https://openphish.com/feed.txt|text|1|OpenPhish Active Phishing Sites"
    ["phishtank"]="https://data.phishtank.com/data/online-valid.csv|csv|1|PhishTank Verified Phishing Sites"
    
    # IP Reputation
    ["emerging_threats"]="https://rules.emergingthreats.net/blockrules/compromised-ips.txt|text|6|Emerging Threats Compromised IPs"
    ["blocklist_de"]="https://lists.blocklist.de/lists/all.txt|text|6|Blocklist.de All Attackers"
    ["ciu"]="https://cinsscore.com/list/ci-badguys.txt|text|12|C.I. Army Bad Guys"
    
    # DNS-based Threats
    ["ransomware_tracker"]="https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt|text|6|Ransomware Tracker Domain Blocklist"
    ["dshield"]="https://www.dshield.org/block.txt|text|6|DShield Top Attackers"
    
    # Application Specific
    ["owasp_csrf"]="https://raw.githubusercontent.com/OWASP/CSRFGuard/master/patterns.txt|text|24|OWASP CSRF Patterns"
    ["xss_payloads"]="https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt|text|24|XSS Payload List"
)

# Logging function
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Colorize output
    case $level in
        "INFO")    echo -e "${BLUE}[$timestamp] [INFO]${NC} $message" ;;
        "SUCCESS") echo -e "${GREEN}[$timestamp] [SUCCESS]${NC} $message" ;;
        "WARNING") echo -e "${YELLOW}[$timestamp] [WARNING]${NC} $message" ;;
        "ERROR")   echo -e "${RED}[$timestamp] [ERROR]${NC} $message" ;;
        *)         echo "[$timestamp] [$level] $message" ;;
    esac
    
    # Log to file
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/threat_feeds.log"
}

# Check if script is already running
check_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local pid=$(cat "$LOCK_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log_message "ERROR" "Another instance is already running (PID: $pid)"
            exit 1
        else
            log_message "WARNING" "Stale lock file found, removing..."
            rm -f "$LOCK_FILE"
        fi
    fi
    
    # Create lock file
    echo $$ > "$LOCK_FILE"
}

# Cleanup lock file
cleanup_lock() {
    if [ -f "$LOCK_FILE" ]; then
        rm -f "$LOCK_FILE"
    fi
}

# Setup directories
setup_directories() {
    log_message "INFO" "Setting up directories..."
    
    # Create directories if they don't exist
    local directories=(
        "$THREAT_FEEDS_DIR"
        "$THREAT_FEEDS_DIR/raw"
        "$THREAT_FEEDS_DIR/processed"
        "$THREAT_FEEDS_DIR/backup"
        "$LOG_DIR"
    )
    
    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            log_message "INFO" "Created directory: $dir"
        fi
    done
}

# Download a single feed with retry logic
download_feed() {
    local feed_name=$1
    local feed_url=$2
    local feed_type=$3
    local output_file="$THREAT_FEEDS_DIR/raw/${feed_name}_$(date +%Y%m%d_%H%M%S).${feed_type}"
    
    log_message "INFO" "Downloading: $feed_name"
    
    # Try downloading with retries
    for attempt in $(seq 1 $MAX_RETRIES); do
        log_message "INFO" "Attempt $attempt/$MAX_RETRIES..."
        
        # Use appropriate download method
        case $feed_type in
            "csv"|"txt"|"text")
                # Use curl for text-based feeds
                if curl -s -L --max-time 30 --retry 2 --retry-delay 3 \
                    -H "User-Agent: CyberGuard-Threat-Collector/1.0" \
                    -o "$output_file.tmp" "$feed_url"; then
                    
                    # Check if download was successful
                    if [ -s "$output_file.tmp" ]; then
                        mv "$output_file.tmp" "$output_file"
                        log_message "SUCCESS" "Downloaded: $feed_name"
                        return 0
                    else
                        log_message "WARNING" "Empty response for $feed_name"
                        rm -f "$output_file.tmp"
                    fi
                fi
                ;;
                
            "json"|"json.gz")
                # Use wget for JSON feeds (better for compressed content)
                if wget -q --timeout=30 --tries=2 \
                    -U "CyberGuard-Threat-Collector/1.0" \
                    -O "$output_file.tmp" "$feed_url"; then
                    
                    # Check if download was successful
                    if [ -s "$output_file.tmp" ]; then
                        mv "$output_file.tmp" "$output_file"
                        
                        # Decompress if gzipped
                        if [[ "$feed_url" == *.gz ]]; then
                            gunzip -f "$output_file"
                            output_file="${output_file%.gz}"
                        fi
                        
                        log_message "SUCCESS" "Downloaded: $feed_name"
                        return 0
                    else
                        log_message "WARNING" "Empty response for $feed_name"
                        rm -f "$output_file.tmp"
                    fi
                fi
                ;;
                
            *)
                log_message "WARNING" "Unknown feed type: $feed_type for $feed_name"
                return 1
                ;;
        esac
        
        # Wait before retry
        if [ $attempt -lt $MAX_RETRIES ]; then
            log_message "INFO" "Retrying in $RETRY_DELAY seconds..."
            sleep $RETRY_DELAY
        fi
    done
    
    log_message "ERROR" "Failed to download: $feed_name after $MAX_RETRIES attempts"
    return 1
}

# Validate downloaded feed
validate_feed() {
    local feed_file=$1
    local feed_type=$2
    local feed_name=$3
    
    log_message "INFO" "Validating: $feed_name"
    
    # Check if file exists and has content
    if [ ! -f "$feed_file" ] || [ ! -s "$feed_file" ]; then
        log_message "ERROR" "Feed file is empty or missing: $feed_file"
        return 1
    fi
    
    # Validate based on file type
    case $feed_type in
        "csv")
            # Check if it's a valid CSV (at least has some rows)
            local line_count=$(wc -l < "$feed_file")
            if [ "$line_count" -lt 2 ]; then
                log_message "WARNING" "CSV file has only $line_count lines"
                return 1
            fi
            
            # Check for common CSV issues
            if grep -q '"\"' "$feed_file"; then
                log_message "WARNING" "CSV has malformed quotes"
                return 1
            fi
            ;;
            
        "json")
            # Validate JSON syntax
            if ! python3 -m json.tool "$feed_file" > /dev/null 2>&1; then
                log_message "ERROR" "Invalid JSON in feed: $feed_name"
                return 1
            fi
            ;;
            
        "text"|"txt")
            # Basic text validation
            local line_count=$(wc -l < "$feed_file")
            if [ "$line_count" -eq 0 ]; then
                log_message "WARNING" "Text file is empty"
                return 1
            fi
            ;;
    esac
    
    # Check for suspicious patterns
    if grep -q -i "hack\|exploit\|malware\|virus" "$feed_file" 2>/dev/null; then
        log_message "INFO" "Feed contains expected threat indicators"
    fi
    
    log_message "SUCCESS" "Validation passed: $feed_name"
    return 0
}

# Process and normalize feed data
process_feed() {
    local feed_name=$1
    local feed_file=$2
    local feed_type=$3
    local output_file="$THREAT_FEEDS_DIR/processed/${feed_name}_processed.csv"
    
    log_message "INFO" "Processing: $feed_name"
    
    # Create processed file with headers
    echo "feed_name,indicator_type,indicator_value,severity,first_seen,last_seen,source" > "$output_file.tmp"
    
    # Process based on feed type
    case $feed_name in
        "mitre_cve")
            # Process CVE data
            awk -F',' 'NR>1 {
                gsub(/"/, "", $1);
                gsub(/"/, "", $2);
                print "mitre_cve,CVE," $1 ",HIGH," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",MITRE"
            }' "$feed_file" >> "$output_file.tmp"
            ;;
            
        "exploit_db")
            # Process Exploit DB
            awk -F',' 'NR>1 {
                if ($1 ~ /^CVE/) {
                    print "exploit_db,EXPLOIT," $1 ",CRITICAL," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",ExploitDB"
                }
            }' "$feed_file" >> "$output_file.tmp"
            ;;
            
        "feodo_tracker"|"ssl_blacklist")
            # Process IP/Domain feeds
            awk -F',' 'NR>1 {
                if ($1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                    print "'"$feed_name"',IP," $1 ",HIGH," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",AbuseCH"
                } else if ($1 ~ /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/) {
                    print "'"$feed_name"',DOMAIN," $1 ",HIGH," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",AbuseCH"
                }
            }' "$feed_file" >> "$output_file.tmp"
            ;;
            
        "malware_domain_list"|"openphish")
            # Process domain/text feeds
            grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\s+" "$feed_file" | \
            awk '{print "'"$feed_name"',IP," $2 ",HIGH," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",'"$feed_name"'"}' >> "$output_file.tmp"
            
            grep -E "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" "$feed_file" | \
            awk '{print "'"$feed_name"',DOMAIN," $1 ",HIGH," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",'"$feed_name"'"}' >> "$output_file.tmp"
            ;;
            
        "owasp_csrf")
            # Process CSRF patterns
            grep -v "^#" "$feed_file" | grep -v "^$" | \
            awk '{print "'"$feed_name"',PATTERN," $1 ",MEDIUM," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",OWASP"}' >> "$output_file.tmp"
            ;;
            
        "xss_payloads")
            # Process XSS payloads
            grep -v "^#" "$feed_file" | grep -v "^$" | \
            awk 'length($0) > 5 && length($0) < 500 {
                print "'"$feed_name"',PAYLOAD," $1 ",HIGH," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",PayloadBox"
            }' >> "$output_file.tmp"
            ;;
            
        *)
            # Generic processing for unknown feeds
            log_message "WARNING" "No specific processor for $feed_name, using generic"
            
            # Try to extract IPs, domains, and URLs
            grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$feed_file" | \
            awk '!seen[$0]++ {print "'"$feed_name"',IP," $0 ",MEDIUM," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",'"$feed_name"'"}' >> "$output_file.tmp"
            
            grep -o -E '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$feed_file" | \
            awk '!seen[$0]++ {print "'"$feed_name"',DOMAIN," $0 ",MEDIUM," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",'"$feed_name"'"}' >> "$output_file.tmp"
            ;;
    esac
    
    # Remove empty lines and sort
    grep -v "^$" "$output_file.tmp" | sort -u > "$output_file"
    rm -f "$output_file.tmp"
    
    local processed_count=$(wc -l < "$output_file")
    log_message "SUCCESS" "Processed $((processed_count-1)) indicators from $feed_name"
}

# Merge all processed feeds into a single database
merge_feeds() {
    log_message "INFO" "Merging all threat feeds..."
    
    local merged_file="$THREAT_FEEDS_DIR/threat_intelligence_$(date +%Y%m%d).csv"
    local temp_file="$merged_file.tmp"
    
    # Start with headers
    echo "feed_name,indicator_type,indicator_value,severity,first_seen,last_seen,source,timestamp" > "$temp_file"
    
    # Merge all processed files
    for processed_file in "$THREAT_FEEDS_DIR/processed"/*_processed.csv; do
        if [ -f "$processed_file" ]; then
            # Skip header line and append
            tail -n +2 "$processed_file" | \
            awk -v ts="$(date '+%Y-%m-%d %H:%M:%S')" '{print $0 "," ts}' >> "$temp_file"
        fi
    done
    
    # Remove duplicates (same indicator from multiple sources)
    awk -F',' '!seen[$3]++' "$temp_file" > "$merged_file"
    rm -f "$temp_file"
    
    local total_indicators=$(wc -l < "$merged_file")
    log_message "SUCCESS" "Merged database created with $((total_indicators-1)) unique indicators"
    
    # Create symbolic link to latest
    ln -sf "$merged_file" "$THREAT_FEEDS_DIR/threat_intelligence_latest.csv"
}

# Update the local threat database
update_threat_database() {
    log_message "INFO" "Updating threat database..."
    
    local latest_file="$THREAT_FEEDS_DIR/threat_intelligence_latest.csv"
    
    if [ ! -f "$latest_file" ]; then
        log_message "ERROR" "No threat intelligence file found"
        return 1
    fi
    
    # Check if Python is available for database update
    if command -v python3 > /dev/null; then
        # Create Python script to update database
        local update_script=$(mktemp)
        
        cat > "$update_script" << 'PYTHON_SCRIPT'
#!/usr/bin/env python3
"""
Update CyberGuard threat database from processed feeds
"""

import sqlite3
import csv
import sys
from datetime import datetime

def update_database(csv_file, db_file="data/cyberguard.db"):
    """Update SQLite database with threat intelligence"""
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Create table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                feed_name TEXT,
                indicator_type TEXT,
                indicator_value TEXT UNIQUE,
                severity TEXT,
                first_seen TEXT,
                last_seen TEXT,
                source TEXT,
                timestamp TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create index for faster lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_indicator 
            ON threat_intelligence(indicator_value, indicator_type)
        ''')
        
        # Read CSV file
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows_inserted = 0
            rows_updated = 0
            
            for row in reader:
                # Check if indicator already exists
                cursor.execute(
                    'SELECT id, last_seen FROM threat_intelligence WHERE indicator_value = ?',
                    (row['indicator_value'],)
                )
                
                existing = cursor.fetchone()
                
                if existing:
                    # Update last_seen if newer
                    existing_last_seen = datetime.strptime(existing[1], '%Y-%m-%d')
                    new_last_seen = datetime.strptime(row['last_seen'], '%Y-%m-%d')
                    
                    if new_last_seen > existing_last_seen:
                        cursor.execute('''
                            UPDATE threat_intelligence 
                            SET last_seen = ?, timestamp = ?
                            WHERE id = ?
                        ''', (row['last_seen'], row['timestamp'], existing[0]))
                        rows_updated += 1
                else:
                    # Insert new indicator
                    cursor.execute('''
                        INSERT INTO threat_intelligence 
                        (feed_name, indicator_type, indicator_value, severity, 
                         first_seen, last_seen, source, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        row['feed_name'],
                        row['indicator_type'],
                        row['indicator_value'],
                        row['severity'],
                        row['first_seen'],
                        row['last_seen'],
                        row['source'],
                        row['timestamp']
                    ))
                    rows_inserted += 1
            
            conn.commit()
            
            # Clean up old entries (older than 90 days)
            cursor.execute('''
                DELETE FROM threat_intelligence 
                WHERE date(last_seen) < date('now', '-90 days')
            ''')
            
            rows_deleted = cursor.rowcount
            conn.commit()
            
            print(f"Database update complete:")
            print(f"  Rows inserted: {rows_inserted}")
            print(f"  Rows updated: {rows_updated}")
            print(f"  Rows deleted (old): {rows_deleted}")
            
            # Get total count
            cursor.execute('SELECT COUNT(*) FROM threat_intelligence')
            total = cursor.fetchone()[0]
            print(f"  Total indicators in database: {total}")
            
    except Exception as e:
        print(f"Error updating database: {e}")
        sys.exit(1)
    
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 update_db.py <csv_file>")
        sys.exit(1)
    
    update_database(sys.argv[1])
PYTHON_SCRIPT
        
        # Run the database update
        if python3 "$update_script" "$latest_file"; then
            log_message "SUCCESS" "Threat database updated successfully"
        else
            log_message "ERROR" "Failed to update threat database"
            return 1
        fi
        
        rm -f "$update_script"
    else
        log_message "WARNING" "Python3 not available, skipping database update"
    fi
}

# Clean up old files
cleanup_old_files() {
    log_message "INFO" "Cleaning up old files..."
    
    # Keep only last 7 days of raw files
    find "$THREAT_FEEDS_DIR/raw" -type f -mtime +7 -delete
    
    # Keep only last 30 days of processed files
    find "$THREAT_FEEDS_DIR/processed" -type f -mtime +30 -delete
    
    # Keep only last 90 days of backup files
    find "$THREAT_FEEDS_DIR/backup" -type f -mtime +90 -delete
    
    # Keep only last 30 days of merged files
    find "$THREAT_FEEDS_DIR" -name "threat_intelligence_*.csv" -mtime +30 -delete
    
    log_message "INFO" "Cleanup completed"
}

# Generate summary report
generate_summary() {
    local summary_file="$LOG_DIR/threat_feed_summary_$(date +%Y%m%d).txt"
    
    log_message "INFO" "Generating summary report..."
    
    cat > "$summary_file" << EOF
=============================================
CYBERGUARD THREAT FEED UPDATE SUMMARY
=============================================
Date: $(date)
Duration: $SECONDS seconds

FEEDS PROCESSED:
EOF
    
    # Count processed feeds
    local processed_count=0
    for feed in "${!THREAT_FEEDS[@]}"; do
        if [ -f "$THREAT_FEEDS_DIR/processed/${feed}_processed.csv" ]; then
            local count=$(tail -n +2 "$THREAT_FEEDS_DIR/processed/${feed}_processed.csv" | wc -l)
            echo "  - $feed: $count indicators" >> "$summary_file"
            processed_count=$((processed_count + 1))
        fi
    done
    
    # Get total unique indicators
    if [ -f "$THREAT_FEEDS_DIR/threat_intelligence_latest.csv" ]; then
        local total_indicators=$(tail -n +2 "$THREAT_FEEDS_DIR/threat_intelligence_latest.csv" | wc -l)
        echo "" >> "$summary_file"
        echo "TOTAL UNIQUE INDICATORS: $total_indicators" >> "$summary_file"
    fi
    
    # Database info
    if [ -f "$PROJECT_ROOT/data/cyberguard.db" ]; then
        echo "" >> "$summary_file"
        echo "DATABASE INFO:" >> "$summary_file"
        sqlite3 "$PROJECT_ROOT/data/cyberguard.db" \
            "SELECT COUNT(*) as 'Total Indicators' FROM threat_intelligence;" >> "$summary_file" 2>/dev/null || \
            echo "  (Database query failed)" >> "$summary_file"
    fi
    
    echo "" >> "$summary_file"
    echo "STATUS: SUCCESS" >> "$summary_file"
    echo "=============================================" >> "$summary_file"
    
    log_message "SUCCESS" "Summary report generated: $summary_file"
    
    # Display summary
    cat "$summary_file"
}

# Main execution function
main() {
    local start_time=$(date +%s)
    
    log_message "INFO" "Starting CyberGuard threat feed update..."
    log_message "INFO" "Project root: $PROJECT_ROOT"
    
    # Setup
    check_lock
    trap cleanup_lock EXIT
    setup_directories
    
    # Track success/failure
    local successful_feeds=0
    local failed_feeds=0
    local total_feeds=${#THREAT_FEEDS[@]}
    
    log_message "INFO" "Processing $total_feeds threat feeds..."
    
    # Process each feed
    for feed_name in "${!THREAT_FEEDS[@]}"; do
        IFS='|' read -r feed_url feed_type refresh_hours description <<< "${THREAT_FEEDS[$feed_name]}"
        
        log_message "INFO" "Feed: $feed_name ($description)"
        
        # Download feed
        if download_feed "$feed_name" "$feed_url" "$feed_type"; then
            # Find the downloaded file
            local latest_raw=$(ls -t "$THREAT_FEEDS_DIR/raw/${feed_name}_"*."$feed_type" 2>/dev/null | head -1)
            
            if [ -n "$latest_raw" ] && validate_feed "$latest_raw" "$feed_type" "$feed_name"; then
                # Process feed
                if process_feed "$feed_name" "$latest_raw" "$feed_type"; then
                    successful_feeds=$((successful_feeds + 1))
                else
                    failed_feeds=$((failed_feeds + 1))
                    log_message "ERROR" "Failed to process feed: $feed_name"
                fi
            else
                failed_feeds=$((failed_feeds + 1))
                log_message "ERROR" "Failed to validate feed: $feed_name"
            fi
        else
            failed_feeds=$((failed_feeds + 1))
        fi
        
        # Small delay between feeds
        sleep 1
    done
    
    # Merge and update if we have successful downloads
    if [ $successful_feeds -gt 0 ]; then
        merge_feeds
        update_threat_database
        cleanup_old_files
        
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        SECONDS=$duration
        
        generate_summary
        
        log_message "SUCCESS" "Threat feed update completed in ${duration} seconds"
        log_message "INFO" "Successfully processed: $successful_feeds/$total_feeds feeds"
        
        if [ $failed_feeds -gt 0 ]; then
            log_message "WARNING" "Failed to process: $failed_feeds feeds"
        fi
    else
        log_message "ERROR" "No feeds were successfully processed"
        exit 1
    fi
}

# Run main function
main "$@"