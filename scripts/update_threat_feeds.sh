# CyberGuard Threat Intelligence Feed Updater

set -euo pipefail  # Exit on error, treat unset vars as errors, fail pipeline if any command fails

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"  # Get absolute path of script directory
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"                     # Get parent directory (project root)
DATA_DIR="${PROJECT_ROOT}/data"                             # Data directory path
THREAT_FEEDS_DIR="${DATA_DIR}/threat_feeds"                 # Threat feeds storage directory
LOG_DIR="${PROJECT_ROOT}/logs"                              # Log files directory
LOCK_FILE="/tmp/cyberguard_threat_feeds.lock"               # Lock file to prevent concurrent execution
MAX_RETRIES=3                                               # Maximum retry attempts for downloads
RETRY_DELAY=5                                               # Seconds to wait between retries

# Color codes for terminal output - ANSI escape codes for colored text
RED='\033[0;31m'      # Red color for error messages
GREEN='\033[0;32m'    # Green color for success messages
YELLOW='\033[1;33m'   # Yellow color for warning messages
BLUE='\033[0;34m'     # Blue color for info messages
NC='\033[0m'          # No Color - reset to default terminal color

# Associative array of threat intelligence feeds
# Format: [feed_name]="URL|type|refresh_hours|description"
declare -A THREAT_FEEDS=(
    # CVE and Vulnerability Feeds
    ["mitre_cve"]="https://cve.mitre.org/data/downloads/allitems.csv|csv|24|MITRE CVE Database"
    ["nvd_cve"]="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz|json|24|NIST NVD CVE Feed"
    ["exploit_db"]="https://raw.githubusercontent.com/vulnersCom/vulners-whitelist/master/exploitdb.csv|csv|12|Exploit Database"
    
    # Malware and Threat Feeds
    ["feodo_tracker"]="https://feodotracker.abuse.ch/downloads/ipblocklist.csv|csv|6|Feodo Tracker Botnet C2"
    ["ssl_blacklist"]="https://sslbl.abuse.ch/blacklist/sslblacklist.csv|csv|6|SSL Certificate Blacklist"
    ["malware_domain_list"]="https://www.malwaredomainlist.com/hostslist/hosts.txt|text|12|Malware Domain List"
    ["urlhaus"]="https://urlhaus.abuse.ch/downloads/csv_online/|csv|6|URLhaus Malware URLs"
    
    # Phishing and Fraud Feeds
    ["openphish"]="https://openphish.com/feed.txt|text|1|OpenPhish Active Phishing Sites"
    ["phishtank"]="https://data.phishtank.com/data/online-valid.csv|csv|1|PhishTank Verified Phishing Sites"
    
    # IP Reputation Feeds
    ["emerging_threats"]="https://rules.emergingthreats.net/blockrules/compromised-ips.txt|text|6|Emerging Threats Compromised IPs"
    ["blocklist_de"]="https://lists.blocklist.de/lists/all.txt|text|6|Blocklist.de All Attackers"
    ["ciu"]="https://cinsscore.com/list/ci-badguys.txt|text|12|C.I. Army Bad Guys"
    
    # DNS-based Threats Feeds
    ["ransomware_tracker"]="https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt|text|6|Ransomware Tracker Domain Blocklist"
    ["dshield"]="https://www.dshield.org/block.txt|text|6|DShield Top Attackers"
    
    # Application Specific Feeds
    ["owasp_csrf"]="https://raw.githubusercontent.com/OWASP/CSRFGuard/master/patterns.txt|text|24|OWASP CSRF Patterns"
    ["xss_payloads"]="https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt|text|24|XSS Payload List"
)

# Logs messages to both terminal and log file with color coding
log_message() {
    local level="$1"           # First parameter: log level (INFO, SUCCESS, WARNING, ERROR)
    local message="$2"         # Second parameter: message to log
    local timestamp           # Variable to store formatted timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')  # Get current time in YYYY-MM-DD HH:MM:SS format
    
    # Output colored message to terminal based on log level
    case "${level}" in
        "INFO")    echo -e "${BLUE}[${timestamp}] [INFO]${NC} ${message}" ;;
        "SUCCESS") echo -e "${GREEN}[${timestamp}] [SUCCESS]${NC} ${message}" ;;
        "WARNING") echo -e "${YELLOW}[${timestamp}] [WARNING]${NC} ${message}" ;;
        "ERROR")   echo -e "${RED}[${timestamp}] [ERROR]${NC} ${message}" ;;
        *)         echo "[${timestamp}] [${level}] ${message}" ;;  # Default for unknown levels
    esac
    
    # Append uncolored message to log file
    echo "[${timestamp}] [${level}] ${message}" >> "${LOG_DIR}/threat_feeds.log"
}

# Prevents multiple instances of the script from running simultaneously
check_lock() {
    # Check if lock file exists
    if [[ -f "${LOCK_FILE}" ]]; then
        local pid  # Variable to store process ID from lock file
        pid=$(cat "${LOCK_FILE}" 2>/dev/null || echo "")  # Read PID from lock file, suppress errors
        
        # Check if the process with that PID is still running
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
            log_message "ERROR" "Another instance is already running (PID: ${pid})"
            exit 1  # Exit script with error code 1
        else
            log_message "WARNING" "Stale lock file found, removing..."
            rm -f "${LOCK_FILE}"  # Remove stale lock file
        fi
    fi
    
    # Create new lock file with current shell's process ID
    echo $$ > "${LOCK_FILE}"
}

# Removes lock file when script exits (normal or error)
cleanup_lock() {
    if [[ -f "${LOCK_FILE}" ]]; then
        rm -f "${LOCK_FILE}"  # Delete lock file
        log_message "INFO" "Lock file cleaned up"
    fi
}

# Creates all required directories if they don't exist
setup_directories() {
    log_message "INFO" "Setting up directories..."
    
    # Array of directory paths to create
    local directories=(
        "${THREAT_FEEDS_DIR}"
        "${THREAT_FEEDS_DIR}/raw"       # Store raw downloaded feed files
        "${THREAT_FEEDS_DIR}/processed" # Store processed/cleaned feed data
        "${THREAT_FEEDS_DIR}/backup"    # Store backup files
        "${LOG_DIR}"                    # Store log files
    )
    
    # Iterate through directory array
    for dir in "${directories[@]}"; do
        if [[ ! -d "${dir}" ]]; then  # Check if directory doesn't exist
            mkdir -p "${dir}"         # Create directory and parent directories if needed
            log_message "INFO" "Created directory: ${dir}"
        fi
    done
}

# Downloads a single threat feed with retry logic
download_feed() {
    local feed_name="$1"   # Name identifier for the feed
    local feed_url="$2"    # URL to download the feed from
    local feed_type="$3"   # File type (csv, json, text)
    local output_file      # Full path for downloaded file
    local attempt          # Loop counter for retry attempts
    
    # Create output filename with timestamp: feedname_YYYYMMDD_HHMMSS.type
    output_file="${THREAT_FEEDS_DIR}/raw/${feed_name}_$(date +%Y%m%d_%H%M%S).${feed_type}"
    
    log_message "INFO" "Downloading: ${feed_name} from ${feed_url}"
    
    # Retry loop for downloading
    for attempt in $(seq 1 "${MAX_RETRIES}"); do
        log_message "INFO" "Attempt ${attempt}/${MAX_RETRIES} for ${feed_name}"
        
        # Handle different feed types with appropriate tools
        case "${feed_type}" in
            "csv"|"txt"|"text")
                # Use curl for text-based feeds (better for HTTP headers)
                if curl -s -L --max-time 30 --retry 2 --retry-delay 3 \
                    -H "User-Agent: CyberGuard-Threat-Collector/1.0" \
                    -H "Accept: text/${feed_type}" \
                    -o "${output_file}.tmp" "${feed_url}"; then
                    
                    # Check if downloaded file has content
                    if [[ -s "${output_file}.tmp" ]]; then
                        mv "${output_file}.tmp" "${output_file}"  # Rename temp to final file
                        log_message "SUCCESS" "Downloaded ${feed_name} successfully"
                        return 0  # Success exit code
                    else
                        log_message "WARNING" "Empty response for ${feed_name}"
                        rm -f "${output_file}.tmp"  # Clean up empty temp file
                    fi
                else
                    log_message "WARNING" "curl failed for ${feed_name}"
                    rm -f "${output_file}.tmp"  # Clean up failed download
                fi
                ;;
                
            "json"|"json.gz")
                # Use wget for JSON feeds (handles redirects and compression well)
                if wget -q --timeout=30 --tries=2 \
                    --user-agent="CyberGuard-Threat-Collector/1.0" \
                    --output-document="${output_file}.tmp" "${feed_url}"; then
                    
                    # Check if downloaded file has content
                    if [[ -s "${output_file}.tmp" ]]; then
                        mv "${output_file}.tmp" "${output_file}"  # Rename temp to final file
                        
                        # Decompress if file is gzipped
                        if [[ "${feed_url}" == *.gz ]]; then
                            gunzip -f "${output_file}"  # Force decompress, remove .gz extension
                            output_file="${output_file%.gz}"  # Update filename without .gz
                        fi
                        
                        log_message "SUCCESS" "Downloaded ${feed_name} successfully"
                        return 0  # Success exit code
                    else
                        log_message "WARNING" "Empty response for ${feed_name}"
                        rm -f "${output_file}.tmp"  # Clean up empty temp file
                    fi
                else
                    log_message "WARNING" "wget failed for ${feed_name}"
                    rm -f "${output_file}.tmp"  # Clean up failed download
                fi
                ;;
                
            *)
                # Unknown feed type - cannot proceed
                log_message "ERROR" "Unknown feed type: ${feed_type} for ${feed_name}"
                return 1  # Error exit code
                ;;
        esac
        
        # Wait before retrying (except on last attempt)
        if [[ "${attempt}" -lt "${MAX_RETRIES}" ]]; then
            log_message "INFO" "Retrying in ${RETRY_DELAY} seconds..."
            sleep "${RETRY_DELAY}"  # Pause before next retry
        fi
    done
    
    # All retries failed
    log_message "ERROR" "Failed to download ${feed_name} after ${MAX_RETRIES} attempts"
    return 1  # Error exit code
}

# Validates downloaded feed for format and content integrity
validate_feed() {
    local feed_file="$1"   # Path to the downloaded feed file
    local feed_type="$2"   # Type of feed (csv, json, text)
    local feed_name="$3"   # Name of the feed for logging
    local line_count       # Variable to store line count
    
    log_message "INFO" "Validating ${feed_name} at ${feed_file}"
    
    # Basic file existence and non-empty check
    if [[ ! -f "${feed_file}" ]] || [[ ! -s "${feed_file}" ]]; then
        log_message "ERROR" "Feed file is empty or missing: ${feed_file}"
        return 1  # Error exit code
    fi
    
    # Type-specific validation
    case "${feed_type}" in
        "csv")
            # Count lines in CSV file
            line_count=$(wc -l < "${feed_file}" 2>/dev/null || echo "0")
            # CSV should have at least header and one data row
            if [[ "${line_count}" -lt 2 ]]; then
                log_message "WARNING" "CSV file has only ${line_count} lines"
                return 1  # Error exit code
            fi
            
            # Check for malformed CSV (unescaped quotes)
            if grep -q '""' "${feed_file}" 2>/dev/null; then
                log_message "WARNING" "CSV has potentially malformed quotes"
                # Note: This is a warning, not an error, as some feeds may use this format
            fi
            ;;
            
        "json")
            # Validate JSON syntax using Python's json.tool
            if ! python3 -m json.tool "${feed_file}" > /dev/null 2>&1; then
                log_message "ERROR" "Invalid JSON syntax in ${feed_name}"
                return 1  # Error exit code
            fi
            ;;
            
        "text"|"txt")
            # Basic text file validation - must have at least one line
            line_count=$(wc -l < "${feed_file}" 2>/dev/null || echo "0")
            if [[ "${line_count}" -eq 0 ]]; then
                log_message "WARNING" "Text file is empty"
                return 1  # Error exit code
            fi
            ;;
    esac
    
    # Optional content validation - check for expected threat-related terms
    if grep -q -i "exploit\|malware\|phish\|attack" "${feed_file}" 2>/dev/null; then
        log_message "INFO" "Feed contains expected threat indicators"
    fi
    
    log_message "SUCCESS" "Validation passed for ${feed_name}"
    return 0  # Success exit code
}

# Processes and normalizes feed data into standardized CSV format
process_feed() {
    local feed_name="$1"   # Name identifier for the feed
    local feed_file="$2"   # Path to raw feed file
    local feed_type="$3"   # Type of feed
    local output_file      # Path for processed output file
    local processed_count  # Count of processed indicators
    
    output_file="${THREAT_FEEDS_DIR}/processed/${feed_name}_processed.csv"
    
    log_message "INFO" "Processing ${feed_name} from ${feed_file}"
    
    # Create temporary file with CSV header
    echo "feed_name,indicator_type,indicator_value,severity,first_seen,last_seen,source" > "${output_file}.tmp"
    
    # Feed-specific processing logic
    case "${feed_name}" in
        "mitre_cve")
            # Process MITRE CVE CSV format
            awk -F',' 'NR>1 {  # Skip header row (NR>1)
                gsub(/"/, "", $1);  # Remove quotes from first column
                gsub(/"/, "", $2);  # Remove quotes from second column
                # Output standardized format: feed_name,type,value,severity,first_seen,last_seen,source
                print "mitre_cve,CVE," $1 ",HIGH," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",MITRE"
            }' "${feed_file}" >> "${output_file}.tmp"
            ;;
            
        "exploit_db")
            # Process Exploit Database CSV
            awk -F',' 'NR>1 {
                # Only process rows where first column starts with CVE
                if ($1 ~ /^CVE/) {
                    print "exploit_db,EXPLOIT," $1 ",CRITICAL," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",ExploitDB"
                }
            }' "${feed_file}" >> "${output_file}.tmp"
            ;;
            
        "feodo_tracker"|"ssl_blacklist")
            # Process Abuse.ch IP/Domain feeds
            awk -F',' 'NR>1 {
                # Check if first column is an IPv4 address
                if ($1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                    print "'"${feed_name}"',IP," $1 ",HIGH," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",AbuseCH"
                } 
                # Check if first column is a domain name
                else if ($1 ~ /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/) {
                    print "'"${feed_name}"',DOMAIN," $1 ",HIGH," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",AbuseCH"
                }
            }' "${feed_file}" >> "${output_file}.tmp"
            ;;
            
        "malware_domain_list"|"openphish")
            # Process text-based domain/IP lists
            # Extract IP addresses (lines starting with IP then whitespace)
            grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\s+" "${feed_file}" 2>/dev/null | \
            awk '{print "'"${feed_name}"',IP," $2 ",HIGH," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",'"${feed_name}"'"}' >> "${output_file}.tmp"
            
            # Extract domain names (lines starting with domain pattern)
            grep -E "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" "${feed_file}" 2>/dev/null | \
            awk '{print "'"${feed_name}"',DOMAIN," $1 ",HIGH," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",'"${feed_name}"'"}' >> "${output_file}.tmp"
            ;;
            
        "owasp_csrf")
            # Process OWASP CSRF patterns (skip comments and empty lines)
            grep -v "^#" "${feed_file}" | grep -v "^$" | \
            awk '{print "'"${feed_name}"',PATTERN," $1 ",MEDIUM," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",OWASP"}' >> "${output_file}.tmp"
            ;;
            
        "xss_payloads")
            # Process XSS payloads with length filtering
            grep -v "^#" "${feed_file}" | grep -v "^$" | \
            awk 'length($0) > 5 && length($0) < 500 {  # Filter payloads by length
                print "'"${feed_name}"',PAYLOAD," $1 ",HIGH," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",PayloadBox"
            }' >> "${output_file}.tmp"
            ;;
            
        *)
            # Generic processing for unhandled feed types
            log_message "WARNING" "No specific processor for ${feed_name}, using generic extraction"
            
            # Extract IPv4 addresses from any text
            grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "${feed_file}" 2>/dev/null | \
            awk '!seen[$0]++ {  # Remove duplicates using associative array
                print "'"${feed_name}"',IP," $0 ",MEDIUM," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",'"${feed_name}"'"
            }' >> "${output_file}.tmp"
            
            # Extract domain names from any text
            grep -o -E '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "${feed_file}" 2>/dev/null | \
            awk '!seen[$0]++ {  # Remove duplicates
                print "'"${feed_name}"',DOMAIN," $0 ",MEDIUM," strftime("%Y-%m-%d") "," strftime("%Y-%m-%d") ",'"${feed_name}"'"
            }' >> "${output_file}.tmp"
            ;;
    esac
    
    # Clean up: remove empty lines, sort uniquely, save to final file
    grep -v "^$" "${output_file}.tmp" | sort -u > "${output_file}"
    rm -f "${output_file}.tmp"  # Remove temporary file
    
    # Count processed indicators (excluding header)
    processed_count=$(wc -l < "${output_file}" 2>/dev/null || echo "0")
    log_message "SUCCESS" "Processed $((processed_count - 1)) indicators from ${feed_name}"
    return 0  # Success exit code
}

# Merges all processed feeds into a single unified database
merge_feeds() {
    log_message "INFO" "Merging all processed threat feeds..."
    
    local merged_file      # Final merged database file
    local temp_file        # Temporary file for merging
    local total_indicators # Count of unique indicators
    
    # Create dated filename for merged database
    merged_file="${THREAT_FEEDS_DIR}/threat_intelligence_$(date +%Y%m%d).csv"
    temp_file="${merged_file}.tmp"
    
    # Create header for merged CSV
    echo "feed_name,indicator_type,indicator_value,severity,first_seen,last_seen,source,timestamp" > "${temp_file}"
    
    # Loop through all processed feed files
    for processed_file in "${THREAT_FEEDS_DIR}/processed/"*_processed.csv; do
        if [[ -f "${processed_file}" ]]; then  # Check if file exists
            # Skip header (first line) and append with timestamp
            tail -n +2 "${processed_file}" | \
            awk -v ts="$(date '+%Y-%m-%d %H:%M:%S')" '{print $0 "," ts}' >> "${temp_file}"
        fi
    done
    
    # Remove duplicate indicators (based on indicator_value column 3), keep first occurrence
    awk -F',' '!seen[$3]++' "${temp_file}" > "${merged_file}"
    rm -f "${temp_file}"  # Clean up temporary file
    
    # Count total unique indicators (excluding header)
    total_indicators=$(wc -l < "${merged_file}" 2>/dev/null || echo "0")
    log_message "SUCCESS" "Created merged database with $((total_indicators - 1)) unique indicators"
    
    # Create symbolic link for easy access to latest database
    ln -sfn "${merged_file}" "${THREAT_FEEDS_DIR}/threat_intelligence_latest.csv"
    return 0  # Success exit code
}

# Updates SQLite database with merged threat intelligence
update_threat_database() {
    local latest_file  # Path to latest merged CSV file
    local update_script # Temporary Python script path
    
    latest_file="${THREAT_FEEDS_DIR}/threat_intelligence_latest.csv"
    
    log_message "INFO" "Updating threat database from ${latest_file}"
    
    # Check if merged file exists
    if [[ ! -f "${latest_file}" ]]; then
        log_message "ERROR" "No threat intelligence file found at ${latest_file}"
        return 1  # Error exit code
    fi
    
    # Check if Python3 is available for database operations
    if ! command -v python3 > /dev/null 2>&1; then
        log_message "WARNING" "Python3 not available, skipping database update"
        return 0  # Exit gracefully (not an error)
    fi
    
    # Create temporary Python script for database operations
    update_script=$(mktemp "${THREAT_FEEDS_DIR}/update_script_XXXXXX.py")
    
    # Python script to update SQLite database
    cat > "${update_script}" << 'PYTHON_EOF'
#!/usr/bin/env python3
"""
Update CyberGuard SQLite database with threat intelligence from CSV
"""

import sqlite3
import csv
import sys
import os
from datetime import datetime
from pathlib import Path

def update_database(csv_file_path: str) -> None:
    """Update SQLite database with threat intelligence data"""
    
    # Calculate database path relative to project root
    script_dir = Path(os.path.dirname(os.path.abspath(__file__)))
    project_root = script_dir.parent.parent  # Go up two levels from script dir
    db_path = project_root / "data" / "cyberguard.db"
    
    print(f"Updating database at: {db_path}")
    print(f"Using CSV file: {csv_file_path}")
    
    try:
        # Connect to SQLite database
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Create threat intelligence table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                feed_name TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                indicator_value TEXT NOT NULL UNIQUE,
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
        
        # Statistics tracking
        rows_inserted = 0
        rows_updated = 0
        rows_skipped = 0
        
        # Read and process CSV file
        with open(csv_file_path, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            
            for row in reader:
                # Check if indicator already exists in database
                cursor.execute(
                    '''SELECT id, last_seen FROM threat_intelligence 
                       WHERE indicator_value = ?''',
                    (row['indicator_value'],)
                )
                
                existing_row = cursor.fetchone()
                
                if existing_row:
                    # Update existing record if last_seen is newer
                    existing_id, existing_last_seen = existing_row
                    
                    try:
                        # Parse dates for comparison
                        existing_date = datetime.strptime(existing_last_seen, '%Y-%m-%d')
                        new_date = datetime.strptime(row['last_seen'], '%Y-%m-%d')
                        
                        if new_date > existing_date:
                            # Update with newer information
                            cursor.execute('''
                                UPDATE threat_intelligence 
                                SET last_seen = ?, timestamp = ?
                                WHERE id = ?
                            ''', (row['last_seen'], row['timestamp'], existing_id))
                            rows_updated += 1
                        else:
                            rows_skipped += 1
                    except ValueError:
                        # Date parsing failed, skip this row
                        rows_skipped += 1
                        continue
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
        
        # Commit all changes to database
        conn.commit()
        
        # Clean up old entries (older than 90 days)
        cursor.execute('''
            DELETE FROM threat_intelligence 
            WHERE date(last_seen) < date('now', '-90 days')
        ''')
        rows_deleted = cursor.rowcount
        conn.commit()
        
        # Get final statistics
        cursor.execute('SELECT COUNT(*) FROM threat_intelligence')
        total_indicators = cursor.fetchone()[0]
        
        # Print summary
        print("=" * 50)
        print("DATABASE UPDATE SUMMARY")
        print("=" * 50)
        print(f"Rows inserted:    {rows_inserted}")
        print(f"Rows updated:     {rows_updated}")
        print(f"Rows skipped:     {rows_skipped}")
        print(f"Rows deleted:     {rows_deleted}")
        print(f"Total indicators: {total_indicators}")
        print("=" * 50)
        
    except FileNotFoundError as e:
        print(f"Error: File not found - {e}")
        sys.exit(1)
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
    finally:
        # Ensure database connection is closed
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    # Validate command line arguments
    if len(sys.argv) != 2:
        print("Usage: python3 update_database.py <csv_file_path>")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    
    # Validate CSV file exists
    if not os.path.isfile(csv_file):
        print(f"Error: CSV file not found: {csv_file}")
        sys.exit(1)
    
    # Update database
    update_database(csv_file)
PYTHON_EOF
    
    # Execute Python script to update database
    if python3 "${update_script}" "${latest_file}"; then
        log_message "SUCCESS" "Threat database updated successfully"
        rm -f "${update_script}"  # Clean up temporary script
        return 0  # Success exit code
    else
        log_message "ERROR" "Failed to update threat database"
        rm -f "${update_script}"  # Clean up temporary script even on failure
        return 1  # Error exit code
    fi
}

# Cleans up old files to manage disk space
cleanup_old_files() {
    log_message "INFO" "Cleaning up old files..."
    
    # Remove raw files older than 7 days
    find "${THREAT_FEEDS_DIR}/raw" -type f -name "*.csv" -mtime +7 -delete 2>/dev/null || true
    find "${THREAT_FEEDS_DIR}/raw" -type f -name "*.json" -mtime +7 -delete 2>/dev/null || true
    find "${THREAT_FEEDS_DIR}/raw" -type f -name "*.txt" -mtime +7 -delete 2>/dev/null || true
    
    # Remove processed files older than 30 days
    find "${THREAT_FEEDS_DIR}/processed" -type f -name "*_processed.csv" -mtime +30 -delete 2>/dev/null || true
    
    # Remove backup files older than 90 days
    find "${THREAT_FEEDS_DIR}/backup" -type f -mtime +90 -delete 2>/dev/null || true
    
    # Remove merged database files older than 30 days (keep daily files for a month)
    find "${THREAT_FEEDS_DIR}" -name "threat_intelligence_*.csv" -mtime +30 -delete 2>/dev/null || true
    
    log_message "SUCCESS" "Cleanup completed"
}

# Generates summary report of the update process
generate_summary() {
    local summary_file  # Path to summary report file
    local processed_count  # Count of successfully processed feeds
    local total_indicators # Total unique indicators
    
    summary_file="${LOG_DIR}/threat_feed_summary_$(date +%Y%m%d_%H%M%S).txt"
    
    log_message "INFO" "Generating summary report at ${summary_file}"
    
    # Create summary report header
    {
        echo "CYBERGUARD THREAT FEED UPDATE SUMMARY"
        echo "======================================"
        echo "Date: $(date)"
        echo "Duration: ${1} seconds"
        echo ""
        echo "FEEDS PROCESSED:"
        echo "----------------"
    } > "${summary_file}"
    
    # Count and list processed feeds
    processed_count=0
    for feed in "${!THREAT_FEEDS[@]}"; do
        processed_feed_file="${THREAT_FEEDS_DIR}/processed/${feed}_processed.csv"
        if [[ -f "${processed_feed_file}" ]]; then
            # Count indicators (excluding header)
            local count
            count=$(tail -n +2 "${processed_feed_file}" | wc -l 2>/dev/null || echo "0")
            echo "  - ${feed}: ${count} indicators" >> "${summary_file}"
            processed_count=$((processed_count + 1))
        fi
    done
    
    # Add total unique indicators from merged database
    local latest_file="${THREAT_FEEDS_DIR}/threat_intelligence_latest.csv"
    if [[ -f "${latest_file}" ]]; then
        total_indicators=$(tail -n +2 "${latest_file}" | wc -l 2>/dev/null || echo "0")
        {
            echo ""
            echo "DATABASE SUMMARY:"
            echo "-----------------"
            echo "Total unique indicators: ${total_indicators}"
        } >> "${summary_file}"
    fi
    
    # Add database statistics if available
    local db_file="${PROJECT_ROOT}/data/cyberguard.db"
    if [[ -f "${db_file}" ]] && command -v sqlite3 > /dev/null 2>&1; then
        {
            echo ""
            echo "DATABASE STATISTICS:"
            echo "--------------------"
        } >> "${summary_file}"
        
        # Query database for statistics
        sqlite3 "${db_file}" << 'SQL_EOF' >> "${summary_file}" 2>/dev/null || echo "  (Database query failed)" >> "${summary_file}"
.timeout 5000
SELECT 'Total records: ' || COUNT(*) FROM threat_intelligence;
SELECT 'Records added today: ' || COUNT(*) FROM threat_intelligence 
WHERE date(timestamp) = date('now');
SELECT 'High severity: ' || COUNT(*) FROM threat_intelligence 
WHERE severity = 'HIGH';
SELECT 'Critical severity: ' || COUNT(*) FROM threat_intelligence 
WHERE severity = 'CRITICAL';
SQL_EOF
    fi
    
    # Add final status
    {
        echo ""
        echo "STATUS: COMPLETED SUCCESSFULLY"
        echo "=============================="
    } >> "${summary_file}"
    
    log_message "SUCCESS" "Summary report generated: ${summary_file}"
    
    # Display summary in terminal
    echo ""
    cat "${summary_file}"
    echo ""
}

# Main execution function - orchestrates the entire update process
main() {
    local start_time     # Script start timestamp
    local end_time       # Script end timestamp
    local duration       # Total execution time in seconds
    local successful_feeds  # Count of successfully processed feeds
    local failed_feeds   # Count of failed feeds
    local total_feeds    # Total number of configured feeds
    local feed_name      # Current feed name in loop
    local feed_url       # Current feed URL
    local feed_type      # Current feed type
    local refresh_hours  # Current feed refresh interval
    local description    # Current feed description
    local latest_raw     # Most recent raw file for current feed
    
    # Record start time
    start_time=$(date +%s)
    
    log_message "INFO" "Starting CyberGuard threat feed update process"
    log_message "INFO" "Project root directory: ${PROJECT_ROOT}"
    
    # Prevent concurrent execution with lock file
    check_lock
    
    # Ensure lock file is removed on script exit (normal or error)
    trap 'cleanup_lock' EXIT
    
    # Create required directory structure
    setup_directories
    
    # Initialize counters
    successful_feeds=0
    failed_feeds=0
    total_feeds=${#THREAT_FEEDS[@]}
    
    log_message "INFO" "Processing ${total_feeds} configured threat feeds"
    
    # Process each feed in the configuration array
    for feed_name in "${!THREAT_FEEDS[@]}"; do
        # Parse feed configuration string
        IFS='|' read -r feed_url feed_type refresh_hours description <<< "${THREAT_FEEDS[${feed_name}]}"
        
        log_message "INFO" "Processing feed: ${feed_name} - ${description}"
        
        # Step 1: Download the feed
        if download_feed "${feed_name}" "${feed_url}" "${feed_type}"; then
            # Step 2: Find the most recently downloaded raw file
            latest_raw=$(find "${THREAT_FEEDS_DIR}/raw" -name "${feed_name}_*.${feed_type}" -type f 2>/dev/null | sort -r | head -1)
            
            if [[ -n "${latest_raw}" ]] && validate_feed "${latest_raw}" "${feed_type}" "${feed_name}"; then
                # Step 3: Process the validated feed
                if process_feed "${feed_name}" "${latest_raw}" "${feed_type}"; then
                    successful_feeds=$((successful_feeds + 1))
                    log_message "SUCCESS" "Successfully processed ${feed_name}"
                else
                    failed_feeds=$((failed_feeds + 1))
                    log_message "ERROR" "Failed to process feed: ${feed_name}"
                fi
            else
                failed_feeds=$((failed_feeds + 1))
                log_message "ERROR" "Failed to validate feed: ${feed_name}"
            fi
        else
            failed_feeds=$((failed_feeds + 1))
            log_message "ERROR" "Failed to download feed: ${feed_name}"
        fi
        
        # Brief pause between feeds to avoid overwhelming servers
        sleep 1
    done
    
    # Check if any feeds were successfully processed
    if [[ ${successful_feeds} -gt 0 ]]; then
        log_message "SUCCESS" "Successfully processed ${successful_feeds}/${total_feeds} feeds"
        
        # Merge all processed feeds into unified database
        merge_feeds
        
        # Update SQLite database with merged data
        update_threat_database
        
        # Clean up old files to manage disk space
        cleanup_old_files
        
        # Calculate total execution time
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        
        # Generate and display summary report
        generate_summary "${duration}"
        
        log_message "SUCCESS" "Threat feed update completed in ${duration} seconds"
        
        # Report on any failures
        if [[ ${failed_feeds} -gt 0 ]]; then
            log_message "WARNING" "${failed_feeds} feeds failed to process"
        fi
    else
        # No feeds were successfully processed
        log_message "ERROR" "No feeds were successfully processed. ${failed_feeds} feeds failed."
        exit 1  # Exit with error code
    fi
    
    log_message "INFO" "Threat feed update process completed"
}

# Script entry point - execute main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi