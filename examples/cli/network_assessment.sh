#!/bin/bash
"""
Network Assessment Script

This script demonstrates comprehensive network security assessment using PGDN CLI.
"""

set -e

# Configuration
CONFIG_FILE="config.json"
LOG_LEVEL="INFO"
PROTOCOL="sui"
REPORT_EMAIL="security@company.com"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if pgdn is installed
    if ! command -v pgdn &> /dev/null; then
        error "PGDN is not installed. Please install with: pip install pgdn"
        exit 1
    fi
    
    # Check if config file exists
    if [ ! -f "$CONFIG_FILE" ]; then
        warn "Config file $CONFIG_FILE not found. Using default configuration."
        CONFIG_FILE=""
    fi
    
    log "Prerequisites check completed"
}

# Update CVE database
update_cve_database() {
    log "Updating CVE database..."
    
    if [ -n "$CONFIG_FILE" ]; then
        pgdn --config "$CONFIG_FILE" --cve-update --days-back 30
    else
        pgdn --cve-update --days-back 30
    fi
    
    if [ $? -eq 0 ]; then
        log "CVE database updated successfully"
    else
        error "Failed to update CVE database"
        return 1
    fi
}

# Run reconnaissance
run_reconnaissance() {
    log "Starting reconnaissance phase..."
    
    local cmd="pgdn --stage recon"
    [ -n "$CONFIG_FILE" ] && cmd="$cmd --config $CONFIG_FILE"
    [ -n "$LOG_LEVEL" ] && cmd="$cmd --log-level $LOG_LEVEL"
    
    eval $cmd
    
    if [ $? -eq 0 ]; then
        log "Reconnaissance completed successfully"
        return 0
    else
        error "Reconnaissance failed"
        return 1
    fi
}

# Run security scanning
run_security_scan() {
    log "Starting security scanning phase..."
    
    local cmd="pgdn --stage scan"
    [ -n "$CONFIG_FILE" ] && cmd="$cmd --config $CONFIG_FILE"
    [ -n "$PROTOCOL" ] && cmd="$cmd --protocol $PROTOCOL"
    [ -n "$LOG_LEVEL" ] && cmd="$cmd --log-level $LOG_LEVEL"
    
    eval $cmd
    
    if [ $? -eq 0 ]; then
        log "Security scanning completed successfully"
        return 0
    else
        error "Security scanning failed"
        return 1
    fi
}

# Process scan results
process_results() {
    log "Processing scan results..."
    
    local cmd="pgdn --stage process"
    [ -n "$CONFIG_FILE" ] && cmd="$cmd --config $CONFIG_FILE"
    [ -n "$LOG_LEVEL" ] && cmd="$cmd --log-level $LOG_LEVEL"
    
    eval $cmd
    
    if [ $? -eq 0 ]; then
        log "Result processing completed successfully"
        return 0
    else
        error "Result processing failed"
        return 1
    fi
}

# Run risk scoring
run_risk_scoring() {
    log "Running risk scoring..."
    
    local cmd="pgdn --stage score --force-rescore"
    [ -n "$CONFIG_FILE" ] && cmd="$cmd --config $CONFIG_FILE"
    [ -n "$LOG_LEVEL" ] && cmd="$cmd --log-level $LOG_LEVEL"
    
    eval $cmd
    
    if [ $? -eq 0 ]; then
        log "Risk scoring completed successfully"
        return 0
    else
        error "Risk scoring failed"
        return 1
    fi
}

# Generate and send reports
generate_reports() {
    log "Generating security reports..."
    
    # Get the latest scan ID (this is a simplified approach)
    # In a real scenario, you might need to query the database or parse logs
    local scan_id=$(sqlite3 scanning.db "SELECT MAX(id) FROM scans;" 2>/dev/null || echo "1")
    
    if [ -z "$scan_id" ] || [ "$scan_id" = "" ]; then
        warn "Could not determine scan ID, using default"
        scan_id="1"
    fi
    
    # Generate JSON report
    log "Generating JSON report for scan ID: $scan_id"
    local cmd="pgdn --stage report --scan-id $scan_id --format json --auto-save"
    [ -n "$CONFIG_FILE" ] && cmd="$cmd --config $CONFIG_FILE"
    
    eval $cmd
    
    if [ $? -eq 0 ]; then
        log "JSON report generated successfully"
    else
        error "Failed to generate JSON report"
    fi
    
    # Generate CSV report
    log "Generating CSV report for scan ID: $scan_id"
    cmd="pgdn --stage report --scan-id $scan_id --format csv --auto-save"
    [ -n "$CONFIG_FILE" ] && cmd="$cmd --config $CONFIG_FILE"
    
    eval $cmd
    
    if [ $? -eq 0 ]; then
        log "CSV report generated successfully"
    else
        error "Failed to generate CSV report"
    fi
    
    # Send email report if configured
    if [ -n "$REPORT_EMAIL" ]; then
        log "Sending email report to: $REPORT_EMAIL"
        cmd="pgdn --stage report --scan-id $scan_id --email --recipient $REPORT_EMAIL"
        [ -n "$CONFIG_FILE" ] && cmd="$cmd --config $CONFIG_FILE"
        
        eval $cmd
        
        if [ $? -eq 0 ]; then
            log "Email report sent successfully"
        else
            warn "Failed to send email report (check email configuration)"
        fi
    fi
}

# Run full assessment pipeline
run_full_pipeline() {
    log "Starting comprehensive network security assessment..."
    
    # Update CVE database first
    update_cve_database || warn "CVE update failed, continuing with assessment"
    
    # Run individual stages
    run_reconnaissance || { error "Assessment failed at reconnaissance stage"; exit 1; }
    run_security_scan || { error "Assessment failed at scanning stage"; exit 1; }
    process_results || { error "Assessment failed at processing stage"; exit 1; }
    run_risk_scoring || { error "Assessment failed at scoring stage"; exit 1; }
    
    # Generate reports
    generate_reports
    
    log "Network security assessment completed successfully!"
}

# Display usage information
usage() {
    cat << EOF
Network Assessment Script

Usage: $0 [OPTIONS]

Options:
    -c, --config FILE     Configuration file to use (default: config.json)
    -p, --protocol PROTO  Protocol filter (default: sui)
    -e, --email EMAIL     Email address for reports
    -l, --log-level LEVEL Log level (DEBUG, INFO, WARNING, ERROR)
    -h, --help           Show this help message

Examples:
    $0                                    # Run full assessment with defaults
    $0 -c custom.json -p solana          # Custom config and protocol
    $0 -e admin@company.com              # Send reports to specific email
    
EOF
}

# Main function
main() {
    log "PGDN Network Security Assessment"
    log "================================"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -p|--protocol)
                PROTOCOL="$2"
                shift 2
                ;;
            -e|--email)
                REPORT_EMAIL="$2"
                shift 2
                ;;
            -l|--log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Run assessment
    check_prerequisites
    run_full_pipeline
    
    log "Assessment completed. Check the reports/ directory for detailed results."
}

# Run main function with all arguments
main "$@"
