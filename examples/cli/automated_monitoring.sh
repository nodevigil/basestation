#!/bin/bash
"""
Automated Monitoring Script

This script sets up continuous monitoring for DePIN infrastructure.
"""

set -e

# Configuration
CONFIG_FILE="config.json"
MONITOR_INTERVAL=3600  # 1 hour
PROTOCOL="sui"
ALERT_EMAIL="alerts@company.com"
LOG_FILE="logs/monitoring.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

# Create log directory
mkdir -p logs

# Setup monitoring environment
setup_monitoring() {
    log "Setting up PGDN monitoring environment..."
    
    # Check if pgdn is available
    if ! command -v pgdn &> /dev/null; then
        error "PGDN is not installed"
        exit 1
    fi
    
    # Verify configuration
    if [ ! -f "$CONFIG_FILE" ]; then
        warn "Config file not found, using defaults"
        CONFIG_FILE=""
    fi
    
    # Create monitoring directories
    mkdir -p monitoring/{scans,reports,alerts}
    
    log "Monitoring environment setup complete"
}

# Run monitoring cycle
run_monitoring_cycle() {
    local cycle_start=$(date +%s)
    log "Starting monitoring cycle #$(date +%Y%m%d%H%M%S)"
    
    # Update CVE database
    info "Updating CVE database..."
    local cmd="pgdn --cve-update --days-back 1"
    [ -n "$CONFIG_FILE" ] && cmd="$cmd --config $CONFIG_FILE"
    
    if eval $cmd; then
        log "CVE database updated successfully"
    else
        warn "CVE update failed, continuing monitoring"
    fi
    
    # Run reconnaissance to discover new targets
    info "Running reconnaissance..."
    cmd="pgdn --stage recon"
    [ -n "$CONFIG_FILE" ] && cmd="$cmd --config $CONFIG_FILE"
    [ -n "$PROTOCOL" ] && cmd="$cmd --protocol $PROTOCOL"
    
    if eval $cmd; then
        log "Reconnaissance completed"
    else
        error "Reconnaissance failed"
        return 1
    fi
    
    # Run security scan
    info "Running security scan..."
    cmd="pgdn --stage scan"
    [ -n "$CONFIG_FILE" ] && cmd="$cmd --config $CONFIG_FILE"
    [ -n "$PROTOCOL" ] && cmd="$cmd --protocol $PROTOCOL"
    
    local scan_output=$(eval $cmd 2>&1)
    local scan_exit_code=$?
    
    if [ $scan_exit_code -eq 0 ]; then
        log "Security scan completed"
        
        # Extract scan metrics
        local vulnerabilities=$(echo "$scan_output" | grep -o "vulnerabilities found: [0-9]*" | grep -o "[0-9]*" || echo "0")
        local targets_scanned=$(echo "$scan_output" | grep -o "targets scanned: [0-9]*" | grep -o "[0-9]*" || echo "0")
        
        info "Scan results: $vulnerabilities vulnerabilities found across $targets_scanned targets"
        
        # Check for high-severity findings
        if [ "$vulnerabilities" -gt 0 ]; then
            warn "Vulnerabilities detected - generating alert report"
            generate_alert_report "$vulnerabilities"
        fi
    else
        error "Security scan failed"
        echo "$scan_output" >> "$LOG_FILE"
        return 1
    fi
    
    # Process results
    info "Processing scan results..."
    cmd="pgdn --stage process"
    [ -n "$CONFIG_FILE" ] && cmd="$cmd --config $CONFIG_FILE"
    
    if eval $cmd; then
        log "Result processing completed"
    else
        warn "Result processing failed"
    fi
    
    # Calculate cycle time
    local cycle_end=$(date +%s)
    local cycle_duration=$((cycle_end - cycle_start))
    log "Monitoring cycle completed in ${cycle_duration}s"
    
    return 0
}

# Generate alert report for high-priority findings
generate_alert_report() {
    local vuln_count=$1
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local alert_file="monitoring/alerts/alert_${timestamp}.json"
    
    info "Generating alert report..."
    
    # Get latest scan ID
    local scan_id=$(sqlite3 scanning.db "SELECT MAX(id) FROM scans;" 2>/dev/null || echo "1")
    
    # Generate detailed report
    local cmd="pgdn --stage report --scan-id $scan_id --format json --output $alert_file"
    [ -n "$CONFIG_FILE" ] && cmd="$cmd --config $CONFIG_FILE"
    
    if eval $cmd; then
        log "Alert report generated: $alert_file"
        
        # Send email alert if configured
        if [ -n "$ALERT_EMAIL" ]; then
            send_email_alert "$alert_file" "$vuln_count"
        fi
    else
        error "Failed to generate alert report"
    fi
}

# Send email alert
send_email_alert() {
    local report_file=$1
    local vuln_count=$2
    
    info "Sending email alert to $ALERT_EMAIL..."
    
    # Get latest scan ID
    local scan_id=$(sqlite3 scanning.db "SELECT MAX(id) FROM scans;" 2>/dev/null || echo "1")
    
    local cmd="pgdn --stage report --scan-id $scan_id --email --recipient $ALERT_EMAIL"
    [ -n "$CONFIG_FILE" ] && cmd="$cmd --config $CONFIG_FILE"
    
    if eval $cmd; then
        log "Email alert sent successfully"
    else
        warn "Failed to send email alert"
    fi
}

# Monitor system health
check_system_health() {
    info "Checking system health..."
    
    # Check disk space
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ "$disk_usage" -gt 90 ]; then
        warn "Disk usage is high: ${disk_usage}%"
    fi
    
    # Check memory usage
    local mem_usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
    if [ "$mem_usage" -gt 90 ]; then
        warn "Memory usage is high: ${mem_usage}%"
    fi
    
    # Check database size
    if [ -f "scanning.db" ]; then
        local db_size=$(du -h scanning.db | cut -f1)
        info "Database size: $db_size"
    fi
    
    # Check log file size
    if [ -f "$LOG_FILE" ]; then
        local log_size=$(du -h "$LOG_FILE" | cut -f1)
        info "Log file size: $log_size"
        
        # Rotate log if too large
        local log_size_mb=$(du -m "$LOG_FILE" | cut -f1)
        if [ "$log_size_mb" -gt 100 ]; then
            warn "Log file is large, rotating..."
            mv "$LOG_FILE" "${LOG_FILE}.$(date +%Y%m%d_%H%M%S)"
            touch "$LOG_FILE"
        fi
    fi
}

# Generate monitoring summary
generate_monitoring_summary() {
    local summary_file="monitoring/daily_summary_$(date +%Y%m%d).txt"
    
    info "Generating monitoring summary..."
    
    cat > "$summary_file" << EOF
PGDN Monitoring Summary - $(date +%Y-%m-%d)
==========================================

Monitoring Configuration:
- Protocol: $PROTOCOL
- Interval: ${MONITOR_INTERVAL}s
- Alert Email: $ALERT_EMAIL

System Status:
- Disk Usage: $(df / | awk 'NR==2 {print $5}')
- Memory Usage: $(free | awk 'NR==2{printf "%.0f%%", $3*100/$2}')
- Database Size: $(du -h scanning.db 2>/dev/null | cut -f1 || echo "N/A")

Recent Activity:
- Scans performed: $(grep "Security scan completed" "$LOG_FILE" | tail -24 | wc -l)
- Vulnerabilities found: $(grep "vulnerabilities found" "$LOG_FILE" | tail -24 | grep -o "[0-9]*" | awk '{sum+=$1} END {print sum+0}')
- Alerts generated: $(ls monitoring/alerts/ 2>/dev/null | wc -l)

Last 5 log entries:
$(tail -5 "$LOG_FILE")
EOF

    log "Monitoring summary saved to: $summary_file"
}

# Cleanup old files
cleanup_old_files() {
    info "Cleaning up old files..."
    
    # Remove reports older than 30 days
    find monitoring/reports/ -name "*.json" -mtime +30 -delete 2>/dev/null || true
    
    # Remove alerts older than 7 days
    find monitoring/alerts/ -name "*.json" -mtime +7 -delete 2>/dev/null || true
    
    # Remove old summaries
    find monitoring/ -name "daily_summary_*.txt" -mtime +30 -delete 2>/dev/null || true
    
    info "Cleanup completed"
}

# Main monitoring loop
start_monitoring() {
    log "Starting PGDN continuous monitoring..."
    log "Monitoring interval: ${MONITOR_INTERVAL}s"
    log "Protocol filter: $PROTOCOL"
    
    # Setup signal handlers
    trap 'log "Monitoring stopped"; exit 0' SIGTERM SIGINT
    
    while true; do
        # Run monitoring cycle
        if run_monitoring_cycle; then
            log "Monitoring cycle successful"
        else
            error "Monitoring cycle failed"
        fi
        
        # Check system health
        check_system_health
        
        # Generate summary once per day
        local hour=$(date +%H)
        if [ "$hour" = "06" ]; then
            generate_monitoring_summary
            cleanup_old_files
        fi
        
        # Wait for next cycle
        info "Waiting ${MONITOR_INTERVAL}s for next monitoring cycle..."
        sleep "$MONITOR_INTERVAL"
    done
}

# Display usage
usage() {
    cat << EOF
Automated PGDN Monitoring Script

Usage: $0 [OPTIONS] COMMAND

Commands:
    start           Start continuous monitoring
    cycle           Run single monitoring cycle
    summary         Generate monitoring summary
    cleanup         Clean up old files

Options:
    -c, --config FILE       Configuration file
    -i, --interval SECONDS  Monitoring interval (default: 3600)
    -p, --protocol PROTO    Protocol filter (default: sui)
    -e, --email EMAIL       Alert email address
    -h, --help             Show this help

Examples:
    $0 start                        # Start continuous monitoring
    $0 -i 1800 start               # Monitor every 30 minutes
    $0 -e admin@company.com start   # Set alert email
    $0 cycle                        # Run single cycle
    
EOF
}

# Main function
main() {
    local command=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            start|cycle|summary|cleanup)
                command="$1"
                shift
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -i|--interval)
                MONITOR_INTERVAL="$2"
                shift 2
                ;;
            -p|--protocol)
                PROTOCOL="$2"
                shift 2
                ;;
            -e|--email)
                ALERT_EMAIL="$2"
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
    
    # Setup environment
    setup_monitoring
    
    # Execute command
    case $command in
        start)
            start_monitoring
            ;;
        cycle)
            run_monitoring_cycle
            ;;
        summary)
            generate_monitoring_summary
            ;;
        cleanup)
            cleanup_old_files
            ;;
        *)
            error "No command specified"
            usage
            exit 1
            ;;
    esac
}

# Run main with all arguments
main "$@"
