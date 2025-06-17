# CVE Database Updater

The CVE Database Updater automatically fetches the latest Common Vulnerabilities and Exposures (CVE) data from the National Vulnerability Database (NVD) API and stores it in the local PostgreSQL database for use by the scanner.

## Features

- **Database Storage**: Stores CVE data in PostgreSQL database for fast lookups
- **Automatic Updates**: Daily scheduled updates from NVD API
- **Smart Matching**: Matches service banners against stored CVE data
- **Comprehensive Data**: Stores CVSS scores, severity levels, affected products
- **Update Logging**: Tracks all update operations with detailed statistics
- **API Rate Limiting**: Respects NVD API rate limits with proper delays

## Database Schema

### CVE Records Table (`cve_records`)
- `cve_id`: Unique CVE identifier (e.g., CVE-2019-20372)  
- `published_date`: Original publication date
- `last_modified`: Last modification date from NVD
- `description`: Vulnerability description
- `severity`: CVSS severity level (LOW, MEDIUM, HIGH, CRITICAL)
- `cvss_score`: CVSS base score
- `affected_products`: JSON array of affected software/versions
- `raw_data`: Complete NVD API response data

### Update Logs Table (`cve_update_logs`)
- `update_date`: When the update was performed  
- `total_cves_processed`: Number of CVEs processed
- `new_cves_added`: New CVEs added to database
- `status`: Update status (SUCCESS, FAILED, PARTIAL)
- `processing_time_seconds`: Time taken for update

## Usage

### Initial Database Population

First time setup - populate database with recent CVEs:
```bash
python main.py --update-cves --initial-cves
```

### Regular Updates

Update with latest CVE data:
```bash
python main.py --update-cves
```

Force update (overwrite existing):
```bash
python main.py --update-cves --replace-cves
```

### Scheduled Daily Updates

Start the scheduler daemon for automatic daily updates:
```bash
python main.py --start-cve-scheduler
```

Custom update time:
```bash
python main.py --start-cve-scheduler --cve-update-time 03:30
```

### Database Statistics

Check database status:
```bash
python -m utils.cve_updater --stats
```

### Manual CVE Operations

```bash
# Direct module usage for testing
python -m utils.cve_updater --update --initial  # Initial population
python -m utils.cve_updater --update            # Regular update  
python -m utils.cve_updater --stats             # Show statistics
python -m utils.cve_updater --search "nginx/1.14.0"  # Search CVEs
```

## Error Handling

The updater includes comprehensive error handling:

- **Network Issues**: Handles API timeouts and connection errors
- **Parsing Errors**: Skips malformed CVE data and continues processing
- **File Backup**: Creates backup before making changes
- **Rate Limiting**: Includes delays between API calls to respect rate limits

## Testing

Test the CVE updater functionality:
```bash
python test_cve_updater.py
```

## Configuration

The updater can be configured by modifying these constants in `utils/cve_updater.py`:

- `NVD_API_BASE`: NVD API endpoint URL
- `SOFTWARE_PATTERNS`: Regex patterns for software version detection
- `timeout`: HTTP request timeout (default: 30 seconds)

## Manual Usage

You can also use the CVE updater as a standalone module:

```python
from utils.cve_updater import update_cves

# Update with merge
success = update_cves(merge=True, save_report=True)

# Replace existing CVEs
success = update_cves(merge=False, save_report=True)
```

## Troubleshooting

### Common Issues

1. **Network Connectivity**: Ensure internet access to reach NVD API
2. **API Rate Limits**: The tool includes delays, but heavy usage may hit limits
3. **File Permissions**: Ensure write access to scanner.py and backup directories
4. **JSON Parsing**: Malformed API responses are handled gracefully

### Log Files

Check application logs for detailed error information when updates fail.

### Recovery

If an update corrupts the scanner file, restore from the automatic backup:
```bash
cp scanning/scanner.py.backup scanning/scanner.py
```
