# Scanner Type Selection Guide

The PGDN scanner now supports fine-grained control over which scanners and tools to run. This is particularly useful for testing, debugging, and troubleshooting specific issues.

## New CLI Options

### `--scanners` 
Specify which modular scanners to run:
- `generic` - Port scanning and banner grabbing
- `web` - HTTP/HTTPS analysis  
- `vulnerability` - CVE lookup and vulnerability detection
- `geo` - GeoIP and ASN lookup
- `sui` - Sui blockchain-specific scans
- `filecoin` - Filecoin blockchain-specific scans

### `--external-tools`
Specify which external tools to run:
- `nmap` - Network mapper for port scanning
- `whatweb` - Web technology fingerprinting
- `ssl_test` - SSL/TLS certificate analysis
- `docker_exposure` - Docker API exposure check

### Shortcut Options
- `--nmap-only` - Run only nmap scan (equivalent to `--scanners --external-tools nmap`)
- `--geo-only` - Run only GeoIP lookup (equivalent to `--scanners geo --external-tools`)

## Usage Examples

### Debug Nmap Issues
```bash
# Run only nmap to see what ports it actually detects
pgdn --stage scan --target example.com --org-id myorg --nmap-only --debug

# Run only nmap with specific scan level
pgdn --stage scan --target example.com --org-id myorg --nmap-only --scan-level 2
```

### Test GeoIP Only
```bash
# Run only GeoIP lookup
pgdn --stage scan --target example.com --org-id myorg --geo-only

# Test geo with debug
pgdn --stage scan --target example.com --org-id myorg --geo-only --debug
```

### Custom Scanner Combinations
```bash
# Run only generic and web scanners
pgdn --stage scan --target example.com --org-id myorg --scanners generic web

# Run only nmap and whatweb tools
pgdn --stage scan --target example.com --org-id myorg --external-tools nmap whatweb

# Run geo + nmap combination
pgdn --stage scan --target example.com --org-id myorg --scanners geo --external-tools nmap

# Run only vulnerability scanner
pgdn --stage scan --target example.com --org-id myorg --scanners vulnerability
```

### Disable External Tools
```bash
# Run scanners but no external tools
pgdn --stage scan --target example.com --org-id myorg --external-tools

# Run only modular scanners, no nmap/whatweb/etc
pgdn --stage scan --target example.com --org-id myorg --scanners generic web vulnerability geo --external-tools
```

## Debugging Your Issue

Based on your example output showing incorrect port results:

```json
"open_ports":[22,80,443,2375,3306]
```

This suggests the fallback scan is being used instead of proper nmap. To debug:

### 1. Test nmap directly
```bash
pgdn --stage scan --target example.com --org-id myorg --nmap-only --debug
```

### 2. Check if nmap is working
```bash
# Test with a simple target
pgdn --stage scan --target google.com --org-id myorg --nmap-only

# Compare with manual nmap
nmap -T4 -p 22,80,443,2375,3306,8080,9000,9184 example.com
```

### 3. Test without external tools to see modular scanner results
```bash
pgdn --stage scan --target example.com --org-id myorg --scanners generic --external-tools
```

### 4. Enable debug mode to see what's happening
```bash
pgdn --stage scan --target example.com --org-id myorg --debug --nmap-only
```

The debug output will include `_debug_info` section showing:
- Which scanners were enabled
- Which external tools were enabled  
- Raw nmap data
- Scanner execution details

## Available Scanner Types

You can see all available scanners with:
```bash
pgdn --list-agents  # Shows all agents including scanners
```

The modular scanners are:
- **generic**: Basic port scanning and service detection
- **web**: HTTP/HTTPS analysis and technology detection
- **vulnerability**: CVE lookup and vulnerability assessment
- **geo**: GeoIP geolocation and ASN information
- **sui**: Sui blockchain network analysis (scan level 3)
- **filecoin**: Filecoin network analysis (scan level 3)

The external tools are:
- **nmap**: Industry-standard network mapper
- **whatweb**: Web application fingerprinting
- **ssl_test**: SSL/TLS security assessment
- **docker_exposure**: Docker API exposure detection

## Troubleshooting Tips

1. **Fallback scan being used**: Use `--nmap-only --debug` to see nmap execution
2. **Wrong port results**: Compare `--nmap-only` vs `--scanners generic` results
3. **Missing tools**: Use `--external-tools nmap` to test specific tools
4. **Permission issues**: nmap may fallback to connect scan without sudo
5. **Network issues**: Test with reliable targets like `google.com` first

## Scan Levels

The scan levels still work with scanner selection:
- **Level 1**: Basic scanning
- **Level 2**: Standard scanning with GeoIP  
- **Level 3**: Comprehensive scanning with protocol-specific analysis

Example:
```bash
pgdn --stage scan --target example.com --org-id myorg --scan-level 3 --scanners sui filecoin
```
