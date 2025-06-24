## PGDN CLI Queue Support Test Summary

### ✅ COMMANDS THAT SUPPORT QUEUEING:

1. **Full Pipeline**
   - `pgdn --queue`
   - `pgdn --queue --org-id myorg`

2. **Individual Stages**
   - `pgdn --stage recon --queue`
   - `pgdn --stage scan --queue`
   - `pgdn --stage process --queue`
   - `pgdn --stage score --queue`
   - `pgdn --stage publish --scan-id 123 --queue`
   - `pgdn --stage report --queue`
   - `pgdn --stage signature --queue`
   - `pgdn --stage discovery --host 192.168.1.1 --queue`

3. **Target Scanning**
   - `pgdn --stage scan --target 192.168.1.1 --org-id myorg --queue`

4. **Parallel Operations**
   - `pgdn --parallel-targets 192.168.1.1 192.168.1.2 --queue`
   - `pgdn --parallel-stages recon scan --queue`

### ❌ COMMANDS THAT DO NOT SUPPORT QUEUEING:

1. **CVE Operations** (handled directly by CVEManager)
   - `pgdn --update-cves --queue` → Error: "CVE commands do not support queueing"
   - `pgdn --start-cve-scheduler --queue` → Error: "CVE commands do not support queueing"

2. **Signature Learning Operations** (handled directly by SignatureManager)
   - `pgdn --learn-signatures-from-scans --signature-protocol sui --queue` → Error: "Signature commands do not support queueing"
   - `pgdn --update-signature-flags --queue` → Error: "Signature commands do not support queueing"

3. **Administrative Commands** (queue management itself)
   - `pgdn --list-agents` (cannot be queued)
   - `pgdn --task-id abc123` (queue status check)
   - `pgdn --cancel-task abc123` (queue management)
   - `pgdn --list-tasks` (queue management)

All queueable commands work correctly and return task IDs for tracking.
Unsupported commands provide clear error messages with suggestions.
