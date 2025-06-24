
# PGDN Scan Levels: Technical Specification

## Overview

PGDN implements a structured, multi-level scanning architecture to assess the risk and exposure of decentralized infrastructure nodes. Scan levels range from lightweight fingerprinting to deep, protocol-specific behavioral analysis.

---

## Scan Level Definitions

| Level | Focus                      | Description                          |
|-------|----------------------------|--------------------------------------|
| 1     | Light Recon                | Safe, fast, surface-level scan       |
| 2     | Infra + Vulnerability Scan| Service and CVE exposure analysis    |
| 3     | Deep Protocol Inspection   | Stateful, aggressive protocol logic  |

---

## Level 1 — Light Recon

**Purpose**: Fast surface discovery. No heavy enumeration, no protocol emulation.

### Tools & Actions:
- `generic_scanner.py`
  - `scan_ports(top_n=100)`
  - `get_service_banners()`
  - `guess_os_from_banner()`
- `web_scanner.py`
  - `fetch_http_headers()`
  - `whatweb_fingerprint()`
  - `check_ssl_certificate()`
- `filecoin_scanner.py`
  - `get_node_info()`
  - `check_rpc_auth()`
  - `check_graphql_open()`
- `sui_scanner.py`
  - `get_node_metadata()`
  - `check_validator_health_basic()`
- `node_scanner_agent.py` or `geo_scanner.py`
  - `get_geo_from_ip()` (MaxMind)
  - `get_asn()`

---

## Level 2 — Infrastructure + CVE Analysis

**Purpose**: Broader port coverage and basic vulnerability discovery.

### Tools & Actions:
- **All Level 1**
- `generic_scanner.py`
  - `scan_ports(full=True)`
  - `detect_services()`
  - `fingerprint_os()`
- `vulnerability_scanner.py`
  - `search_cves_for_banner()`
  - `run_nuclei_scan()`
  - `check_for_known_misconfigs()`
- `filecoin_scanner.py`
  - `check_rpc_methods()`
  - `check_metrics_for_sensitive_data()`
- `sui_scanner.py`
  - `check_unauth_metrics()`
  - `verify_version_security()`

---

## Level 3 — Deep Protocol Inspection

**Purpose**: Stateful, invasive behavior testing and protocol security.

### Tools & Actions:
- **All Level 1 + 2**
- `filecoin_scanner.py`
  - `simulate_storage_deal()`
  - `query_wallet_balance()`
  - `analyze_sector_state()`
- `sui_scanner.py`
  - `send_dummy_transaction(testnet)`
  - `check_validator_config()`
  - `query_chain_stats()`
- `vulnerability_scanner.py`
  - `fuzz_open_ports()`
  - `docker_exposure_scan()`
- `web_scanner.py`
  - `run_endpoint_fuzzer()`
  - `detect_path_traversal_or_debug_endpoints()`

---

## Summary Table

| Scanner               | L1                         | L2                              | L3                               |
|-----------------------|----------------------------|----------------------------------|-----------------------------------|
| `generic_scanner`     | Top ports, banners         | Full TCP, service map, OS        | Fuzz ports, aggressive fingerprint |
| `web_scanner`         | HTTP headers, TLS          | Misconfig checks                 | Fuzz URLs, test auth              |
| `vulnerability_scanner` | —                        | Nuclei, CVE matching             | Docker scan, active fuzzing       |
| `filecoin_scanner`    | Version, peer ID, RPC auth | Metrics, unauth RPC              | Simulated deals, wallet API       |
| `sui_scanner`         | Version, `/metrics`        | Validator health                 | Tx emulation, chain drift check   |
| `geo_scanner`         | GeoIP, ASN                 | GeoIP, ASN                       | GeoIP, ASN                        |

---

## Implementation Instructions (Execution-Focused)

> Implement **scan level support** (levels 1–3) across the PGDN scanning system.

### Goals:
1. **Add `scan_level` support** to all relevant scanners:
   - `generic_scanner.py`
   - `web_scanner.py`
   - `vulnerability_scanner.py`
   - `filecoin_scanner.py`
   - `sui_scanner.py`

2. Refactor each scanner’s `scan(target, **kwargs)` method to:
   - Accept a `scan_level` integer (default to `1`)
   - Run specific internal methods depending on the scan level

3. Update the `ScanOrchestrator` to:
   - Accept a `scan_level` argument
   - Pass it through to all scanner calls

4. Follow the scan execution breakdown documented in this file

5. Ensure each scanner runs only what it should per level (fail gracefully if functionality is skipped)

6. Use the provided TDD plan and stub tests to validate:
   - Each level triggers only the correct function calls
   - Invalid `scan_level` input is handled

### GeoIP + ASN Enrichment

- Add a GeoIP and ASN enrichment step at **Level 1 and above**:
  - Use MaxMind GeoLite2 database locally
  - Extract and store:
    - `country_name`, `city_name`, `latitude`, `longitude`
    - `asn_number`, `asn_organization`
  - Add this logic to `node_scanner_agent.py` (or move to `geo_scanner.py` for separation)
  - Cache lookups for reuse

---

## TDD Instructions

Write unit tests to validate scan behavior per level:

```python
def test_level_1_skips_cve_scans():
    scanner = GenericScanner()
    scanner.scan('127.0.0.1', scan_level=1)
    assert not scanner.cve_scan_ran
```

Test:
- That the correct methods are called at each scan level
- That orchestrator passes down scan_level correctly
- That geoip/asn enrichment runs for level >= 1
- That scan_level defaults to 1
