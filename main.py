from discovery.sui import SuiDiscovery
from scanning.scanner import Scanner
from analysis.trust import TrustScorer
from scanning.sui_scanner import SuiSpecificScanner
from services.scan_service import ScanService
from repositories.validator_repository import ValidatorRepository
from repositories.scan_repository import ScanRepository

import json
import logging
import time

# Setup logging
logging.basicConfig(
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)

# Disable SQLAlchemy logging
logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)

def main():
    logging.info("🔍 Discovering Sui validator hosts...")
    discovery = SuiDiscovery()
    hosts = discovery.get_hosts()
    logging.info(f"✅ Found {len(hosts)} hosts")
    
    scan_service = ScanService()
    scanner = Scanner()
    sui_scanner = SuiSpecificScanner()
    scorer = TrustScorer()
    
    scan_interval_days = 7
    sleep_between_scans = 5  # seconds between scans to be respectful
    
    while True:
        # Get validators that need scanning (using the existing method that handles concurrency)
        with ScanRepository() as scan_repo:
            validator_ids_needing_scan = scan_repo.get_validators_needing_scan(days_ago=scan_interval_days)
        
        if not validator_ids_needing_scan:
            logging.info("🎯 All validators have been scanned recently. No scanning needed.")
            break
            
        logging.info(f"📋 Found {len(validator_ids_needing_scan)} validators that need scanning")
        
        # Process validators one by one
        for validator_id in validator_ids_needing_scan:
            # Double-check if this validator still needs scanning (handles multiple agents)
            with ScanRepository() as scan_repo:
                if scan_repo.has_recent_scan(validator_id, days=scan_interval_days):
                    logging.info(f"⏭️  Validator {validator_id} was already scanned by another agent, skipping")
                    continue
            
            # Get the validator address from the ID
            with ValidatorRepository() as validator_repo:
                validator = validator_repo.get_validator_by_id(validator_id)
                if not validator:
                    logging.error(f"Validator with id {validator_id} not found")
                    continue
                host = validator.address

            logging.info(f"🎯 Selected host for scanning: {host} (id: {validator_id})")
            
            # Resolve host to IP
            try:
                ip = discovery.resolve_hosts_to_ips([host])[0]
                logging.info(f"🌍 Resolved {host} to IP: {ip}")
            except Exception as e:
                logging.error(f"❌ DNS error for {host}: {e}")
                failed_result = {
                    "ip": host,
                    "score": None,
                    "flags": [],
                    "summary": f"DNS error: {e}",
                    "timestamp": None,
                    "hash": None,
                    "generic_scan": None,
                    "sui_specific_scan": None,
                    "failed": True
                }
                scan_service.save_scan_results([failed_result])
                continue

            # Perform the scanning
            results = []
            logging.info(f"🛡️  Scanning IP: {ip} (host: {host})")
            try:
                generic_result = scanner.scan(ip)
                sui_result = sui_scanner.scan(ip)
                combined_scan = {
                    "ip": ip,
                    "generic_scan": generic_result,
                    "sui_specific_scan": sui_result
                }
                results.append(combined_scan)
            except Exception as e:
                logging.error(f"❌ Scan failed for {ip}: {e}")
                failed_result = {
                    "ip": ip,
                    "score": None,
                    "flags": [],
                    "summary": str(e),
                    "timestamp": None,
                    "hash": None,
                    "generic_scan": None,
                    "sui_specific_scan": None,
                    "failed": True
                }
                scan_service.save_scan_results([failed_result])
                continue

            # Score the results
            scored_results = []
            for res in results:
                # Pass the *generic scan* into the scorer as before
                score_obj = scorer.score(res["generic_scan"])
                # Attach Sui-specific findings to the output
                output = {
                    "ip": res["ip"],
                    "score": score_obj["score"],
                    "flags": score_obj["flags"],
                    "summary": score_obj["summary"],
                    "timestamp": score_obj["timestamp"],
                    "hash": score_obj["hash"],
                    "generic_scan": res["generic_scan"],
                    "docker_exposure": score_obj["docker_exposure"],
                    "sui_specific_scan": res["sui_specific_scan"]
                }
                scored_results.append(output)

            # Save results
            scan_service.save_scan_results(scored_results)
            
            # Print results to console
            for r in scored_results:
                print(json.dumps(r, indent=2))
            
            logging.info(f"✅ Completed scan for {host} (id: {validator_id})")
            
            # Sleep between scans to be respectful and allow other agents to work
            time.sleep(sleep_between_scans)

        break
     
    logging.info("🏁 All validators have been scanned successfully!")

if __name__ == "__main__":
    main()
