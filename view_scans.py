#!/usr/bin/env python3
"""
Utility script to view scan results from the validator_addresses table
"""

from services.scan_service import ScanService
from repositories.validator_repository import ValidatorRepository
import json
import sys
from datetime import datetime

def print_scan_summary():
    """Print a summary of all scans"""
    print("=" * 60)
    print("VALIDATOR SCAN RESULTS SUMMARY")
    print("=" * 60)
    
    scan_service = ScanService()
    summaries = scan_service.get_all_scan_summaries(limit=50)
    
    if not summaries:
        print("No scan results found.")
        return
    
    print(f"Total scans found: {len(summaries)}")
    print("-" * 60)
    
    for summary in summaries:
        print(f"Validator: {summary['validator_address']}")
        print(f"IP Address: {summary['ip_address']}")
        print(f"Score: {summary['score']}")
        print(f"Scan Date: {summary['scan_date']}")
        print(f"Flags: {summary['flags']}")
        print("-" * 60)

def print_validator_scans(validator_address):
    """Print all scans for a specific validator"""
    print(f"Scan results for validator: {validator_address}")
    print("=" * 60)
    
    scan_service = ScanService()
    summary = scan_service.get_scan_summary_for_validator(validator_address)
    
    if not summary:
        print(f"No scan results found for validator {validator_address}")
        return
    
    print(f"Total scans: {summary['total_scans']}")
    print(f"Latest scan date: {summary['latest_scan']['scan_date']}")
    print(f"Latest IP: {summary['latest_scan']['ip_address']}")
    print(f"Latest score: {summary['latest_scan']['score']}")
    print(f"Latest flags: {summary['latest_scan']['flags']}")
    print("-" * 60)

def print_ip_scans(ip_address):
    """Print all scans for a specific IP"""
    print(f"Scan results for IP: {ip_address}")
    print("=" * 60)
    
    scan_service = ScanService()
    summary = scan_service.get_scan_summary_for_ip(ip_address)
    
    if not summary:
        print(f"No scan results found for IP {ip_address}")
        return
    
    print(f"Total scans: {summary['total_scans']}")
    print(f"Validator: {summary['latest_scan']['validator_address']}")
    print(f"Latest scan date: {summary['latest_scan']['scan_date']}")
    print(f"Latest score: {summary['latest_scan']['score']}")
    print(f"Latest flags: {summary['latest_scan']['flags']}")
    print("-" * 60)

def print_validators_with_scans():
    """Print all validators that have scan results"""
    print("VALIDATORS WITH SCAN RESULTS")
    print("=" * 60)
    
    with ValidatorRepository() as validator_repo:
        validators = validator_repo.get_all_validators()
        scan_service = ScanService()
        
        validators_with_scans = []
        for validator in validators:
            summary = scan_service.get_scan_summary_for_validator(validator.address)
            if summary:
                validators_with_scans.append({
                    'validator': validator,
                    'summary': summary
                })
        
        if not validators_with_scans:
            print("No validators with scan results found.")
            return
        
        for item in validators_with_scans:
            validator = item['validator']
            summary = item['summary']
            print(f"Validator: {validator.address}")
            print(f"Name: {validator.name or 'N/A'}")
            print(f"Source: {validator.source}")
            print(f"Total scans: {summary['total_scans']}")
            print(f"Latest scan: {summary['latest_scan']['scan_date']}")
            print(f"Latest score: {summary['latest_scan']['score']}")
            print("-" * 40)

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python view_scans.py summary              - Show summary of all scans")
        print("  python view_scans.py validator <address>  - Show scans for specific validator")
        print("  python view_scans.py ip <ip_address>      - Show scans for specific IP")
        print("  python view_scans.py validators           - Show all validators with scans")
        return
    
    command = sys.argv[1].lower()
    
    if command == "summary":
        print_scan_summary()
    elif command == "validator" and len(sys.argv) > 2:
        print_validator_scans(sys.argv[2])
    elif command == "ip" and len(sys.argv) > 2:
        print_ip_scans(sys.argv[2])
    elif command == "validators":
        print_validators_with_scans()
    else:
        print("Invalid command or missing arguments.")
        print("Use 'python view_scans.py' without arguments to see usage.")

if __name__ == "__main__":
    main()
