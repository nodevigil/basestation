#!/usr/bin/env python3
"""
CLI script to manage validator addresses in the database
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.validator_service import ValidatorService
from repositories.validator_repository import ValidatorRepository
import argparse
import json

def main():
    parser = argparse.ArgumentParser(description='Manage validator addresses')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Import Sui validators
    import_parser = subparsers.add_parser('import-sui', help='Import Sui validators')
    
    # List validators
    list_parser = subparsers.add_parser('list', help='List validators')
    list_parser.add_argument('--source', help='Filter by source')
    list_parser.add_argument('--all', action='store_true', help='Include inactive validators')
    
    # Add validator
    add_parser = subparsers.add_parser('add', help='Add a validator manually')
    add_parser.add_argument('address', help='Validator address')
    add_parser.add_argument('--name', help='Validator name')
    
    # Deactivate validator
    deactivate_parser = subparsers.add_parser('deactivate', help='Deactivate a validator')
    deactivate_parser.add_argument('address', help='Validator address')
    
    # Stats
    stats_parser = subparsers.add_parser('stats', help='Show validator statistics')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    service = ValidatorService()
    
    try:
        if args.command == 'import-sui':
            addresses = service.import_sui_validators()
            print(f"Successfully imported {len(addresses)} Sui validators")
            
        elif args.command == 'list':
            validators = service.get_active_validators(source=args.source)
            if not validators:
                print("No validators found")
                return
            
            print(f"Found {len(validators)} validators:")
            for v in validators:
                print(f"  Address: {v['address']}")
                print(f"  Name: {v['name'] or 'N/A'}")
                print(f"  Source: {v['source']}")
                print(f"  Created: {v['created_at']}")
                print(f"  Active: {v['active']}")
                print()
                
        elif args.command == 'add':
            result = service.add_manual_validator(args.address, args.name)
            if result:
                print(f"Successfully added validator: {result['address']}")
            else:
                print("Failed to add validator")
                
        elif args.command == 'deactivate':
            success = service.deactivate_validator(args.address)
            if success:
                print(f"Successfully deactivated validator: {args.address}")
            else:
                print(f"Validator not found: {args.address}")
                
        elif args.command == 'stats':
            stats = service.get_validator_stats()
            print("Validator Statistics:")
            print(f"  Total validators: {stats['total_validators']}")
            print(f"  Active validators: {stats['active_validators']}")
            print(f"  Inactive validators: {stats['inactive_validators']}")
            print("\nBy source:")
            for source, counts in stats['sources'].items():
                print(f"  {source}: {counts['active']}/{counts['total']} active")
                
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
