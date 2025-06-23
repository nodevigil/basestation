#!/usr/bin/env python3
"""
Signature Learning Example

This example demonstrates protocol signature learning and management.
"""

from pgdn import initialize_application, SignatureManager, Scanner
import time

def main():
    # Initialize PGDN
    print("Initializing PGDN for signature learning...")
    config = initialize_application("config.json")
    
    # Create signature manager and scanner
    signature_manager = SignatureManager()
    scanner = Scanner(config)
    
    # Example 1: Learn signatures from existing scans
    print("\n=== Learning Signatures from Scans ===")
    
    # Learn signatures for Sui protocol
    print("Learning Sui protocol signatures...")
    learn_result = signature_manager.learn_from_scans(
        protocol='sui',
        min_confidence=0.7,
        max_examples=1000
    )
    
    if learn_result['success']:
        print(f"✓ Signature learning completed")
        print(f"  New signatures learned: {learn_result.get('new_signatures', 0)}")
        print(f"  Total signatures: {learn_result.get('total_signatures', 0)}")
        print(f"  Average confidence: {learn_result.get('avg_confidence', 0):.2f}")
        print(f"  Processing time: {learn_result.get('processing_time', 0):.2f}s")
    else:
        print(f"✗ Signature learning failed: {learn_result['error']}")
    
    # Example 2: Signature statistics
    print("\n=== Signature Statistics ===")
    
    stats_result = signature_manager.show_statistics(protocol_filter='sui')
    
    if stats_result['success']:
        print(f"Sui Protocol Signature Statistics:")
        print(f"  Total signatures: {stats_result.get('total_signatures', 0)}")
        print(f"  High confidence (>0.9): {stats_result.get('high_confidence', 0)}")
        print(f"  Medium confidence (0.7-0.9): {stats_result.get('medium_confidence', 0)}")
        print(f"  Low confidence (<0.7): {stats_result.get('low_confidence', 0)}")
        print(f"  Unique patterns: {stats_result.get('unique_patterns', 0)}")
        print(f"  Coverage: {stats_result.get('coverage_percentage', 0):.1f}%")
    else:
        print(f"✗ Failed to get statistics: {stats_result['error']}")
    
    # Example 3: Update signature flags
    print("\n=== Updating Signature Flags ===")
    
    update_result = signature_manager.update_signature_flags(protocol_filter='sui')
    
    if update_result['success']:
        print(f"✓ Signature flags updated")
        print(f"  Signatures updated: {update_result.get('updated_count', 0)}")
        print(f"  New flags added: {update_result.get('new_flags', 0)}")
    else:
        print(f"✗ Failed to update flags: {update_result['error']}")
    
    # Example 4: Perform scan and create signature
    print("\n=== Scan and Signature Creation ===")
    
    # Perform a scan to create new signature data
    target = "127.0.0.1"  # Safe target for demo
    print(f"Scanning {target} to generate signature data...")
    
    scan_result = scanner.scan_target(target)
    
    if scan_result['success']:
        scan_id = scan_result.get('scan_id')
        print(f"✓ Scan completed with ID: {scan_id}")
        
        # Mark this scan as having signature created
        mark_result = signature_manager.mark_signature_created(scan_id=scan_id)
        
        if mark_result['success']:
            print(f"✓ Signature marked as created for scan {scan_id}")
        else:
            print(f"✗ Failed to mark signature: {mark_result['error']}")
    else:
        print(f"✗ Scan failed: {scan_result['error']}")
    
    # Example 5: Multi-protocol signature learning
    print("\n=== Multi-Protocol Signature Learning ===")
    
    protocols = ['sui', 'solana']
    protocol_results = {}
    
    for protocol in protocols:
        print(f"Learning signatures for {protocol}...")
        
        result = signature_manager.learn_from_scans(
            protocol=protocol,
            min_confidence=0.8,
            max_examples=500
        )
        
        protocol_results[protocol] = result
        
        if result['success']:
            print(f"  ✓ {protocol}: {result.get('new_signatures', 0)} new signatures")
        else:
            print(f"  ✗ {protocol}: {result['error']}")
    
    # Compare results across protocols
    print("\nProtocol Comparison:")
    for protocol, result in protocol_results.items():
        if result['success']:
            signatures = result.get('new_signatures', 0)
            confidence = result.get('avg_confidence', 0)
            print(f"  {protocol}: {signatures} signatures (avg confidence: {confidence:.2f})")
    
    # Example 6: Signature quality analysis
    print("\n=== Signature Quality Analysis ===")
    
    # Analyze signature quality across all protocols
    all_stats = signature_manager.show_statistics()
    
    if all_stats['success']:
        total_sigs = all_stats.get('total_signatures', 0)
        high_quality = all_stats.get('high_confidence', 0)
        
        if total_sigs > 0:
            quality_ratio = high_quality / total_sigs
            print(f"Overall signature quality: {quality_ratio:.2%}")
            
            if quality_ratio > 0.8:
                print("  ✓ Excellent signature quality")
            elif quality_ratio > 0.6:
                print("  ⚠️  Good signature quality")
            else:
                print("  ❌ Signature quality needs improvement")
        
        print(f"Signature distribution:")
        print(f"  High quality (>0.9): {all_stats.get('high_confidence', 0)}")
        print(f"  Medium quality (0.7-0.9): {all_stats.get('medium_confidence', 0)}")
        print(f"  Low quality (<0.7): {all_stats.get('low_confidence', 0)}")
    
    # Example 7: Signature performance monitoring
    print("\n=== Signature Performance Monitoring ===")
    
    # Monitor signature detection performance
    performance_metrics = {
        'detection_rate': 0.85,
        'false_positive_rate': 0.03,
        'false_negative_rate': 0.12,
        'avg_detection_time': 0.45,
        'signature_matches_today': 1247
    }
    
    print("Signature Detection Performance:")
    print(f"  Detection rate: {performance_metrics['detection_rate']:.1%}")
    print(f"  False positive rate: {performance_metrics['false_positive_rate']:.1%}")
    print(f"  False negative rate: {performance_metrics['false_negative_rate']:.1%}")
    print(f"  Average detection time: {performance_metrics['avg_detection_time']:.2f}s")
    print(f"  Matches today: {performance_metrics['signature_matches_today']}")
    
    # Performance assessment
    detection_rate = performance_metrics['detection_rate']
    fp_rate = performance_metrics['false_positive_rate']
    
    if detection_rate > 0.9 and fp_rate < 0.05:
        print("  ✓ Excellent signature performance")
    elif detection_rate > 0.8 and fp_rate < 0.1:
        print("  ⚠️  Good signature performance")
    else:
        print("  ❌ Signature performance needs optimization")
    
    # Example 8: Signature maintenance
    print("\n=== Signature Maintenance ===")
    
    print("Signature maintenance recommendations:")
    
    # Check for old signatures
    old_signatures = 45  # Simulated count
    if old_signatures > 0:
        print(f"  📋 Review {old_signatures} signatures older than 6 months")
    
    # Check for low-confidence signatures
    low_conf_sigs = 23  # Simulated count
    if low_conf_sigs > 0:
        print(f"  🔍 Investigate {low_conf_sigs} low-confidence signatures")
    
    # Check for unused signatures
    unused_sigs = 12  # Simulated count
    if unused_sigs > 0:
        print(f"  🗑️  Consider removing {unused_sigs} unused signatures")
    
    print("  ✅ Regular signature validation recommended")
    print("  ✅ Continuous learning from new scans enabled")

if __name__ == "__main__":
    main()
