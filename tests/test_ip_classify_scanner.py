#!/usr/bin/env python3
"""
Test suite for IP Classification Scanner.
"""

import pytest
import sys
from unittest.mock import patch, MagicMock
import json

# Add the project root to the Python path
sys.path.insert(0, '.')

from pgdn_scanner.scanners.ip_classify_scanner import IpClassifyScanner


class TestIpClassifyScanner:
    """Test suite for IpClassifyScanner."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.scanner = IpClassifyScanner()
    
    def test_scanner_type(self):
        """Test scanner type property."""
        assert self.scanner.scanner_type == "ip_classify"
    
    def test_initialization(self):
        """Test scanner initialization with config."""
        config = {
            'timeout': 10,
            'default_port': 80,
            'ipinfo_url': 'https://custom.ipinfo.com/{ip}/json'
        }
        scanner = IpClassifyScanner(config)
        assert scanner.timeout == 10
        assert scanner.default_port == 80
        assert scanner.ipinfo_url == 'https://custom.ipinfo.com/{ip}/json'
    
    def test_private_ip_detection(self):
        """Test detection of private IP addresses."""
        # Test private IPv4 addresses
        private_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1']
        
        for ip in private_ips:
            result = self.scanner._scan_single_ip(ip, scan_level=1)
            assert result['scanner_type'] == 'ip_classify'
            assert 'Private Network' in result.get('classification', '')
            assert 'Private Network' in result.get('likely_role', '')
    
    @patch('socket.gethostbyname')
    def test_dns_resolution_failure(self, mock_gethostbyname):
        """Test handling of DNS resolution failures."""
        import socket
        mock_gethostbyname.side_effect = socket.gaierror("DNS resolution failed")
        
        result = self.scanner._scan_single_ip('invalid.domain.test', scan_level=1)
        
        assert 'error' in result
        assert 'DNS resolution failed' in result['error']
        assert result['scanner_type'] == 'ip_classify'
    
    @patch('socket.gethostbyaddr')
    def test_reverse_dns_lookup(self, mock_gethostbyaddr):
        """Test reverse DNS lookup functionality."""
        # Test successful lookup
        mock_gethostbyaddr.return_value = ('example.cloudfront.net', [], ['1.2.3.4'])
        result = self.scanner._reverse_dns('1.2.3.4')
        assert result == 'example.cloudfront.net'
        
        # Test failed lookup
        mock_gethostbyaddr.side_effect = Exception("No reverse DNS")
        result = self.scanner._reverse_dns('1.2.3.4')
        assert result is None
    
    def test_hostname_classification(self):
        """Test hostname classification logic."""
        test_cases = [
            ('example.cloudfront.net', 'CloudFront CDN'),
            ('test.elb.amazonaws.com', 'AWS ELB'),
            ('compute.amazonaws.com', 'AWS EC2'),
            ('cloudflare.com', 'Cloudflare'),
            ('test.azure.com', 'Azure'),
            ('cdn.fastly.com', 'Fastly'),
            ('edge.akamai.com', 'Akamai'),
            ('unknown.example.com', 'Unknown or custom'),
            ('', 'unknown')
        ]
        
        for hostname, expected in test_cases:
            result = self.scanner._classify_hostname(hostname)
            assert result == expected
    
    @patch('requests.get')
    def test_aws_ranges_fetch(self, mock_get):
        """Test AWS IP ranges fetching."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'prefixes': [
                {'ip_prefix': '1.2.3.0/24', 'service': 'CLOUDFRONT', 'region': 'GLOBAL'}
            ]
        }
        mock_get.return_value = mock_response
        
        ranges = self.scanner._fetch_aws_ranges()
        assert len(ranges) == 1
        assert ranges[0]['service'] == 'CLOUDFRONT'
        assert ranges[0]['region'] == 'GLOBAL'
    
    def test_aws_service_matching(self):
        """Test AWS service matching functionality."""
        aws_ranges = [
            {'ip_prefix': '1.2.3.0/24', 'service': 'CLOUDFRONT', 'region': 'GLOBAL'},
            {'ip_prefix': '10.0.0.0/8', 'service': 'EC2', 'region': 'us-east-1'}
        ]
        
        # Test matching IP
        service, region, prefix = self.scanner._match_aws_service('1.2.3.4', aws_ranges)
        assert service == 'CLOUDFRONT'
        assert region == 'GLOBAL'
        assert prefix == '1.2.3.0/24'
        
        # Test non-matching IP
        service, region, prefix = self.scanner._match_aws_service('8.8.8.8', aws_ranges)
        assert service is None
        assert region is None
        assert prefix is None
    
    @patch('requests.get')
    def test_ipinfo_fetch(self, mock_get):
        """Test IPInfo API fetching."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'org': 'AS15169 Google LLC',
            'country': 'US',
            'city': 'Mountain View'
        }
        mock_get.return_value = mock_response
        
        result = self.scanner._fetch_ipinfo('8.8.8.8')
        assert result['org'] == 'AS15169 Google LLC'
        assert result['country'] == 'US'
    
    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_tls_inspection(self, mock_ssl_context, mock_connection):
        """Test TLS certificate inspection."""
        # Mock SSL certificate data
        mock_cert = {
            'subject': [
                [('commonName', 'example.com')],
                [('organizationName', 'Example Org')]
            ]
        }
        
        mock_ssl_socket = MagicMock()
        mock_ssl_socket.getpeercert.return_value = mock_cert
        
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_socket
        mock_ssl_context.return_value = mock_context
        
        mock_connection.return_value.__enter__.return_value = MagicMock()
        
        result = self.scanner._tls_inspect('1.2.3.4', 443)
        assert result == 'example.com'
    
    @patch('requests.get')
    def test_http_headers_fetch(self, mock_get):
        """Test HTTP headers fetching."""
        mock_response = MagicMock()
        mock_response.headers = {
            'Server': 'nginx/1.18.0',
            'Content-Type': 'text/html',
            'CF-Ray': '12345-SJC'
        }
        mock_get.return_value = mock_response
        
        headers = self.scanner._http_headers('1.2.3.4', 80)
        assert headers['Server'] == 'nginx/1.18.0'
        assert headers['CF-Ray'] == '12345-SJC'
    
    def test_likely_role_determination(self):
        """Test likely role determination logic."""
        # Test Cloudflare detection
        result_data = {'ipinfo_org': 'Cloudflare Inc.'}
        headers = {'cf-ray': '12345-SJC'}
        role = self.scanner._determine_likely_role(result_data, headers, None)
        assert 'Cloudflare' in role
        
        # Test AWS ALB detection
        result_data = {}
        headers = {'x-amzn-trace-id': 'Root=1-123456'}
        role = self.scanner._determine_likely_role(result_data, headers, None)
        assert 'AWS' in role
        
        # Test CloudFront via TLS
        result_data = {}
        headers = {}
        role = self.scanner._determine_likely_role(result_data, headers, 'example.cloudfront.net')
        assert 'CloudFront' in role
    
    @patch('socket.gethostbyname')
    @patch.object(IpClassifyScanner, '_fetch_aws_ranges')
    @patch.object(IpClassifyScanner, '_classify_ip')
    def test_single_ip_scan(self, mock_classify, mock_aws_ranges, mock_dns):
        """Test single IP scanning."""
        mock_dns.return_value = '1.2.3.4'
        mock_aws_ranges.return_value = []
        mock_classify.return_value = {
            'ip': '1.2.3.4',
            'classification': 'Test Service',
            'likely_role': 'test'
        }
        
        result = self.scanner._scan_single_ip('example.com', scan_level=1)
        
        assert result['target'] == 'example.com'
        assert result['scanner_type'] == 'ip_classify'
        assert result['scan_level'] == 1
        mock_classify.assert_called_once()
    
    @patch('socket.gethostbyname')
    @patch.object(IpClassifyScanner, '_fetch_aws_ranges')
    @patch.object(IpClassifyScanner, '_classify_ip')
    def test_multiple_ip_scan(self, mock_classify, mock_aws_ranges, mock_dns):
        """Test multiple IP scanning."""
        mock_dns.return_value = '1.2.3.4'  # Not used for direct IPs
        mock_aws_ranges.return_value = []
        
        # Mock classify_ip to return different results for each IP
        def classify_side_effect(ip, port, aws_ranges, scan_level):
            return {
                'ip': ip,
                'classification': f'Service for {ip}',
                'likely_role': 'test'
            }
        
        mock_classify.side_effect = classify_side_effect
        
        result = self.scanner._scan_multiple_ips(['1.2.3.4', '5.6.7.8'], scan_level=1)
        
        assert result['scanner_type'] == 'ip_classify'
        assert result['scan_level'] == 1
        assert len(result['results']) == 2
        assert result['results'][0]['ip'] == '1.2.3.4'
        assert result['results'][1]['ip'] == '5.6.7.8'
    
    @patch('socket.gethostbyname')
    @patch.object(IpClassifyScanner, '_scan_multiple_ips')
    @patch.object(IpClassifyScanner, '_scan_single_ip')
    def test_scan_method_routing(self, mock_single, mock_multiple, mock_dns):
        """Test scan method routing between single and multiple IPs."""
        # Test single IP
        self.scanner.scan('1.2.3.4', scan_level=1)
        mock_single.assert_called_once_with('1.2.3.4', 1)
        
        # Test multiple IPs
        mock_single.reset_mock()
        self.scanner.scan('1.2.3.4,5.6.7.8', scan_level=2)
        mock_multiple.assert_called_once_with(['1.2.3.4', '5.6.7.8'], 2)
    
    def test_scan_level_functionality(self):
        """Test different scan levels provide appropriate detail."""
        # Mock various methods to avoid external calls
        with patch.object(self.scanner, '_fetch_aws_ranges', return_value=[]):
            with patch.object(self.scanner, '_reverse_dns', return_value=None):
                with patch.object(self.scanner, '_fetch_ipinfo', return_value={}):
                    with patch.object(self.scanner, '_match_aws_service', return_value=(None, None, None)):
                        with patch.object(self.scanner, '_classify_hostname', return_value='unknown'):
                            # Level 1 scan - should not include TLS/HTTP data
                            with patch.object(self.scanner, '_tls_inspect') as mock_tls:
                                with patch.object(self.scanner, '_http_headers') as mock_http:
                                    result = self.scanner._classify_ip('8.8.8.8', 443, [], scan_level=1)
                                    mock_tls.assert_not_called()
                                    mock_http.assert_not_called()
                                    assert result['tls_common_name'] is None
                                    assert result['http_headers'] == {}
                            
                            # Level 2 scan - should include TLS/HTTP data
                            with patch.object(self.scanner, '_tls_inspect', return_value='example.com') as mock_tls:
                                with patch.object(self.scanner, '_http_headers', return_value={'Server': 'nginx'}) as mock_http:
                                    result = self.scanner._classify_ip('8.8.8.8', 443, [], scan_level=2)
                                    mock_tls.assert_called_once()
                                    mock_http.assert_called_once()
                                    assert result['tls_common_name'] == 'example.com'
                                    assert result['http_headers']['Server'] == 'nginx'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])