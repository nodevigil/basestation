"""
Tests for CLI JSON output functionality.
Tests the main CLI functions to ensure they return proper JSON results.
"""
import pytest
import json
import sys
import io
from unittest.mock import patch, MagicMock, mock_open
from argparse import Namespace
from datetime import datetime

# Import the functions we'll be testing
from cli import (
    run_full_pipeline,
    run_single_stage,
    scan_target,
    update_cve_database,
    learn_signatures_from_scans,
    check_task_status,
    list_agents,
    run_with_queue,
    run_parallel_scans,
    run_parallel_stages,
    mark_scan_signature_created,
    show_signature_stats,
    update_signature_flags
)
from core.config import Config


class TestCLIJSONOutput:
    """Test class for CLI JSON output functionality."""
    
    @pytest.fixture
    def mock_config(self):
        """Create a mock configuration."""
        config = MagicMock(spec=Config)
        config.logging = MagicMock()
        config.database = MagicMock()
        config.scanning = MagicMock()
        config.scanning.max_concurrent_scans = 1
        config.scanning.sleep_between_scans = 0
        config.scanning.timeout_seconds = 30
        return config
    
    @pytest.fixture
    def mock_args(self):
        """Create mock CLI arguments."""
        return Namespace(
            json=True,
            stage=None,
            agent=None,
            scan_target=None,
            recon_agents=None,
            protocol=None,
            host=None,
            list_agents=False,
            update_cves=False,
            replace_cves=False,
            initial_cves=False,
            config=None,
            log_level='INFO',
            debug=False,
            force_rescore=False,
            scan_id=None,
            force_report=False,
            force=False,
            report_input=None,
            report_output=None,
            report_format='json',
            report_email=False,
            recipient_email=None,
            auto_save_report=False,
            publish_ledger=False,
            publish_report=False,
            queue=False,
            task_id=None,
            wait_for_completion=False,
            list_tasks=False,
            cancel_task=None,
            parallel_targets=None,
            max_parallel=5,
            parallel_stages=None,
            target_file=None,
            learn_signatures_from_scans=False,
            signature_protocol=None,
            signature_learning_min_confidence=0.7,
            signature_learning_max_examples=1000,
            update_signature_flags=False,
            protocol_filter=None,
            mark_signature_created=None,
            show_signature_stats=False
        )

    def test_run_full_pipeline_json_success(self, mock_config, mock_args):
        """Test run_full_pipeline returns JSON on success."""
        mock_orchestrator = MagicMock()
        mock_orchestrator.run_full_pipeline.return_value = {
            'success': True,
            'execution_id': 'test-exec-123',
            'execution_time_seconds': 45.67,
            'stages': {
                'recon': [{'id': 1, 'address': '192.168.1.1'}],
                'scan': [{'id': 1, 'result': 'success'}],
                'process': [{'id': 1, 'score': 0.8}],
                'publish': True
            }
        }
        
        with patch('cli.create_orchestrator', return_value=mock_orchestrator):
            result = run_full_pipeline(mock_config, json_output=True)
            
            assert result is not None
            assert isinstance(result, dict)
            assert result['success'] is True
            assert result['execution_id'] == 'test-exec-123'
            assert 'execution_time_seconds' in result
            assert 'stages' in result

    def test_run_full_pipeline_json_failure(self, mock_config, mock_args):
        """Test run_full_pipeline returns JSON on failure."""
        mock_orchestrator = MagicMock()
        mock_orchestrator.run_full_pipeline.side_effect = Exception("Test error")
        
        with patch('cli.create_orchestrator', return_value=mock_orchestrator):
            result = run_full_pipeline(mock_config, json_output=True)
            
            assert result is not None
            assert isinstance(result, dict)
            assert 'error' in result
            assert 'Test error' in result['error']

    def test_run_single_stage_json_success(self, mock_config):
        """Test run_single_stage returns JSON on success."""
        mock_orchestrator = MagicMock()
        mock_orchestrator.run_single_stage.return_value = [
            {'id': 1, 'address': '192.168.1.1', 'status': 'discovered'}
        ]
        
        with patch('cli.create_orchestrator', return_value=mock_orchestrator):
            result = run_single_stage(
                mock_config, 
                'recon', 
                json_output=True
            )
            
            assert result is not None
            assert isinstance(result, dict)
            assert result['success'] is True
            assert result['stage'] == 'recon'
            assert 'results' in result
            assert len(result['results']) == 1

    def test_run_single_stage_json_failure(self, mock_config):
        """Test run_single_stage returns JSON on failure."""
        mock_orchestrator = MagicMock()
        mock_orchestrator.run_single_stage.side_effect = Exception("Stage failed")
        
        with patch('cli.create_orchestrator', return_value=mock_orchestrator):
            result = run_single_stage(
                mock_config, 
                'scan', 
                json_output=True
            )
            
            assert result is not None
            assert isinstance(result, dict)
            assert 'error' in result
            assert 'Stage failed' in result['error']

    def test_scan_target_json_success(self, mock_config):
        """Test scan_target returns JSON on success."""
        mock_scanner = MagicMock()
        mock_scanner.scan_nodes.return_value = [{
            'id': 0,
            'address': '192.168.1.100',
            'generic_scan': {'open_ports': [22, 80, 443]},
            'protocol_scan': {'metrics_exposed': True, 'rpc_exposed': False},
            'web_probes': {'http://192.168.1.100': {'waf': {'detected': False}}}
        }]
        
        with patch('agents.scan.node_scanner_agent.NodeScannerAgent', return_value=mock_scanner), \
             patch('socket.gethostbyname', return_value='192.168.1.100'):
            
            result = scan_target(mock_config, '192.168.1.100', json_output=True)
            
            assert result is not None
            assert isinstance(result, dict)
            assert result['success'] is True
            assert result['target'] == '192.168.1.100'
            assert 'scan_result' in result

    def test_scan_target_json_dns_failure(self, mock_config):
        """Test scan_target returns JSON on DNS failure."""
        import socket
        
        with patch('socket.gethostbyname', side_effect=socket.gaierror("DNS resolution failed")):
            result = scan_target(mock_config, 'invalid.host', json_output=True)
            
            assert result is not None
            assert isinstance(result, dict)
            assert 'error' in result
            assert 'DNS resolution failed' in result['error']

    def test_update_cve_database_json_success(self):
        """Test update_cve_database returns JSON on success."""
        mock_stats = {
            'total_cves': 1000,
            'high_severity_count': 150,
            'recent_cves_30_days': 50,
            'last_update': '2025-06-23T10:00:00Z',
            'last_update_new_cves': 10,
            'last_update_updated_cves': 5
        }
        
        with patch('cli.update_cves_database', return_value=True), \
             patch('cli.get_cve_stats', return_value=mock_stats):
            
            result = update_cve_database(json_output=True)
            
            assert result is not None
            assert isinstance(result, dict)
            assert result['success'] is True
            assert 'statistics' in result
            assert result['statistics']['total_cves'] == 1000

    def test_update_cve_database_json_failure(self):
        """Test update_cve_database returns JSON on failure."""
        with patch('cli.update_cves_database', side_effect=Exception("CVE update failed")):
            result = update_cve_database(json_output=True)
            
            assert result is not None
            assert isinstance(result, dict)
            assert 'error' in result
            assert 'CVE update failed' in result['error']

    def test_learn_signatures_from_scans_json_success(self, mock_args):
        """Test learn_signatures_from_scans returns JSON on success."""
        mock_learner = MagicMock()
        mock_learner.learn_from_scans.return_value = {
            'success': True,
            'session_id': 'session-123',
            'statistics': {
                'signatures_learned': 5,
                'examples_processed': 100,
                'protocols_affected': ['sui'],
                'database_updates': {
                    'updated': ['sui_metrics'],
                    'created': ['sui_rpc'],
                    'errors': []
                },
                'improvements': {
                    'sui': {
                        'examples_added': 50,
                        'confidence_improvement': 0.15
                    }
                }
            }
        }
        
        mock_args.signature_protocol = 'sui'
        
        with patch('agents.discovery.signature_learner.ScanDataSignatureLearner', return_value=mock_learner):
            result = learn_signatures_from_scans(mock_args, json_output=True)
            
            assert result is not None
            assert isinstance(result, dict)
            assert result['success'] is True
            assert result['session_id'] == 'session-123'
            assert 'statistics' in result

    def test_learn_signatures_from_scans_json_missing_protocol(self, mock_args):
        """Test learn_signatures_from_scans returns JSON when protocol is missing."""
        mock_args.signature_protocol = None
        
        result = learn_signatures_from_scans(mock_args, json_output=True)
        
        assert result is not None
        assert isinstance(result, dict)
        assert 'error' in result
        assert 'signature-protocol is required' in result['error']

    def test_list_agents_json_success(self):
        """Test list_agents returns JSON on success."""
        mock_registry = MagicMock()
        mock_registry.list_all_agents.return_value = {
            'recon': ['SuiReconAgent', 'FilecoinReconAgent'],
            'scan': ['NodeScannerAgent'],
            'process': ['ProcessingAgent'],
            'score': ['ScoringAgent']
        }
        
        with patch('cli.get_agent_registry', return_value=mock_registry):
            result = list_agents(json_output=True)
            
            assert result is not None
            assert isinstance(result, dict)
            assert result['success'] is True
            assert 'agents' in result
            assert 'recon' in result['agents']

    def test_check_task_status_json_success(self):
        """Test check_task_status returns JSON on success."""
        mock_queue_manager = MagicMock()
        mock_queue_manager.get_task_status.return_value = {
            'status': 'SUCCESS',
            'ready': True,
            'successful': True,
            'failed': False,
            'result': {'execution_id': 'exec-123', 'results_count': 5},
            'error': None
        }
        
        with patch('cli.create_queue_manager', return_value=mock_queue_manager), \
             patch('core.config.Config'):
            
            result = check_task_status('task-123', json_output=True)
            
            assert result is not None
            assert isinstance(result, dict)
            assert result['success'] is True
            assert result['task_id'] == 'task-123'
            assert 'status' in result

    def test_check_task_status_json_failure(self):
        """Test check_task_status returns JSON on failure."""
        with patch('cli.create_queue_manager', side_effect=Exception("Queue not available")), \
             patch('core.config.Config'):
            
            result = check_task_status('task-123', json_output=True)
            
            assert result is not None
            assert isinstance(result, dict)
            assert 'error' in result
            assert 'Queue not available' in result['error']

    def test_run_parallel_scans_json_success(self, mock_config, mock_args):
        """Test run_parallel_scans returns JSON on success."""
        targets = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        mock_args.max_parallel = 2
        mock_args.protocol = None
        mock_args.queue = False
        mock_args.debug = False
        
        mock_scanner = MagicMock()
        mock_scanner.scan_nodes.return_value = [{'result': 'success'}]
        
        with patch('agents.scan.node_scanner_agent.NodeScannerAgent', return_value=mock_scanner):
            result = run_parallel_scans(mock_config, targets, mock_args, json_output=True)
            
            assert result is not None
            assert isinstance(result, dict)
            assert result['success'] is True
            assert result['total_targets'] == 3
            assert 'results' in result

    def test_show_signature_stats_json_success(self):
        """Test show_signature_stats returns JSON on success."""
        mock_service = MagicMock()
        mock_service.get_signature_creation_stats.return_value = {
            'total_scans': 100,
            'signatures_created': 75,
            'pending_signatures': 25,
            'completion_rate': 0.75,
            'protocol_breakdown': [
                {
                    'protocol': 'sui',
                    'total_scans': 50,
                    'signatures_created': 40,
                    'pending': 10
                },
                {
                    'protocol': 'filecoin',
                    'total_scans': 30,
                    'signatures_created': 25,
                    'pending': 5
                }
            ]
        }
        
        with patch('services.scan_service.ScanService', return_value=mock_service):
            result = show_signature_stats(json_output=True)
            
            assert result is not None
            assert isinstance(result, dict)
            assert result['success'] is True
            assert 'statistics' in result
            assert result['statistics']['total_scans'] == 100

    def test_mark_scan_signature_created_json_success(self):
        """Test mark_scan_signature_created returns JSON on success."""
        mock_service = MagicMock()
        mock_service.mark_signature_created.return_value = True
        
        with patch('services.scan_service.ScanService', return_value=mock_service):
            result = mark_scan_signature_created(123, json_output=True)
            
            assert result is not None
            assert isinstance(result, dict)
            assert result['success'] is True
            assert result['scan_id'] == 123

    def test_mark_scan_signature_created_json_failure(self):
        """Test mark_scan_signature_created returns JSON on failure."""
        mock_service = MagicMock()
        mock_service.mark_signature_created.return_value = False
        
        with patch('services.scan_service.ScanService', return_value=mock_service):
            result = mark_scan_signature_created(999, json_output=True)
            
            assert result is not None
            assert isinstance(result, dict)
            assert 'error' in result
            assert 'Failed to mark scan 999' in result['error']

    def test_update_signature_flags_json_success(self, mock_args):
        """Test update_signature_flags returns JSON on success."""
        mock_service = MagicMock()
        
        # Mock pending scans
        mock_scan1 = MagicMock()
        mock_scan1.id = 1
        mock_scan1.scan_results = {'detected_protocol': 'sui'}
        
        mock_scan2 = MagicMock()
        mock_scan2.id = 2
        mock_scan2.scan_results = {'detected_protocol': 'filecoin'}
        
        mock_service.get_scans_pending_signature_creation.return_value = [mock_scan1, mock_scan2]
        mock_service.mark_signature_created.return_value = True
        
        mock_args.signature_protocol_filter = None
        
        with patch('services.scan_service.ScanService', return_value=mock_service):
            result = update_signature_flags(mock_args, json_output=True)
            
            assert result is not None
            assert isinstance(result, dict)
            assert result['success'] is True
            assert result['processed_count'] == 2
            assert result['skipped_count'] == 0


class TestCLIJSONArgument:
    """Test the --json CLI argument parsing."""
    
    def test_json_argument_parsing(self):
        """Test that --json argument is properly parsed."""
        from cli import parse_arguments
        
        # Mock sys.argv to include --json
        test_args = ['pgdn', '--json']
        
        with patch('sys.argv', test_args):
            args = parse_arguments()
            assert hasattr(args, 'json')
            assert args.json is True

    def test_json_argument_default_false(self):
        """Test that --json defaults to False."""
        from cli import parse_arguments
        
        # Mock sys.argv without --json
        test_args = ['pgdn']
        
        with patch('sys.argv', test_args):
            args = parse_arguments()
            assert hasattr(args, 'json')
            assert args.json is False

    def test_json_with_other_arguments(self):
        """Test --json works with other CLI arguments."""
        from cli import parse_arguments
        
        test_args = ['pgdn', '--json', '--stage', 'scan', '--protocol', 'sui']
        
        with patch('sys.argv', test_args):
            args = parse_arguments()
            assert args.json is True
            assert args.stage == 'scan'
            assert args.protocol == 'sui'
