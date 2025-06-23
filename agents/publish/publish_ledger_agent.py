"""
Publisher agent for outputting scan results to blockchain ledger.
"""

import os
import json
import hashlib
import time
from typing import Optional, Dict, Any, List
from web3 import Web3
from web3.contract import Contract
from web3.exceptions import ContractLogicError, TransactionNotFound
from eth_account import Account
from datetime import datetime

from agents.base import PublishAgent
from core.config import Config
from repositories.ledger_repository import LedgerRepository

# Try to load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


class DePINLedgerError(Exception):
    """Custom exception for DePIN ledger interface errors"""
    pass


class PublishLedgerAgent(PublishAgent):
    """
    Publishing agent for outputting scan results to blockchain ledger.
    
    This agent handles the publishing of scan results to a blockchain ledger,
    which is a prerequisite for report publishing. Integrates with DePINScanLedgerV3.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize publish ledger agent.
        
        Args:
            config: Configuration instance
        """
        super().__init__(config, "PublishLedgerAgent")
        
        # Initialize ledger repository for database logging
        self.ledger_repo = LedgerRepository()
        
        # Initialize blockchain connection
        self._initialize_blockchain_connection()
    
    def _initialize_blockchain_connection(self):
        """Initialize Web3 connection and contract interface."""
        connection_start = datetime.utcnow()
        connection_data = {
            'agent_name': self.agent_name,
            'connection_successful': False,
            'contract_loaded': False,
            'is_authorized_publisher': False
        }
        
        try:
            # Load configuration from environment or config
            self.rpc_url = self._get_config_value('ZKSYNC_RPC_URL', 'https://sepolia.era.zksync.dev')
            self.contract_address_str = self._get_config_value('CONTRACT_ADDRESS')
            self.private_key_str = self._get_config_value('PRIVATE_KEY')
            
            connection_data.update({
                'rpc_url': self.rpc_url,
                'contract_address': self.contract_address_str
            })
            
            # Load contract ABI from file
            self.contract_abi = self._load_abi_from_file()
            
            # Validate required parameters
            if not self.contract_address_str:
                raise DePINLedgerError("CONTRACT_ADDRESS must be configured")
            if not self.private_key_str:
                raise DePINLedgerError("PRIVATE_KEY must be configured")
            
            # Initialize Web3 connection
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            
            if not self.w3.is_connected():
                raise DePINLedgerError(f"Failed to connect to zkSync Era RPC at {self.rpc_url}")
                
            connection_data['connection_successful'] = True
            connection_data['network_name'] = 'zkSync Era Sepolia'
            
            self.account = Account.from_key(self.private_key_str)
            self.contract_address = Web3.to_checksum_address(self.contract_address_str)
            self.contract: Contract = self.w3.eth.contract(
                address=self.contract_address,
                abi=self.contract_abi
            )
            
            connection_data.update({
                'contract_loaded': True,
                'account_address': self.account.address
            })
            
            # Load gas parameters
            self.default_gas_limit = int(self._get_config_value('GAS_LIMIT', '2000000'))
            self.default_gas_price = self.w3.to_wei(self._get_config_value('GAS_PRICE_GWEI', '0.25'), 'gwei')
            
            # Get account balance
            try:
                balance = self.w3.eth.get_balance(self.account.address)
                connection_data.update({
                    'account_balance_wei': str(balance),
                    'account_balance_eth': float(self.w3.from_wei(balance, 'ether'))
                })
            except:
                pass
            
            # Check account permissions
            try:
                self.is_publisher = self.contract.functions.authorizedPublishers(self.account.address).call()
                connection_data['is_authorized_publisher'] = self.is_publisher
                self.logger.info(f"📊 Connected to ledger as {'authorized' if self.is_publisher else 'unauthorized'} publisher")
            except:
                self.logger.warning("Could not check publisher authorization")
                self.is_publisher = False
            
            # Get contract info
            try:
                if hasattr(self.contract.functions, 'getContractInfo'):
                    contract_info = self.contract.functions.getContractInfo().call()
                    connection_data.update({
                        'contract_version': contract_info[0],
                        'contract_paused': contract_info[1],
                        'total_summaries': contract_info[2],
                        'publish_cooldown': contract_info[3],
                        'reputation_threshold': contract_info[4],
                        'active_hosts': contract_info[5]
                    })
            except:
                pass
            
            # Calculate connection duration
            connection_duration = datetime.utcnow() - connection_start
            connection_data['connection_duration_ms'] = int(connection_duration.total_seconds() * 1000)
            
            self.logger.info(f"✅ Blockchain connection initialized: {self.account.address}")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize blockchain connection: {e}")
            self.w3 = None
            self.contract = None
            self.is_publisher = False
            
            connection_data.update({
                'error_message': str(e),
                'error_type': type(e).__name__
            })
            
            # Calculate connection duration even on failure
            connection_duration = datetime.utcnow() - connection_start
            connection_data['connection_duration_ms'] = int(connection_duration.total_seconds() * 1000)
        
        finally:
            # Log the connection attempt to database
            try:
                self.ledger_repo.create_connection_log(**connection_data)
            except Exception as log_error:
                self.logger.warning(f"Failed to log connection attempt: {log_error}")
    
    def _load_abi_from_file(self) -> List[Dict]:
        """Load contract ABI from the contracts/ledger/abi.json file."""
        try:
            # Try to find the ABI file relative to the project root
            possible_paths = [
                'contracts/ledger/abi.json',  # From project root
                '../contracts/ledger/abi.json',  # If running from subdirectory
                '../../contracts/ledger/abi.json',  # If running from deeper subdirectory
                os.path.join(os.getcwd(), 'contracts', 'ledger', 'abi.json'),  # Absolute from cwd
            ]
            
            for abi_path in possible_paths:
                if os.path.exists(abi_path):
                    self.logger.info(f"Loading ABI from: {abi_path}")
                    with open(abi_path, 'r') as f:
                        abi = json.load(f)
                    self.logger.info(f"✅ Successfully loaded ABI with {len(abi)} items")
                    return abi
            
            # If no ABI file found, fall back to minimal ABI
            self.logger.warning("ABI file not found at contracts/ledger/abi.json, using minimal ABI")
            return self._get_minimal_abi()
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in ABI file: {e}")
            raise DePINLedgerError(f"Invalid ABI file format: {e}")
        except Exception as e:
            self.logger.error(f"Error loading ABI file: {e}")
            raise DePINLedgerError(f"Failed to load ABI: {e}")
    
    def _get_config_value(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get configuration value from environment or config object."""
        # First try environment variables
        value = os.getenv(key)
        if value:
            return value
        
        # Then try config object if available
        if self.config and hasattr(self.config, 'get'):
            value = self.config.get(key.lower())
            if value:
                return str(value)
        
        return default
    
    def _get_minimal_abi(self) -> List[Dict]:
        """Return minimal ABI for basic contract interaction."""
        return [
            {
                "inputs": [
                    {"internalType": "string", "name": "hostUid", "type": "string"},
                    {"internalType": "uint256", "name": "scanTime", "type": "uint256"},
                    {"internalType": "bytes32", "name": "summaryHash", "type": "bytes32"},
                    {"internalType": "uint16", "name": "score", "type": "uint16"},
                    {"internalType": "string", "name": "reportPointer", "type": "string"}
                ],
                "name": "publishScanSummary",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "address", "name": "", "type": "address"}],
                "name": "authorizedPublishers",
                "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]
    
    def _send_transaction(self, function_call, gas_limit: Optional[int] = None) -> str:
        """Send a transaction to the contract."""
        try:
            # Get current nonce
            nonce = self.w3.eth.get_transaction_count(self.account.address, 'pending')
            
            # Build transaction
            transaction = function_call.build_transaction({
                'from': self.account.address,
                'nonce': nonce,
                'gas': gas_limit or self.default_gas_limit,
                'gasPrice': self.default_gas_price,
            })
            
            # Sign and send transaction
            signed_txn = self.account.sign_transaction(transaction)
            # Handle both old and new web3 versions
            raw_transaction = getattr(signed_txn, 'rawTransaction', None) or getattr(signed_txn, 'raw_transaction', None)
            if raw_transaction is None:
                raise DePINLedgerError("Could not get raw transaction from signed transaction")
            
            tx_hash = self.w3.eth.send_raw_transaction(raw_transaction)
            
            return tx_hash.hex()
            
        except Exception as e:
            raise DePINLedgerError(f"Transaction failed: {str(e)}")
    
    def _wait_for_transaction(self, tx_hash: str, timeout: int = 120) -> Dict[str, Any]:
        """Wait for transaction confirmation."""
        try:
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
            
            if receipt.status == 0:
                raise DePINLedgerError(f"Transaction failed: {tx_hash}")
                
            return dict(receipt)
            
        except TransactionNotFound:
            raise DePINLedgerError(f"Transaction not found: {tx_hash}")
        except Exception as e:
            raise DePINLedgerError(f"Transaction confirmation failed: {str(e)}")
    
    def _generate_summary_hash(self, scan_data: Dict[str, Any]) -> str:
        """Generate a deterministic hash for scan summary data."""
        # Create deterministic JSON string
        json_str = json.dumps(scan_data, sort_keys=True, separators=(',', ':'))
        hash_bytes = hashlib.sha256(json_str.encode('utf-8')).digest()
        return '0x' + hash_bytes.hex()
    
    def _format_scan_for_ledger(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Format scan result for blockchain ledger submission."""
        try:
            # Extract key information from scan result
            host_uid = scan_result.get('host_uid') or scan_result.get('validator_id', 'unknown_host')
            scan_time = scan_result.get('scan_time') or scan_result.get('timestamp', int(time.time()))
            trust_score = scan_result.get('trust_score', 0)
            
            # Ensure score is within valid range (0-65535)
            trust_score = max(0, min(65535, int(trust_score)))
            
            # Create summary data for hashing
            summary_data = {
                'host_uid': host_uid,
                'scan_time': scan_time,
                'trust_score': trust_score,
                'vulnerabilities': scan_result.get('vulnerabilities', []),
                'open_ports': scan_result.get('open_ports', []),
                'services': scan_result.get('services', []),
                'ssl_info': scan_result.get('ssl_info', {}),
                'scan_type': scan_result.get('scan_type', 'unknown')
            }
            
            # Generate summary hash
            summary_hash = self._generate_summary_hash(summary_data)
            
            # Generate report pointer (could be IPFS, Walrus, or other storage)
            report_pointer = scan_result.get('report_pointer') or f"scan_{scan_result.get('scan_id', 'unknown')}_{int(time.time())}"
            
            return {
                'host_uid': host_uid,
                'scan_time': scan_time,
                'summary_hash': summary_hash,
                'score': trust_score,
                'report_pointer': report_pointer,
                'summary_data': summary_data
            }
            
        except Exception as e:
            self.logger.error(f"Error formatting scan for ledger: {e}")
            raise DePINLedgerError(f"Failed to format scan data: {e}")
    
    def _get_scan_results_from_db(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve scan results from database."""
        try:
            from repositories.scan_repository import ScanRepository
            
            self.logger.info(f"Retrieving scan {scan_id} from database")
            
            with ScanRepository() as scan_repo:
                scan = scan_repo.get_scan_by_id(scan_id)
                
                if not scan:
                    self.logger.error(f"Scan {scan_id} not found in database")
                    return None
                
                if scan.failed:
                    self.logger.warning(f"Scan {scan_id} is marked as failed")
                    return None
                
                # Convert database scan to format expected by ledger
                scan_result = {
                    'scan_id': scan.id,
                    'host_uid': f'validator_{scan.validator_address_id}',
                    'validator_id': f'validator_{scan.validator_address_id}',
                    'scan_time': int(scan.scan_date.timestamp()) if scan.scan_date else int(time.time()),
                    'timestamp': int(scan.scan_date.timestamp()) if scan.scan_date else int(time.time()),
                    'trust_score': scan.score or 0,
                    'ip_address': scan.ip_address,
                    'scan_hash': scan.scan_hash,
                    'scan_results': scan.scan_results or {},
                    'vulnerabilities': scan.scan_results.get('vulnerabilities', []) if scan.scan_results else [],
                    'open_ports': scan.scan_results.get('open_ports', []) if scan.scan_results else [],
                    'services': scan.scan_results.get('services', []) if scan.scan_results else [],
                    'ssl_info': scan.scan_results.get('ssl_info', {}) if scan.scan_results else {},
                    'scan_type': scan.scan_results.get('scan_type', 'validator_scan') if scan.scan_results else 'validator_scan',
                    'version': scan.version
                }
                
                self.logger.info(f"Retrieved scan {scan_id}: validator_id={scan.validator_address_id}, score={scan.score}")
                return scan_result
                
        except Exception as e:
            self.logger.error(f"Error retrieving scan {scan_id} from database: {e}")
            return None
    
    def _update_scan_with_ledger_info(self, scan_id: int, tx_hash: str, summary_hash: str) -> bool:
        """Update scan record with ledger transaction details."""
        try:
            # The ledger information is already stored in the ledger_publish_logs table
            # This method could be used to update the scan record itself if needed
            self.logger.info(f"Scan {scan_id} ledger info recorded: tx_hash={tx_hash[:8]}...")
            
            # For now, just log the success - the ledger repository handles the persistence
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating scan {scan_id} with ledger info: {e}")
            return False
    
    def publish_single_scan(self, scan_result: Dict[str, Any], wait_for_confirmation: bool = True) -> Dict[str, Any]:
        """
        Publish a single scan result to the blockchain ledger.
        
        Args:
            scan_result: Formatted scan result dictionary
            wait_for_confirmation: Whether to wait for transaction confirmation
            
        Returns:
            Dictionary containing publication results
        """
        if not self.w3 or not self.contract:
            raise DePINLedgerError("Blockchain connection not initialized")
        
        if not self.is_publisher:
            raise DePINLedgerError("Account not authorized to publish to ledger")
        
        processing_start = datetime.utcnow()
        scan_id = scan_result.get('scan_id')
        
        # Create initial log entry
        log_data = {
            'scan_id': scan_id,
            'publishing_agent': self.agent_name,
            'agent_version': '1.0.0',  # Could be made configurable
            'blockchain_network': 'zkSync Era Sepolia',
            'rpc_url': self.rpc_url,
            'contract_address': self.contract_address,
            'publisher_address': self.account.address,
            'is_batch': False,
            'success': False,
            'transaction_confirmed': False
        }
        
        log_entry = None
        try:
            # Format scan data for ledger
            ledger_data = self._format_scan_for_ledger(scan_result)
            
            # Update log with scan data
            log_data.update({
                'host_uid': ledger_data['host_uid'],
                'scan_time': ledger_data['scan_time'],
                'summary_hash': ledger_data['summary_hash'],
                'trust_score': ledger_data['score'],
                'report_pointer': ledger_data['report_pointer']
            })
            
            # Create log entry
            log_entry = self.ledger_repo.create_publish_log(**log_data)
            
            # Convert summary_hash to bytes32
            summary_hash_bytes = bytes.fromhex(ledger_data['summary_hash'][2:])
            
            # Create function call
            function_call = self.contract.functions.publishScanSummary(
                ledger_data['host_uid'],
                ledger_data['scan_time'],
                summary_hash_bytes,
                ledger_data['score'],
                ledger_data['report_pointer']
            )
            
            # Send transaction
            tx_hash = self._send_transaction(function_call)
            
            # Calculate processing duration
            processing_duration = datetime.utcnow() - processing_start
            processing_duration_ms = int(processing_duration.total_seconds() * 1000)
            
            # Update log entry with transaction details
            update_data = {
                'success': True,
                'transaction_hash': tx_hash,
                'gas_price_gwei': float(self.w3.from_wei(self.default_gas_price, 'gwei')),
                'processing_duration_ms': processing_duration_ms
            }
            
            if log_entry:
                self.ledger_repo.update_publish_log(log_entry.id, **update_data)
            
            result = {
                'success': True,
                'transaction_hash': tx_hash,
                'summary_hash': ledger_data['summary_hash'],
                'host_uid': ledger_data['host_uid'],
                'score': ledger_data['score'],
                'confirmed': False,
                'log_id': log_entry.id if log_entry else None
            }
            
            # Wait for confirmation if requested
            if wait_for_confirmation:
                try:
                    receipt = self._wait_for_transaction(tx_hash)
                    result['confirmed'] = True
                    result['block_number'] = receipt['blockNumber']
                    result['gas_used'] = receipt['gasUsed']
                    
                    # Update log with confirmation details
                    if log_entry:
                        confirmation_data = {
                            'transaction_confirmed': True,
                            'confirmation_timestamp': datetime.utcnow(),
                            'block_number': receipt['blockNumber'],
                            'gas_used': receipt['gasUsed']
                        }
                        
                        # Calculate confirmation duration
                        confirmation_duration = datetime.utcnow() - processing_start
                        confirmation_data['confirmation_duration_ms'] = int(confirmation_duration.total_seconds() * 1000)
                        
                        self.ledger_repo.update_publish_log(log_entry.id, **confirmation_data)
                        
                except Exception as e:
                    self.logger.warning(f"Transaction sent but confirmation failed: {e}")
                    
                    # Log confirmation failure
                    if log_entry:
                        self.ledger_repo.update_publish_log(log_entry.id, 
                            error_message=f"Confirmation failed: {str(e)}",
                            error_type=type(e).__name__
                        )
            
            return result
            
        except ContractLogicError as e:
            error_msg = f"Contract error: {str(e)}"
            if log_entry:
                self.ledger_repo.update_publish_log(log_entry.id, 
                    error_message=error_msg,
                    error_type='ContractLogicError'
                )
            raise DePINLedgerError(error_msg)
            
        except Exception as e:
            error_msg = f"Publication failed: {str(e)}"
            if log_entry:
                processing_duration = datetime.utcnow() - processing_start
                self.ledger_repo.update_publish_log(log_entry.id, 
                    error_message=error_msg,
                    error_type=type(e).__name__,
                    processing_duration_ms=int(processing_duration.total_seconds() * 1000)
                )
            raise DePINLedgerError(error_msg)
    
    def publish_batch_scans(self, scan_results: List[Dict[str, Any]], wait_for_confirmation: bool = True) -> Dict[str, Any]:
        """
        Publish multiple scan results in a single batch transaction (V3 feature).
        
        Args:
            scan_results: List of scan result dictionaries
            wait_for_confirmation: Whether to wait for transaction confirmation
            
        Returns:
            Dictionary containing batch publication results
        """
        if not self.w3 or not self.contract:
            raise DePINLedgerError("Blockchain connection not initialized")
        
        if not self.is_publisher:
            raise DePINLedgerError("Account not authorized to publish to ledger")
        
        if not scan_results:
            raise DePINLedgerError("No scan results provided")
        
        if len(scan_results) > 50:
            raise DePINLedgerError("Batch too large (max 50 scans)")
        
        processing_start = datetime.utcnow()
        
        # Create batch log entry
        batch_log_data = {
            'batch_size': len(scan_results),
            'blockchain_network': 'zkSync Era Sepolia',
            'contract_address': self.contract_address,
            'publisher_address': self.account.address,
            'success': False,
            'confirmed': False
        }
        
        batch_log = None
        individual_logs = []
        
        try:
            # Check if contract supports batch operations
            if not hasattr(self.contract.functions, 'batchPublishScans'):
                # Fallback to individual publications
                return self._publish_individual_scans(scan_results, wait_for_confirmation)
            
            # Create batch log
            batch_log = self.ledger_repo.create_batch_log(**batch_log_data)
            
            # Format all scans for batch submission and create individual logs
            batch_requests = []
            for scan_result in scan_results:
                ledger_data = self._format_scan_for_ledger(scan_result)
                summary_hash_bytes = bytes.fromhex(ledger_data['summary_hash'][2:])
                
                # Create individual log entry for each scan in the batch
                individual_log_data = {
                    'scan_id': scan_result.get('scan_id'),
                    'publishing_agent': self.agent_name,
                    'blockchain_network': 'zkSync Era Sepolia',
                    'rpc_url': self.rpc_url,
                    'contract_address': self.contract_address,
                    'publisher_address': self.account.address,
                    'is_batch': True,
                    'batch_id': batch_log.id,
                    'host_uid': ledger_data['host_uid'],
                    'scan_time': ledger_data['scan_time'],
                    'summary_hash': ledger_data['summary_hash'],
                    'trust_score': ledger_data['score'],
                    'report_pointer': ledger_data['report_pointer'],
                    'success': False,
                    'transaction_confirmed': False
                }
                
                individual_log = self.ledger_repo.create_publish_log(**individual_log_data)
                individual_logs.append(individual_log)
                
                batch_requests.append((
                    ledger_data['host_uid'],
                    ledger_data['scan_time'],
                    summary_hash_bytes,
                    ledger_data['score'],
                    ledger_data['report_pointer']
                ))
            
            # Submit batch transaction
            function_call = self.contract.functions.batchPublishScans(batch_requests)
            tx_hash = self._send_transaction(function_call, gas_limit=self.default_gas_limit * 2)
            
            # Calculate processing duration
            processing_duration = datetime.utcnow() - processing_start
            processing_duration_ms = int(processing_duration.total_seconds() * 1000)
            
            # Update batch log
            batch_update_data = {
                'success': True,
                'transaction_hash': tx_hash,
                'gas_price_gwei': float(self.w3.from_wei(self.default_gas_price, 'gwei')),
                'processing_duration_ms': processing_duration_ms,
                'successful_publishes': len(scan_results)
            }
            
            self.ledger_repo.update_batch_log(batch_log.id, **batch_update_data)
            
            # Update individual logs
            for log in individual_logs:
                self.ledger_repo.update_publish_log(log.id, 
                    success=True,
                    transaction_hash=tx_hash,
                    processing_duration_ms=processing_duration_ms
                )
            
            result = {
                'success': True,
                'transaction_hash': tx_hash,
                'batch_size': len(scan_results),
                'batch_id': 0,
                'confirmed': False,
                'batch_log_id': batch_log.id,
                'individual_log_ids': [log.id for log in individual_logs]
            }
            
            # Wait for confirmation if requested
            if wait_for_confirmation:
                try:
                    receipt = self._wait_for_transaction(tx_hash)
                    result['confirmed'] = True
                    result['block_number'] = receipt['blockNumber']
                    result['gas_used'] = receipt['gasUsed']
                    
                    # Try to extract batch ID from events
                    blockchain_batch_id = 0
                    for log_entry in receipt['logs']:
                        try:
                            if hasattr(self.contract.events, 'BatchScansPublished'):
                                decoded = self.contract.events.BatchScansPublished().processLog(log_entry)
                                blockchain_batch_id = decoded['args']['batchId']
                                result['batch_id'] = blockchain_batch_id
                                break
                        except:
                            continue
                    
                    # Update batch log with confirmation details
                    confirmation_duration = datetime.utcnow() - processing_start
                    batch_confirmation_data = {
                        'confirmed': True,
                        'block_number': receipt['blockNumber'],
                        'gas_used': receipt['gasUsed'],
                        'blockchain_batch_id': blockchain_batch_id,
                        'confirmation_duration_ms': int(confirmation_duration.total_seconds() * 1000)
                    }
                    
                    self.ledger_repo.update_batch_log(batch_log.id, **batch_confirmation_data)
                    
                    # Update individual logs
                    for log in individual_logs:
                        self.ledger_repo.update_publish_log(log.id, 
                            transaction_confirmed=True,
                            confirmation_timestamp=datetime.utcnow(),
                            block_number=receipt['blockNumber'],
                            gas_used=receipt['gasUsed'],
                            confirmation_duration_ms=int(confirmation_duration.total_seconds() * 1000)
                        )
                        
                except Exception as e:
                    self.logger.warning(f"Batch transaction sent but confirmation failed: {e}")
                    
                    # Log confirmation failure
                    if batch_log:
                        self.ledger_repo.update_batch_log(batch_log.id, 
                            error_message=f"Confirmation failed: {str(e)}"
                        )
            
            return result
            
        except Exception as e:
            error_msg = f"Batch publication failed: {str(e)}"
            
            # Update batch log with error
            if batch_log:
                processing_duration = datetime.utcnow() - processing_start
                self.ledger_repo.update_batch_log(batch_log.id, 
                    error_message=error_msg,
                    processing_duration_ms=int(processing_duration.total_seconds() * 1000),
                    failed_publishes=len(scan_results)
                )
            
            # Update individual logs with error
            for log in individual_logs:
                self.ledger_repo.update_publish_log(log.id, 
                    error_message=error_msg,
                    error_type=type(e).__name__
                )
            
            raise DePINLedgerError(error_msg)
    
    def _publish_individual_scans(self, scan_results: List[Dict[str, Any]], wait_for_confirmation: bool) -> Dict[str, Any]:
        """Fallback method to publish scans individually when batch is not available."""
        results = []
        success_count = 0
        
        for i, scan_result in enumerate(scan_results):
            try:
                result = self.publish_single_scan(scan_result, wait_for_confirmation=False)
                results.append(result)
                success_count += 1
                self.logger.info(f"Published scan {i+1}/{len(scan_results)}")
            except Exception as e:
                self.logger.error(f"Failed to publish scan {i+1}: {e}")
                results.append({'success': False, 'error': str(e)})
        
        return {
            'success': success_count == len(scan_results),
            'total_scans': len(scan_results),
            'successful_scans': success_count,
            'failed_scans': len(scan_results) - success_count,
            'individual_results': results,
            'method': 'individual_fallback'
        }
    
    def publish_results(self, processed_results: List[Dict[str, Any]]) -> bool:
        """
        Publish scan results to ledger (legacy method).
        
        Args:
            processed_results: Processed scan results
            
        Returns:
            True if ledger publishing succeeded, False otherwise
        """
        self.logger.info(f"📚 Publishing {len(processed_results)} results to ledger")
        
        try:
            if not processed_results:
                self.logger.warning("No results to publish")
                return True
            
            # Use batch publishing if available and multiple results
            if len(processed_results) > 1:
                try:
                    result = self.publish_batch_scans(processed_results)
                    success = result.get('success', False)
                    if success:
                        self.logger.info(f"✅ Successfully published batch of {len(processed_results)} scans")
                        return True
                except Exception as e:
                    self.logger.warning(f"Batch publishing failed, falling back to individual: {e}")
            
            # Fallback to individual publishing
            success_count = 0
            for scan_result in processed_results:
                try:
                    result = self.publish_single_scan(scan_result)
                    if result.get('success'):
                        success_count += 1
                except Exception as e:
                    self.logger.error(f"Failed to publish individual scan: {e}")
            
            success_rate = success_count / len(processed_results)
            self.logger.info(f"📊 Published {success_count}/{len(processed_results)} scans ({success_rate:.1%})")
            
            return success_rate >= 0.8  # Consider successful if 80% or more succeed
            
        except Exception as e:
            self.logger.error(f"❌ Ledger publishing failed: {e}")
            return False
    
    def execute(self, scan_id: int, *args, **kwargs) -> Dict[str, Any]:
        """
        Execute ledger publishing for a specific scan.
        
        Args:
            scan_id: The ID of the scan to publish to ledger
            
        Returns:
            Dictionary containing execution results
        """
        self.logger.info(f"📚 Publishing scan {scan_id} results to blockchain ledger")
        
        try:
            # Check if scan is already published to ledger
            if self.ledger_repo.is_scan_published(scan_id):
                publish_status = self.ledger_repo.get_scan_publish_status(scan_id)
                self.logger.info(f"📚 Scan {scan_id} already published to ledger")
                return {
                    'success': True,
                    'scan_id': scan_id,
                    'already_published': True,
                    'ledger_published': True,
                    'transaction_hash': publish_status.get('transaction_hash'),
                    'summary_hash': publish_status.get('summary_hash'),
                    'block_number': publish_status.get('block_number'),
                    'confirmed': publish_status.get('confirmed', False),
                    'message': 'Scan already published to blockchain ledger'
                }
            
            # Check blockchain connection
            if not self.w3 or not self.contract:
                return {
                    'success': False,
                    'scan_id': scan_id,
                    'error': 'Blockchain connection not initialized',
                    'message': 'Failed to connect to blockchain network'
                }
            
            if not self.is_publisher:
                return {
                    'success': False,
                    'scan_id': scan_id,
                    'error': 'Not authorized to publish',
                    'message': 'Account not authorized to publish to ledger'
                }
            
            # Retrieve scan results from database
            scan_result = self._get_scan_results_from_db(scan_id)
            if not scan_result:
                return {
                    'success': False,
                    'scan_id': scan_id,
                    'error': 'Scan not found',
                    'message': f'Could not retrieve scan {scan_id} from database'
                }
            
            # Publish to blockchain ledger
            ledger_result = self.publish_single_scan(scan_result, wait_for_confirmation=True)
            
            if ledger_result.get('success'):
                # Update scan record with ledger transaction details
                self._update_scan_with_ledger_info(
                    scan_id, 
                    ledger_result['transaction_hash'], 
                    ledger_result['summary_hash']
                )
                
                return {
                    'success': True,
                    'scan_id': scan_id,
                    'ledger_published': True,
                    'transaction_hash': ledger_result['transaction_hash'],
                    'summary_hash': ledger_result['summary_hash'],
                    'block_number': ledger_result.get('block_number'),
                    'confirmed': ledger_result.get('confirmed', False),
                    'message': 'Successfully published to blockchain ledger'
                }
            else:
                return {
                    'success': False,
                    'scan_id': scan_id,
                    'error': 'Ledger publication failed',
                    'message': 'Failed to publish scan to blockchain ledger'
                }
            
        except DePINLedgerError as e:
            self.logger.error(f"Ledger error for scan {scan_id}: {e}")
            return {
                'success': False,
                'scan_id': scan_id,
                'error': str(e),
                'message': f'Ledger error: {e}'
            }
        except Exception as e:
            self.logger.error(f"Unexpected error publishing scan {scan_id}: {e}")
            return {
                'success': False,
                'scan_id': scan_id,
                'error': str(e),
                'message': f'Unexpected error: {e}'
            }
    
    def run(self, scan_id: int, *args, **kwargs) -> bool:
        """
        Execute ledger publishing for a specific scan ID.
        
        Args:
            scan_id: The ID of the scan to publish to ledger
            
        Returns:
            True if ledger publishing succeeded, False otherwise
        """
        result = self.execute(scan_id=scan_id)
        return result.get('success', False)
    
    def get_ledger_status(self) -> Dict[str, Any]:
        """
        Get the current status of the ledger connection and permissions.
        
        Returns:
            Dictionary containing ledger status information
        """
        try:
            if not self.w3 or not self.contract:
                return {
                    'connected': False,
                    'error': 'Not initialized'
                }
            
            # Get account balance
            balance = self.w3.eth.get_balance(self.account.address)
            
            # Get contract info if available
            contract_info = {}
            try:
                if hasattr(self.contract.functions, 'getContractInfo'):
                    result = self.contract.functions.getContractInfo().call()
                    contract_info = {
                        'version': result[0],
                        'is_paused': result[1],
                        'total_summaries': result[2],
                        'publish_cooldown': result[3],
                        'reputation_threshold': result[4],
                        'active_hosts': result[5]
                    }
            except:
                pass
            
            return {
                'connected': True,
                'rpc_url': self.rpc_url,
                'contract_address': self.contract_address,
                'account_address': self.account.address,
                'balance_wei': balance,
                'balance_eth': float(self.w3.from_wei(balance, 'ether')),
                'is_publisher': self.is_publisher,
                'contract_info': contract_info
            }
            
        except Exception as e:
            return {
                'connected': False,
                'error': str(e)
            }