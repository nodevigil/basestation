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
from pgdn.core.config import Config
from pgdn.repositories.ledger_repository import LedgerRepository

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
            self.default_gas_limit = int(self._get_config_value('GAS_LIMIT', '10000000'))  # 10M default for zkSync Era
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
            
            # Check if account is contract owner (primary authorization)
            try:
                contract_owner = self.contract.functions.owner().call()
                self.is_owner = self.account.address.lower() == contract_owner.lower()
                
                if self.is_owner:
                    self.logger.info(f"📊 Connected as contract owner: {self.account.address}")
                    self.is_publisher = True  # Owner is always a publisher
                else:
                    self.logger.info(f"📊 Connected as regular account: {self.account.address}")
                    # Check explicit publisher authorization
                    self.is_publisher = self.contract.functions.authorizedPublishers(self.account.address).call()
                
                connection_data['is_authorized_publisher'] = self.is_publisher
                
                self.logger.info(f"📊 Authorization status: {'✅ AUTHORIZED' if self.is_publisher else '❌ NOT AUTHORIZED'}")
                
                # Log authorization details
                if not self.is_publisher and not self.is_owner:
                    self.logger.warning(f"⚠️ Address {self.account.address} is NOT authorized to publish")
                    self.logger.warning(f"💡 Contract owner is: {contract_owner}")
                    self.logger.warning(f"💡 Contact owner to authorize your address or use owner's private key")
                        
            except Exception as auth_error:
                self.logger.warning(f"Could not check authorization: {auth_error}")
                self.logger.debug(f"🔍 Authorization check exception: {type(auth_error).__name__}: {str(auth_error)}")
                self.is_publisher = False
                self.is_owner = False
            
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
                    
                    # Log cooldown info
                    cooldown = contract_info[3]
                    if cooldown > 0:
                        self.logger.info(f"⏰ Publish cooldown is {cooldown} seconds")
                        self.logger.info(f"💡 Consider calling setPublishCooldown(0) as owner to disable rate limiting")
                    else:
                        self.logger.info(f"✅ Publish cooldown is disabled")
                        
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
            self.is_owner = False
            
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
            raise DePINLedgerError("ABI file not found at contracts/ledger/abi.json and no ABI could be loaded")
            
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
    
    def _send_transaction(self, function_call, gas_limit: Optional[int] = None) -> str:
        """Send a transaction to the contract."""
        self.logger.debug(f"🔍 Preparing to send transaction")
        
        try:
            # Get current nonce
            nonce = self.w3.eth.get_transaction_count(self.account.address, 'pending')
            self.logger.debug(f"🔍 Account nonce: {nonce}")
            
            # Estimate gas if not provided
            if gas_limit is None:
                try:
                    estimated_gas = function_call.estimate_gas({'from': self.account.address})
                    # Add 20% buffer to estimated gas
                    gas_limit = int(estimated_gas * 1.2)
                    self.logger.debug(f"🔍 Estimated gas: {estimated_gas}, using with buffer: {gas_limit}")
                except Exception as estimate_error:
                    self.logger.warning(f"Gas estimation failed: {estimate_error}, using default")
                    gas_limit = self.default_gas_limit
            
            # Build transaction
            transaction_params = {
                'from': self.account.address,
                'nonce': nonce,
                'gas': gas_limit,
                'gasPrice': self.default_gas_price,
            }
            
            transaction = function_call.build_transaction(transaction_params)
            
            # Sign and send transaction
            signed_txn = self.account.sign_transaction(transaction)
            
            # Handle both old and new web3 versions
            raw_transaction = getattr(signed_txn, 'rawTransaction', None) or getattr(signed_txn, 'raw_transaction', None)
            if raw_transaction is None:
                raise DePINLedgerError("Could not get raw transaction from signed transaction")
            
            tx_hash = self.w3.eth.send_raw_transaction(raw_transaction)
            tx_hash_hex = tx_hash.hex()
            
            self.logger.info(f"✅ Transaction sent successfully: {tx_hash_hex}")
            return tx_hash_hex
            
        except Exception as e:
            self.logger.error(f"❌ Transaction failed: {e}")
            raise DePINLedgerError(f"Transaction failed: {str(e)}")
    
    def _wait_for_transaction(self, tx_hash: str, timeout: int = 120) -> Dict[str, Any]:
        """Wait for transaction confirmation."""
        self.logger.debug(f"🔍 Waiting for transaction confirmation: {tx_hash}")
        
        try:
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
            
            if receipt.status == 0:
                self.logger.error(f"❌ Transaction failed with status 0: {tx_hash}")
                raise DePINLedgerError(f"Transaction failed: {tx_hash}")
            
            self.logger.info(f"✅ Transaction confirmed successfully: {tx_hash}")
            return dict(receipt)
            
        except TransactionNotFound as e:
            self.logger.error(f"❌ Transaction not found: {tx_hash}")
            raise DePINLedgerError(f"Transaction not found: {tx_hash}")
        except Exception as e:
            self.logger.error(f"❌ Transaction confirmation failed: {e}")
            raise DePINLedgerError(f"Transaction confirmation failed: {str(e)}")
    
    def _generate_summary_hash(self, scan_data: Dict[str, Any]) -> str:
        """Generate a deterministic hash for scan summary data using the same format as JavaScript."""
        # Create summary data in the same format as the JavaScript version
        summary_data = {
            'hostUid': scan_data.get('host_uid', ''),
            'scanTime': scan_data.get('scan_time', 0),
            'score': scan_data.get('trust_score', 0),
            'reportPointer': scan_data.get('report_pointer', ''),
            'testData': False  # Mark as real data, not test data
        }
        
        # Convert to JSON string with same format as JavaScript JSON.stringify
        json_str = json.dumps(summary_data, sort_keys=True, separators=(',', ':'))
        
        # Generate hash using web3's keccak (same as ethers.keccak256)
        hash_bytes = self.w3.keccak(text=json_str)
        
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
            from pgdn.repositories.scan_repository import ScanRepository
            
            self.logger.info(f"Retrieving scan {scan_id} from database")
            
            with ScanRepository() as scan_repo:
                scan = scan_repo.get_scan_by_id(scan_id)
                
                if not scan:
                    self.logger.error(f"Scan {scan_id} not found in database")
                    return None
                
                if scan.failed:
                    self.logger.warning(f"Scan {scan_id} is marked as failed")
                    return None
                
                # Use current time for ledger publishing instead of original scan date
                # This prevents issues with old scans being published with timestamps too far in the past
                current_time = int(time.time())
                original_scan_time = int(scan.scan_date.timestamp()) if scan.scan_date else current_time
                
                # Log the time difference for debugging
                if scan.scan_date:
                    time_diff = current_time - original_scan_time
                    self.logger.info(f"Scan {scan_id} original date: {scan.scan_date}, age: {time_diff} seconds")
                    if time_diff > 86400:  # More than 1 day old
                        self.logger.info(f"Using current time for ledger publishing (scan is {time_diff/86400:.1f} days old)")
                
                # Convert database scan to format expected by ledger
                scan_result = {
                    'scan_id': scan.id,
                    'host_uid': f'validator_{scan.validator_address_id}',
                    'validator_id': f'validator_{scan.validator_address_id}',
                    'scan_time': current_time,  # Use current time for publishing
                    'original_scan_time': original_scan_time,  # Keep original for reference
                    'timestamp': current_time,  # Use current time for publishing
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
        
        if not self.is_publisher and not self.is_owner:
            raise DePINLedgerError("Account not authorized to publish to ledger")
        
        processing_start = datetime.utcnow()
        scan_id = scan_result.get('scan_id')
        
        # Create initial log entry
        log_data = {
            'scan_id': scan_id,
            'publishing_agent': self.agent_name,
            'agent_version': '1.0.0',
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
            
            self.logger.info(f"🔍 About to call publishScanSummary with: host='{ledger_data['host_uid']}', time={ledger_data['scan_time']}, score={ledger_data['score']}")
            
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
            
            self.logger.info(f"Scan {scan_id} ledger info recorded: tx_hash={tx_hash[:10]}...")
            
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
                    
                    # Log confirmation failure but keep success=True since transaction was sent
                    # The transaction may still be valid and confirmed later
                    if log_entry:
                        self.ledger_repo.update_publish_log(log_entry.id, 
                            error_message=f"Confirmation failed: {str(e)}",
                            error_type=type(e).__name__
                        )
            
            return result
            
        except ContractLogicError as e:
            error_msg = f"Contract error: {str(e)}"
            self.logger.error(f"❌ Contract logic error: {error_msg}")
                
            if log_entry:
                self.ledger_repo.update_publish_log(log_entry.id, 
                    success=False,
                    error_message=error_msg,
                    error_type='ContractLogicError'
                )
            raise DePINLedgerError(error_msg)
            
        except Exception as e:
            error_msg = f"Publication failed: {str(e)}"
            self.logger.error(f"❌ Publication failed: {error_msg}")
                
            if log_entry:
                processing_duration = datetime.utcnow() - processing_start
                self.ledger_repo.update_publish_log(log_entry.id, 
                    success=False,
                    error_message=error_msg,
                    error_type=type(e).__name__,
                    processing_duration_ms=int(processing_duration.total_seconds() * 1000)
                )
            raise DePINLedgerError(error_msg)
    
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
            
            # Publish individual scans
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
                    'confirmed': publish_status.get('confirmed', False),
                    'message': 'Scan already published to blockchain ledger'
                }
            
            # Log any previous failed attempts
            failed_attempts = self.ledger_repo.get_failed_attempts_for_scan(scan_id)
            if failed_attempts:
                self.logger.info(f"📚 Scan {scan_id} has {len(failed_attempts)} previous failed attempt(s), retrying...")
                latest_failure = failed_attempts[0]
                self.logger.info(f"📚 Last failure: {latest_failure.error_message} ({latest_failure.attempt_timestamp})")
            
            # Check blockchain connection
            if not self.w3 or not self.contract:
                self.logger.error(f"❌ Blockchain connection not initialized")
                return {
                    'success': False,
                    'scan_id': scan_id,
                    'error': 'Blockchain connection not initialized',
                    'message': 'Failed to connect to blockchain network'
                }
            
            if not self.is_publisher and not self.is_owner:
                self.logger.error(f"❌ Account not authorized to publish: {self.account.address}")
                return {
                    'success': False,
                    'scan_id': scan_id,
                    'error': 'Not authorized to publish',
                    'message': 'Account not authorized to publish to ledger'
                }
            
            # Retrieve scan results from database
            self.logger.info(f"Retrieving scan {scan_id} from database")
            scan_result = self._get_scan_results_from_db(scan_id)
            if not scan_result:
                self.logger.error(f"❌ Could not retrieve scan {scan_id} from database")
                return {
                    'success': False,
                    'scan_id': scan_id,
                    'error': 'Scan not found',
                    'message': f'Could not retrieve scan {scan_id} from database'
                }
            
            self.logger.info(f"Retrieved scan {scan_id}: validator_id={scan_result.get('validator_id')}, score={scan_result.get('trust_score')}")
            
            # Publish to blockchain ledger
            ledger_result = self.publish_single_scan(scan_result, wait_for_confirmation=True)
            
            if ledger_result.get('success'):
                self.logger.info(f"✅ Ledger publication successful for scan {scan_id}")
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
                self.logger.error(f"❌ Ledger publication failed for scan {scan_id}: {ledger_result}")
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
                'is_owner': getattr(self, 'is_owner', False),
                'contract_info': contract_info
            }
            
        except Exception as e:
            return {
                'connected': False,
                'error': str(e)
            }