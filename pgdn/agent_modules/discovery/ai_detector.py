"""
AI Service Detector - AI-powered protocol identification

This module provides AI-powered fallback detection for DePIN protocols
when signature matching confidence is low.
"""

import json
import re
import requests
import logging
import os
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime


class AIServiceDetector:
    """AI-powered service detection using OpenAI or Anthropic APIs"""
    
    def __init__(self, config=None):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Get API keys from config or environment
        if config:
            self.openai_api_key = getattr(config, 'openai_api_key', None) or os.environ.get('OPENAI_API_KEY')
            self.anthropic_api_key = getattr(config, 'anthropic_api_key', None) or os.environ.get('ANTHROPIC_API_KEY')
            self.preferred_provider = getattr(config, 'ai_provider', 'auto')
            self.ai_fallback_threshold = getattr(config, 'ai_fallback_threshold', 0.4)
        else:
            self.openai_api_key = os.environ.get('OPENAI_API_KEY')
            self.anthropic_api_key = os.environ.get('ANTHROPIC_API_KEY')
            self.preferred_provider = 'auto'
            self.ai_fallback_threshold = 0.4
        
        # Validate API configuration
        if not self.openai_api_key and not self.anthropic_api_key:
            self.logger.warning("No AI API keys configured. AI fallback will be disabled.")
        else:
            self.logger.info(f"AI detector initialized with {self.preferred_provider} provider")
    
    def should_use_ai_fallback(self, confidence_score: float, scan_data: Dict) -> bool:
        """Determine if AI fallback should be used"""
        # Don't use AI if confidence is already high
        if confidence_score >= 0.8:
            return False
        
        # Don't use AI if no API keys available
        if not self.openai_api_key and not self.anthropic_api_key:
            return False
        
        # Check if we have meaningful data to analyze
        has_probe_data = bool(scan_data.get('probes', {}))
        has_service_data = bool(scan_data.get('nmap', {}).get('services', {}))
        has_port_data = bool(scan_data.get('nmap', {}).get('ports', []))
        
        has_data = has_probe_data or has_service_data or has_port_data
        
        # Use AI if confidence is below threshold and we have data
        return confidence_score < self.ai_fallback_threshold and has_data
    
    def analyze_service_with_ai(self, hostname: str, scan_data: Dict, discovery_id: int) -> Tuple[Optional[str], float, Dict[str, Any]]:
        """Analyze service using AI APIs to identify the protocol"""
        self.logger.info(f"🤖 Starting AI analysis for {hostname}")
        
        try:
            # Prepare analysis context
            context = self._prepare_analysis_context(hostname, scan_data)
            
            # Try providers in preferred order
            result = None
            provider_used = None
            
            # Try Anthropic first if preferred or auto
            if self.preferred_provider in ['anthropic', 'auto'] and self.anthropic_api_key:
                try:
                    result = self._analyze_with_anthropic(context)
                    provider_used = 'anthropic'
                    self.logger.debug("Successfully used Anthropic for analysis")
                except Exception as e:
                    self.logger.warning(f"Anthropic analysis failed: {e}")
            
            # Try OpenAI if Anthropic failed or not available
            if not result and self.openai_api_key:
                try:
                    result = self._analyze_with_openai(context)
                    provider_used = 'openai'
                    self.logger.debug("Successfully used OpenAI for analysis")
                except Exception as e:
                    self.logger.warning(f"OpenAI analysis failed: {e}")
            
            # If all providers failed
            if not result:
                self.logger.error("All AI providers failed")
                return None, 0.0, {'error': 'All AI providers failed'}
            
            # Parse AI response
            protocol, confidence, evidence = self._parse_ai_response(result, provider_used)
            
            # Add AI analysis metadata
            evidence['ai_analysis'] = {
                'provider_used': provider_used,
                'analysis_timestamp': datetime.utcnow().isoformat(),
                'discovery_id': discovery_id,
                'hostname': hostname
            }
            
            self.logger.info(f"🤖 AI analysis complete: {protocol} (confidence: {confidence:.3f}) via {provider_used}")
            return protocol, confidence, evidence
            
        except Exception as e:
            self.logger.error(f"AI analysis failed with error: {e}")
            return None, 0.0, {'error': str(e)}
    
    def _prepare_analysis_context(self, hostname: str, scan_data: Dict) -> Dict[str, Any]:
        """Prepare structured context for AI analysis"""
        nmap_data = scan_data.get('nmap', {})
        probe_data = scan_data.get('probes', {})
        
        context = {
            'hostname': hostname,
            'network_scan': {
                'open_ports': nmap_data.get('ports', []),
                'services': nmap_data.get('services', {})
            },
            'protocol_probes': {}
        }
        
        # Sanitize probe data for AI analysis
        for probe_key, probe_response in probe_data.items():
            if isinstance(probe_response, dict):
                # Limit and sanitize data for AI
                sanitized_response = {
                    'status_code': probe_response.get('status'),
                    'url': probe_response.get('url'),
                    'response_time_ms': probe_response.get('response_time_ms')
                }
                
                # Limit headers to first 5 items
                headers = probe_response.get('headers', {})
                if headers:
                    sanitized_response['headers'] = dict(list(headers.items())[:5])
                
                # Limit body to first 1000 characters
                body = probe_response.get('body', '')
                if body:
                    sanitized_response['body_preview'] = str(body)[:1000]
                
                context['protocol_probes'][probe_key] = sanitized_response
        
        return context
    
    def _analyze_with_anthropic(self, context: Dict) -> Dict:
        """Analyze using Anthropic Claude API"""
        prompt = self._build_analysis_prompt(context)
        
        headers = {
            'Content-Type': 'application/json',
            'x-api-key': self.anthropic_api_key,
            'anthropic-version': '2023-06-01'
        }
        
        payload = {
            'model': 'claude-3-5-sonnet-20241022',
            'max_tokens': 1000,
            'messages': [
                {
                    'role': 'user',
                    'content': prompt
                }
            ]
        }
        
        response = requests.post(
            'https://api.anthropic.com/v1/messages',
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code != 200:
            raise Exception(f"Anthropic API error: {response.status_code} - {response.text}")
        
        return response.json()
    
    def _analyze_with_openai(self, context: Dict) -> Dict:
        """Analyze using OpenAI GPT API"""
        prompt = self._build_analysis_prompt(context)
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.openai_api_key}'
        }
        
        payload = {
            'model': 'gpt-4',
            'messages': [
                {
                    'role': 'system',
                    'content': 'You are an expert in decentralized infrastructure protocols and network service identification.'
                },
                {
                    'role': 'user',
                    'content': prompt
                }
            ],
            'max_tokens': 1000,
            'temperature': 0.1
        }
        
        response = requests.post(
            'https://api.openai.com/v1/chat/completions',
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code != 200:
            raise Exception(f"OpenAI API error: {response.status_code} - {response.text}")
        
        return response.json()
    
    def _build_analysis_prompt(self, context: Dict) -> str:
        """Build analysis prompt for AI APIs"""
        return f"""Analyze this network scan data to identify the DePIN (Decentralized Physical Infrastructure) protocol running on {context['hostname']}:

Network Scan Data:
- Open Ports: {context['network_scan']['open_ports']}
- Services: {json.dumps(context['network_scan']['services'], indent=2)}

Protocol Probe Results:
{json.dumps(context['protocol_probes'], indent=2)}

Common DePIN Protocols:
sui, filecoin, ethereum, celestia, bittensor, theta, akash, helium, solana, polygon, arweave, storj, siacoin, chia

Analysis Instructions:
1. Look for protocol-specific indicators in ports, services, and probe responses
2. Consider JSON-RPC endpoints, specific port patterns, and protocol keywords
3. Be conservative with confidence scores - only high confidence (>0.8) for clear matches

Respond with ONLY a valid JSON object in this exact format:
{{
    "protocol": "protocol_name_or_null",
    "confidence": 0.85,
    "reasoning": "detailed explanation of identification logic",
    "key_indicators": ["evidence1", "evidence2", "evidence3"],
    "service_type": "blockchain_node"
}}

Requirements:
- Use exact protocol names (e.g., "sui", "filecoin", "ethereum")
- Set protocol to null if uncertain
- Confidence must be 0.0-1.0 based on evidence strength
- Be conservative with confidence scores
- Focus on DePIN/blockchain protocols but include other services if clearly identified"""
    
    def _parse_ai_response(self, api_response: Dict, provider: str) -> Tuple[Optional[str], float, Dict]:
        """Parse AI API response to extract protocol identification"""
        try:
            # Extract content based on provider
            if provider == 'anthropic':
                content = api_response['content'][0]['text']
            elif provider == 'openai':
                content = api_response['choices'][0]['message']['content']
            else:
                raise ValueError(f"Unknown provider: {provider}")
            
            # Clean up the content
            content = content.strip()
            
            # Remove markdown code blocks if present
            if content.startswith('```json'):
                content = content[7:]
            if content.endswith('```'):
                content = content[:-3]
            
            content = content.strip()
            
            # Parse JSON response
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError:
                # Try to extract JSON from text using regex
                json_match = re.search(r'\{.*\}', content, re.DOTALL)
                if json_match:
                    parsed = json.loads(json_match.group())
                else:
                    raise ValueError("No valid JSON found in AI response")
            
            # Extract and validate fields
            protocol = parsed.get('protocol')
            if protocol == 'null' or protocol == '' or protocol is None:
                protocol = None
            
            confidence = float(parsed.get('confidence', 0.0))
            confidence = max(0.0, min(1.0, confidence))  # Clamp between 0 and 1
            
            evidence = {
                'ai_reasoning': parsed.get('reasoning', ''),
                'key_indicators': parsed.get('key_indicators', []),
                'service_type': parsed.get('service_type', ''),
                'provider': provider,
                'raw_response': content[:500]  # Keep first 500 chars for debugging
            }
            
            return protocol, confidence, evidence
            
        except Exception as e:
            self.logger.error(f"Failed to parse AI response: {e}")
            return None, 0.0, {
                'error': f"AI response parsing failed: {str(e)}",
                'raw_response': str(api_response)[:500],
                'provider': provider
            }