"""
Configuration Helper - Simple config setup for AI-enhanced discovery
"""

import os
from typing import Optional


def create_ai_enhanced_config(openai_key: Optional[str] = None, 
                             anthropic_key: Optional[str] = None,
                             enable_ai_fallback: bool = True,
                             ai_fallback_threshold: float = 0.4,
                             preferred_provider: str = 'auto'):
    """
    Create configuration for AI-enhanced DePIN Discovery Agent.
    
    Args:
        openai_key: OpenAI API key
        anthropic_key: Anthropic API key
        enable_ai_fallback: Whether to enable AI fallback detection
        ai_fallback_threshold: Confidence threshold below which AI is used
        preferred_provider: Preferred AI provider ('auto', 'openai', 'anthropic')
        
    Returns:
        Configuration object
    """
    
    class Config:
        def __init__(self):
            self.enable_ai_fallback = enable_ai_fallback
            self.ai_fallback_threshold = ai_fallback_threshold
            self.ai_provider = preferred_provider
            
            # Set API keys from parameters or environment
            self.openai_api_key = openai_key or os.environ.get('OPENAI_API_KEY')
            self.anthropic_api_key = anthropic_key or os.environ.get('ANTHROPIC_API_KEY')
    
    return Config()


# Example usage
if __name__ == "__main__":
    # Example 1: Use environment variables
    config = create_ai_enhanced_config()
    
    # Example 2: Explicit API keys
    config = create_ai_enhanced_config(
        openai_key="your-openai-key-here",
        anthropic_key="your-anthropic-key-here",
        ai_fallback_threshold=0.3,
        preferred_provider='anthropic'
    )
    
    # Example 3: Disable AI fallback
    config = create_ai_enhanced_config(
        enable_ai_fallback=False
    )