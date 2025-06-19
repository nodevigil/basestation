"""
Entry point for the DePIN Infrastructure Scanner console script.
"""

import sys
import os

# Add the current directory to the Python path so we can import main
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _main import main

def main_entry():
    """Entry point for the console script."""
    main()

if __name__ == "__main__":
    main()
