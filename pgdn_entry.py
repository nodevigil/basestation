"""
Console script entry point for the DePIN Infrastructure Scanner.
"""

import sys
import os

# Add the current directory to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

def main():
    """Entry point for the pgdn console script."""
    try:
        from cli import main as main_func
        main_func()
    except ImportError as e:
        print(f"Error importing cli module: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
