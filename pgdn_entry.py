"""
Console script entry point for the DePIN Infrastructure Scanner.
"""

import sys

def main():
    """Entry point for the pgdn console script."""
    try:
        from pgdn_scanner.cli import main as main_func
        main_func()
    except ImportError as e:
        print(f"Error importing cli module: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
