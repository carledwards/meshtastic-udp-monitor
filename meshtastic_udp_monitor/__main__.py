#!/usr/bin/env python3
"""
Entry point for running meshtastic_udp_monitor as a module
Usage: python -m meshtastic_udp_monitor
"""

import argparse
from .monitor import MeshtasticUDPDecoder

def main():
    """Main entry point with argument parsing"""
    parser = argparse.ArgumentParser(
        description="Real-time Meshtastic mesh network traffic monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m meshtastic_udp_monitor           # Simple output
  python -m meshtastic_udp_monitor -v        # Verbose output with hex dumps
  python -m meshtastic_udp_monitor --verbose # Same as -v
        """
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output (hex dumps, encryption details, raw data)'
    )
    
    args = parser.parse_args()
    
    # Create and start the decoder with verbose flag
    decoder = MeshtasticUDPDecoder(verbose=args.verbose)
    decoder.start_monitoring()

if __name__ == "__main__":
    main()
