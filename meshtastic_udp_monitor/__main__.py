#!/usr/bin/env python3
"""
Entry point for running meshtastic_udp_monitor as a module
Usage: python -m meshtastic_udp_monitor
"""

import argparse
import sys
import os
from datetime import datetime
from .monitor import MeshtasticUDPDecoder

def cmd_monitor(args):
    """Handle monitor command"""
    decoder = MeshtasticUDPDecoder(
        verbose=args.verbose, 
        capture_dir=args.capture_dir,
        node_db_file=getattr(args, 'node_db', None)
    )
    decoder.start_monitoring()

def cmd_replay(args):
    """Handle replay command"""
    decoder = MeshtasticUDPDecoder(
        verbose=args.verbose,
        node_db_file=getattr(args, 'node_db', None)
    )
    
    if args.input:
        # Replay from file or directory
        if os.path.isdir(args.input):
            decoder.replay_directory(args.input, update_db=getattr(args, 'update_db', False))
        else:
            decoder.replay_file(args.input, update_db=getattr(args, 'update_db', False))
    else:
        # Replay from stdin
        decoder.replay_stdin(update_db=getattr(args, 'update_db', False))

def main():
    """Main entry point with subcommand parsing"""
    parser = argparse.ArgumentParser(
        prog="python -m meshtastic_udp_monitor",
        description="Real-time Meshtastic mesh network traffic monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor live traffic
  python -m meshtastic_udp_monitor
  python -m meshtastic_udp_monitor monitor -v
  python -m meshtastic_udp_monitor monitor --capture-dir ./packets/
  
  # Replay captured data
  python -m meshtastic_udp_monitor replay packets.tsv
  python -m meshtastic_udp_monitor replay ./packets/ -v
  cat packets.tsv | python -m meshtastic_udp_monitor replay
        """
    )
    
    # Create subparsers for commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Monitor command (default)
    monitor_parser = subparsers.add_parser('monitor', help='Monitor live UDP traffic')
    monitor_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output (hex dumps, encryption details, raw data)'
    )
    monitor_parser.add_argument(
        '--capture-dir',
        help='Directory to capture packets to (creates daily .tsv files)'
    )
    monitor_parser.add_argument(
        '--node-db',
        help='Node database file (JSONL format) to track node information'
    )
    monitor_parser.set_defaults(func=cmd_monitor)
    
    # Replay command
    replay_parser = subparsers.add_parser('replay', help='Replay captured packets')
    replay_parser.add_argument(
        'input',
        nargs='?',
        help='File or directory to replay from (omit to read from stdin)'
    )
    replay_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output (hex dumps, encryption details, raw data)'
    )
    replay_parser.add_argument(
        '--node-db',
        help='Node database file (JSONL format) to use for node name lookups'
    )
    replay_parser.add_argument(
        '--update-db',
        action='store_true',
        help='Update the node database with information found during replay'
    )
    replay_parser.set_defaults(func=cmd_replay)
    
    # Parse arguments
    args = parser.parse_args()
    
    # If no command specified, default to monitor
    if args.command is None:
        # Check if there are any monitor-specific args in the root
        # For backward compatibility, support -v at root level
        if len(sys.argv) > 1 and ('-v' in sys.argv or '--verbose' in sys.argv):
            args.verbose = True
        else:
            args.verbose = False
        args.capture_dir = None
        cmd_monitor(args)
    else:
        # Execute the specified command
        args.func(args)

if __name__ == "__main__":
    main()
