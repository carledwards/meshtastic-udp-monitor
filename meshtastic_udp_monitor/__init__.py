"""
Meshtastic UDP Monitor - Real-time monitoring and decoding of Meshtastic mesh network traffic

This package provides tools for monitoring UDP multicast packets from Meshtastic devices
on the local network, with support for decryption and detailed packet analysis.
"""

__version__ = "1.0.0"
__author__ = "Carl Edwards"
__description__ = "Real-time Meshtastic mesh network traffic monitor"

from .monitor import MeshtasticUDPDecoder

def main():
    """Main entry point for the UDP monitor"""
    from .__main__ import main as _main
    _main()

__all__ = ['MeshtasticUDPDecoder', 'main']
