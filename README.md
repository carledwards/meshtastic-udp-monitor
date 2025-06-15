# Meshtastic UDP Monitor

Real-time monitoring and decoding of Meshtastic mesh network traffic via UDP multicast packets.

## Overview

This tool captures and decodes UDP multicast packets broadcast by Meshtastic devices on your local network, providing detailed analysis of mesh network communications including:

- Real-time packet monitoring with protobuf decoding
- PSK decryption for multiple channel types (LongFast, NodeChat, YardSale, etc.)
- Message type analysis (text messages, position updates, telemetry, traceroute, etc.)
- Network topology visualization through traceroute analysis
- Signal quality metrics (RSSI, SNR) with quality indicators
- Packet analysis with hex dumps and statistics

## Features

### 🔍 **Comprehensive Packet Analysis**
- Decodes MeshPacket protobuf structures
- Supports all Meshtastic port types (TEXT_MESSAGE, POSITION, TELEMETRY, TRACEROUTE, etc.)
- Real-time hex dump analysis with ASCII representation
- Detailed packet statistics and monitoring rates

### 🔐 **Advanced Decryption Support**
- **PSK Decryption** for standard channels:
  - Default channel (LongFast)
  - Channel 1 (NodeChat)
  - Channel 2 (YardSale)
  - Event channels
  - All PSK variants (256 different keys)
- Automatic key detection and fallback
- PKI encryption detection (requires private keys)

### 📊 **Rich Data Interpretation**
- **Text Messages**: Full UTF-8 message decoding
- **Position Data**: GPS coordinates with Google Maps links
- **Telemetry**: Voltage, temperature, and sensor data
- **Traceroute**: Network path visualization with SNR measurements
- **Node Information**: Device details, hardware models, MAC addresses
- **Routing**: ACK packets, error codes, and network status

### 🛠️ **Additional Features**
- Signal quality assessment (Excellent/Good/Fair/Poor ratings)
- Network performance monitoring
- Graceful shutdown with statistics
- Thread-safe packet counting
- Configurable output formatting

## Installation

### Option 1: Install from PyPI (when published)
```bash
pip install meshtastic-udp-monitor
```

### Option 2: Install from Source
```bash
git clone https://github.com/carledwards/meshtastic-udp-monitor.git
cd meshtastic-udp-monitor
pip install -e .
```

### Option 3: Manual Installation with Virtual Environment (Recommended)
```bash
git clone https://github.com/carledwards/meshtastic-udp-monitor.git
cd meshtastic-udp-monitor

# Create and activate virtual environment
python3 -m venv .env
source .env/bin/activate  # On Windows: .env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Option 4: Manual Installation (System-wide)
```bash
git clone https://github.com/carledwards/meshtastic-udp-monitor.git
cd meshtastic-udp-monitor
pip install -r requirements.txt
```

## Usage

### Basic Usage
```bash
# Simple, clean output (default)
python -m meshtastic_udp_monitor

# Verbose output with hex dumps and detailed analysis
python -m meshtastic_udp_monitor -v
python -m meshtastic_udp_monitor --verbose

# Show help
python -m meshtastic_udp_monitor --help
```

### Run as Installed Command
```bash
# After pip install
meshtastic-udp-monitor
meshtastic-udp-monitor -v
# or
mesh-monitor
mesh-monitor --verbose
```

### Output Modes

**Simple Mode (Default)**: Clean, essential information
- Packet source/destination
- Channel and signal quality
- Message type and key content
- Perfect for real-time monitoring

**Verbose Mode (`-v`)**: Detailed technical analysis
- Complete packet headers
- Hex dumps of raw data
- Decryption process details
- All protobuf fields
- Ideal for debugging and analysis

## Requirements

- Python 3.7+
- Network access to Meshtastic devices broadcasting UDP packets
- Dependencies (automatically installed):
  - `meshtastic>=2.0.0` - Official Meshtastic Python library
  - `protobuf>=4.0.0` - Protocol buffer support
  - `cryptography>=3.0.0` - Encryption/decryption support

## Network Setup

Your Meshtastic devices must be configured to broadcast UDP packets on your local network:

### Device Configuration Required:

1. **Enable WiFi** on your Meshtastic device
   - Use the Meshtastic app or web interface
   - Configure WiFi credentials for your local network

2. **Enable UDP Broadcasting** (if not already enabled)
   - In the Meshtastic app: Settings → Radio Configuration → Network
   - Enable "WiFi" if not already on
   - Ensure "UDP Broadcast" or "Network Logging" is enabled
   - Some firmware versions enable this by default

3. **Connect to your local network**
   - Device should show as connected to WiFi
   - Device and monitoring computer must be on the same network

4. **Verify UDP packets are being sent**
   - Multicast packets are sent to `224.0.0.69:4403`
   - Most mesh traffic will automatically broadcast over UDP when WiFi is enabled

### Troubleshooting Device Setup:

- **No packets received?** Check that WiFi is connected and UDP broadcasting is enabled
- **Firewall issues?** Ensure UDP port 4403 is allowed on your network
- **Wrong network?** Device and computer must be on the same local network/subnet
- **Firmware version?** Newer firmware versions have better UDP support

The monitor will automatically detect and decode packets from any properly configured Meshtastic device on your network.

## Example Output

**Simple Mode (Default):**
```
Using Meshtastic protobuf definitions
Listening for Meshtastic UDP packets on 224.0.0.69:4403
Press Ctrl+C to stop monitoring

Packet #1 - 2025-06-15 08:00:15.123
From: !4e66636c → To: Broadcast
Channel: 0 | Hops: 3/3 | Signal: -65 dBm (Good), 8.5 dB SNR

TEXT_MESSAGE_APP: Text Message
  📱 Message Text: "Hello mesh network!"
```

**Verbose Mode (`-v` flag):**
```
Using Meshtastic protobuf definitions
Listening for Meshtastic UDP packets on 224.0.0.69:4403
Press Ctrl+C to stop monitoring

Packet #1 - 2025-06-15 08:00:15.123
Source: 192.168.1.100:4403
Size: 45 bytes

DECODED MESHPACKET:
  From Node: !4e66636c
  To: Broadcast (all nodes)
  Channel Hash: 0
  Packet ID: 0x1a2b3c4d
  SNR: 8.5 dB (Good)
  RSSI: -65 dBm (Good)
  Hop Limit: 3 hops remaining

  DECRYPTION ATTEMPT:
    Status: Success (using Default PSK (index 1))

    Decoded Message:
      Port: TEXT_MESSAGE_APP (1)
      📱 Message Text: "Hello mesh network!"

RAW PACKET DATA:
  0000: 08 6c 63 66 4e 10 ff ff ff ff 0f 18 00 20 4d 3c |.lcfN........ M<|
  0010: 2b 1a 32 0a 1e 0a 12 48 65 6c 6c 6f 20 6d 65 73 |+.2....Hello mes|
  0020: 68 20 6e 65 74 77 6f 72 6b 21 10 01 18 01       |h network!....|
```

See [examples/example_output.txt](examples/example_output.txt) for more detailed output examples.

## Supported Message Types

| Port Type | Description | Decoded Information |
|-----------|-------------|-------------------|
| `TEXT_MESSAGE_APP` | Text messages | Full message content, sender info |
| `POSITION_APP` | GPS location | Coordinates, altitude, speed, satellites |
| `TELEMETRY_APP` | Device sensors | Voltage, temperature, environmental data |
| `TRACEROUTE_APP` | Network routing | Route paths, hop counts, SNR measurements |
| `NODEINFO_APP` | Device info | Node names, hardware models, MAC addresses |
| `ROUTING_APP` | Network control | ACK packets, error codes, routing status |
| `NEIGHBORINFO_APP` | Neighbor discovery | Local node information |
| `ADMIN_APP` | Device administration | Configuration and control messages |

## Encryption Support

### PSK (Pre-Shared Key) Decryption ✅
- **Default Channel** (LongFast) - Most common
- **Channel 1** (NodeChat) - Secondary channel
- **Channel 2** (YardSale) - Tertiary channel  
- **Event Channels** - Special event communications
- **All PSK Variants** - 256 different key combinations

### PKI (Public Key Infrastructure) Detection ✅
- Detects PKI-encrypted direct messages
- Requires device private keys for decryption
- Provides guidance for PKI key extraction

## Troubleshooting

### No Packets Received
1. **Check network connectivity** - Ensure devices are on same network
2. **Verify UDP broadcasting** - Check device WiFi settings
3. **Firewall settings** - Allow UDP traffic on port 4403
4. **Multicast support** - Ensure your network supports multicast

### Decryption Failures
1. **Channel configuration** - Verify channel settings match
2. **PSK variants** - Tool tries 256+ key combinations automatically
3. **PKI encryption** - Direct messages may use PKI (requires private keys)
4. **Custom channels** - Non-standard channels may need custom PSKs

### Performance Issues
1. **High packet rates** - Normal for active mesh networks
2. **CPU usage** - Decryption is computationally intensive
3. **Memory usage** - Monitor with large networks

## Development

### Project Structure
```
meshtastic-udp-monitor/
├── meshtastic_udp_monitor/
│   ├── __init__.py          # Package initialization
│   ├── __main__.py          # Module entry point
│   └── monitor.py           # Main monitoring class
├── examples/
│   └── example_output.txt   # Sample output
├── requirements.txt         # Dependencies
├── setup.py                # Package setup
├── README.md               # This file
└── LICENSE                 # MIT License
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **Meshtastic Project** - For the amazing mesh networking platform
- **Meshtastic Python Library** - For protobuf definitions and utilities
- **Community Contributors** - For testing and feedback

## Related Projects

- [Meshtastic](https://meshtastic.org/) - The main Meshtastic project
- [Meshtastic Python](https://github.com/meshtastic/python) - Official Python library
- [Meshtastic Firmware](https://github.com/meshtastic/firmware) - Device firmware
