#!/usr/bin/env python3
"""
Meshtastic UDP Packet Monitor - Main monitoring class

Monitors and decodes UDP multicast packets from Meshtastic devices on the local network.
Uses the actual Meshtastic protobuf definitions for accurate parsing with PSK decryption support.
"""

import socket
import struct
import time
import signal
import sys
import os
import glob
from datetime import datetime
import threading
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Import the actual Meshtastic protobuf definitions
try:
    from meshtastic import mesh_pb2, portnums_pb2, telemetry_pb2
    PROTOBUF_AVAILABLE = True
except ImportError as e:
    print(f"✗ Error importing Meshtastic protobufs: {e}")
    print("Install with: pip install meshtastic")
    sys.exit(1)

class MeshtasticUDPDecoder:
    def __init__(self, verbose=False, capture_dir=None):
        self.multicast_group = '224.0.0.69'
        self.port = 4403
        self.sock = None
        self.running = False
        self.packet_count = 0
        self.total_bytes = 0
        self.start_time = None
        self.stats_lock = threading.Lock()
        self.verbose = verbose
        self.capture_dir = capture_dir
        self.capture_file = None
        self.current_capture_date = None
        
        # Default channel keys - from Meshtastic source code
        # The actual PSKs from src/mesh/Channels.h and userPrefs.jsonc
        default_psk = bytes([0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
                            0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01])
        
        # Event PSK (32-byte AES-256 key) - also used as USERPREFS_CHANNEL_0_PSK
        event_psk = bytes([0x38, 0x4b, 0xbc, 0xc0, 0x1d, 0xc0, 0x22, 0xd1, 0x81, 0xbf, 0x36,
                          0xb8, 0x61, 0x21, 0xe1, 0xfb, 0x96, 0xb7, 0x2e, 0x55, 0xbf, 0x74,
                          0x22, 0x7e, 0x9d, 0x6a, 0xfb, 0x48, 0xd6, 0x4c, 0xb1, 0xa1])
        
        # Predefined PSKs from userPrefs.jsonc
        channel_1_psk = bytes([0x4e, 0x22, 0x1d, 0x8b, 0xc3, 0x09, 0x1b, 0xe2, 0x11, 0x9c, 0x89, 0x12, 
                              0xf2, 0x25, 0x19, 0x5d, 0x15, 0x3e, 0x30, 0x7b, 0x86, 0xb6, 0xec, 0xc4, 
                              0x6a, 0xc3, 0x96, 0x5e, 0x9e, 0x10, 0x9d, 0xd5])
        
        channel_2_psk = bytes([0x15, 0x6f, 0xfe, 0x46, 0xd4, 0x56, 0x63, 0x8a, 0x54, 0x43, 0x13, 0xf2, 
                              0xef, 0x6c, 0x63, 0x89, 0xf0, 0x06, 0x30, 0x52, 0xce, 0x36, 0x5e, 0xb1, 
                              0xe8, 0xbb, 0x86, 0xe6, 0x26, 0x5b, 0x1d, 0x58])
        
        # Generate PSK variants for different pskIndex values
        psk_variants = []
        for psk_index in range(0, 256):  # Try pskIndex 0-255 (including 0 for no encryption)
            if psk_index == 0:
                # pskIndex 0 means no encryption - but we still need a key for the hash calculation
                psk_variants.append((b'\x00' * 16, "No encryption (pskIndex 0)"))
            else:
                variant = bytearray(default_psk)
                variant[-1] = (variant[-1] + psk_index - 1) % 256
                psk_variants.append((bytes(variant), f"PSK variant (index {psk_index})"))
        
        # Combine all PSKs in priority order (most common first)
        self.channel_keys = [
            (default_psk, "Default PSK (index 1)"),
            (channel_1_psk, "Channel 1 (NodeChat)"),
            (channel_2_psk, "Channel 2 (YardSale)"),
            (event_psk, "Event PSK (32-byte)"),
        ] + psk_variants
        
    def setup_socket(self):
        """Set up the multicast UDP socket"""
        try:
            # Create socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to the multicast group
            self.sock.bind(('', self.port))
            
            # Join multicast group
            mreq = struct.pack("4sl", socket.inet_aton(self.multicast_group), socket.INADDR_ANY)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            print(f"Listening for Meshtastic UDP packets on {self.multicast_group}:{self.port}")
            print("Press Ctrl+C to stop monitoring\n")
            return True
            
        except Exception as e:
            print(f"✗ Error setting up socket: {e}")
            return False
    
    def format_hex_dump(self, data, bytes_per_line=16):
        """Format binary data as a hex dump with ASCII representation"""
        lines = []
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i + bytes_per_line]
            
            # Hex representation
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
            
            # ASCII representation
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            
            lines.append(f"  {i:04x}: {hex_part} |{ascii_part}|")
        
        return '\n'.join(lines)
    
    def format_node_id(self, node_id):
        """Format node ID in hex format like Meshtastic app"""
        return f"!{node_id:08x}"
    
    def format_timestamp(self, timestamp):
        """Format Unix timestamp to readable date/time"""
        try:
            dt = datetime.fromtimestamp(timestamp)
            return f"{dt.strftime('%Y-%m-%d %H:%M:%S')} ({timestamp})"
        except:
            return f"Invalid timestamp ({timestamp})"
    
    def format_rssi_snr(self, value):
        """Format RSSI/SNR values with quality indicators"""
        # Add quality indicator for SNR
        if value >= 10:
            quality = "Excellent"
        elif value >= 5:
            quality = "Good"
        elif value >= 0:
            quality = "Fair"
        elif value >= -5:
            quality = "Poor"
        else:
            quality = "Very Poor"
            
        return f"{value:.1f} dB ({quality})"
    
    def format_rssi(self, rssi_val):
        """Format RSSI values with quality indicators"""
        # Add quality indicator for RSSI
        if rssi_val >= -50:
            quality = "Excellent"
        elif rssi_val >= -60:
            quality = "Very Good"
        elif rssi_val >= -70:
            quality = "Good"
        elif rssi_val >= -80:
            quality = "Fair"
        elif rssi_val >= -90:
            quality = "Poor"
        else:
            quality = "Very Poor"
            
        return f"{rssi_val} dBm ({quality})"
    
    def format_priority(self, priority):
        """Format priority with human-readable names"""
        priority_names = {
            mesh_pb2.MeshPacket.Priority.UNSET: "UNSET",
            mesh_pb2.MeshPacket.Priority.MIN: "MIN",
            mesh_pb2.MeshPacket.Priority.BACKGROUND: "BACKGROUND", 
            mesh_pb2.MeshPacket.Priority.DEFAULT: "DEFAULT",
            mesh_pb2.MeshPacket.Priority.RELIABLE: "RELIABLE",
            mesh_pb2.MeshPacket.Priority.RESPONSE: "RESPONSE",
            mesh_pb2.MeshPacket.Priority.HIGH: "HIGH",
            mesh_pb2.MeshPacket.Priority.ALERT: "ALERT",
            mesh_pb2.MeshPacket.Priority.ACK: "ACK",
            mesh_pb2.MeshPacket.Priority.MAX: "MAX"
        }
        
        name = priority_names.get(priority, "UNKNOWN")
        return f"{name} ({priority})"
    
    def construct_correct_nonce(self, packet_id, from_node):
        """Construct nonce exactly like Meshtastic does in CryptoEngine::initNonce"""
        nonce = bytearray(16)  # 128-bit nonce
        
        # First 8 bytes: packetId as 64-bit little-endian
        struct.pack_into('<Q', nonce, 0, packet_id)
        
        # Next 4 bytes: fromNode as 32-bit little-endian  
        struct.pack_into('<I', nonce, 8, from_node)
        
        # Last 4 bytes remain zero (no extraNonce for regular packets)
        
        return bytes(nonce)

    def decrypt_payload(self, encrypted_data, packet_id, from_node, channel_hash):
        """Attempt to decrypt the encrypted payload using available channel keys"""
        # Try all available keys since we don't know which channel index produces this hash
        for i, (key, key_name) in enumerate(self.channel_keys):
            try:
                # Construct nonce CORRECTLY like Meshtastic does
                nonce = self.construct_correct_nonce(packet_id, from_node)
                
                # For AES-256 keys, truncate to 16 bytes for AES-128
                if len(key) > 16:
                    key = key[:16]
                
                # Create cipher
                cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
                decryptor = cipher.decryptor()
                
                # Decrypt the payload
                decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
                
                # Try to parse as Data protobuf first
                try:
                    data_msg = mesh_pb2.Data()
                    data_msg.ParseFromString(decrypted)
                    
                    # Validate that this looks like a real protobuf message
                    # Check if portnum is in valid range
                    if hasattr(data_msg, 'portnum') and 0 <= data_msg.portnum <= 255:
                        return decrypted, f"Success (using {key_name})", data_msg
                    
                except Exception:
                    pass
                
                # Try parsing as Routing protobuf (for traceroute packets)
                try:
                    routing_msg = mesh_pb2.Routing()
                    routing_msg.ParseFromString(decrypted)
                    
                    # If parsing succeeded, this is likely the correct key
                    return decrypted, f"Success (using {key_name})", routing_msg
                    
                except Exception:
                    pass
                
                # If protobuf parsing failed, check if decrypted data looks reasonable
                # (sometimes the decryption works but protobuf parsing fails)
                if len(decrypted) > 0:
                    # Check if it starts with reasonable protobuf field tags
                    if decrypted[0] in [0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78]:
                        # This might be valid protobuf data even if parsing failed
                        return decrypted, f"Partial success (using {key_name}) - protobuf parsing failed", None
                
            except Exception as e:
                continue  # Try next key
        
        # Try some additional PSK variants based on the channel hash
        additional_keys = []
        
        # Generate PSK based on channel hash
        for base_psk in [self.channel_keys[0][0], self.channel_keys[1][0]]:  # Try default and channel 1 PSKs
            variant = bytearray(base_psk)
            # Modify based on channel hash
            variant[-1] = (variant[-1] + channel_hash) % 256
            additional_keys.append((bytes(variant), f"Hash-based variant (hash {channel_hash})"))
        
        # Try the additional keys
        for key, key_name in additional_keys:
            try:
                nonce = self.construct_correct_nonce(packet_id, from_node)
                
                if len(key) > 16:
                    key = key[:16]
                
                cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
                
                # Try protobuf parsing
                try:
                    data_msg = mesh_pb2.Data()
                    data_msg.ParseFromString(decrypted)
                    if hasattr(data_msg, 'portnum') and 0 <= data_msg.portnum <= 255:
                        return decrypted, f"Success (using {key_name})", data_msg
                except:
                    pass
                
                try:
                    routing_msg = mesh_pb2.Routing()
                    routing_msg.ParseFromString(decrypted)
                    return decrypted, f"Success (using {key_name})", routing_msg
                except:
                    pass
                    
            except Exception:
                continue
        
        # Check if this might be PKI encrypted
        pki_hint = ""
        if len(encrypted_data) > 12:  # PKI packets have extra auth data
            pki_hint = " (Packet may use PKI encryption - requires node's private key)"
        
        return None, f"All decryption attempts failed for channel hash {channel_hash} (tried {len(self.channel_keys) + len(additional_keys)} keys){pki_hint}", None
    
    def format_hardware_model(self, hw_model):
        """Format hardware model number with human-readable name"""
        # Hardware model mapping from actual meshtastic firmware source
        # Based on meshtastic/mesh.pb.h from the official firmware repository
        hardware_models = {
            0: "UNSET",
            1: "TLORA_V2",
            2: "TLORA_V1", 
            3: "TLORA_V2_1_1P6",
            4: "TBEAM",
            5: "HELTEC_V2_0",
            6: "TBEAM_V0P7",
            7: "T_ECHO",
            8: "TLORA_V1_1P3",
            9: "RAK4631",
            10: "HELTEC_V2_1",
            11: "HELTEC_V1",
            12: "LILYGO_TBEAM_S3_CORE",
            13: "RAK11200",
            14: "NANO_G1",
            15: "TLORA_V2_1_1P8",
            16: "TLORA_T3_S3",
            17: "NANO_G1_EXPLORER",
            18: "NANO_G2_ULTRA",
            19: "LORA_TYPE",
            20: "WIPHONE",
            21: "WIO_WM1110",
            22: "RAK2560",
            23: "HELTEC_HRU_3601",
            24: "HELTEC_WIRELESS_BRIDGE",
            25: "STATION_G1",
            26: "RAK11310",
            27: "SENSELORA_RP2040",
            28: "SENSELORA_S3",
            29: "CANARYONE",
            30: "RP2040_LORA",
            31: "STATION_G2",
            32: "LORA_RELAY_V1",
            33: "NRF52840DK",
            34: "PPR",
            35: "GENIEBLOCKS",
            36: "NRF52_UNKNOWN",
            37: "PORTDUINO",
            38: "ANDROID_SIM",
            39: "DIY_V1",
            40: "NRF52840_PCA10059",
            41: "DR_DEV",
            42: "M5STACK",
            43: "HELTEC_V3",
            44: "HELTEC_WSL_V3",
            45: "BETAFPV_2400_TX",
            46: "BETAFPV_900_NANO_TX",
            47: "RPI_PICO",
            48: "HELTEC_WIRELESS_TRACKER",
            49: "HELTEC_WIRELESS_PAPER",
            50: "T_DECK",
            51: "T_WATCH_S3",
            52: "PICOMPUTER_S3",
            53: "HELTEC_HT62",
            54: "EBYTE_ESP32_S3",
            55: "ESP32_S3_PICO",
            56: "CHATTER_2",
            57: "HELTEC_WIRELESS_PAPER_V1_0",
            58: "HELTEC_WIRELESS_TRACKER_V1_0",
            59: "UNPHONE",
            60: "TD_LORAC",
            61: "CDEBYTE_EORA_S3",
            62: "TWC_MESH_V4",
            63: "NRF52_PROMICRO_DIY",
            64: "RADIOMASTER_900_BANDIT_NANO",
            65: "HELTEC_CAPSULE_SENSOR_V3",
            66: "HELTEC_VISION_MASTER_T190",
            67: "HELTEC_VISION_MASTER_E213",
            68: "HELTEC_VISION_MASTER_E290",
            69: "HELTEC_MESH_NODE_T114",
            70: "SENSECAP_INDICATOR",
            71: "TRACKER_T1000_E",
            72: "RAK3172",
            73: "WIO_E5",
            74: "RADIOMASTER_900_BANDIT",
            75: "ME25LS01_4Y10TD",
            76: "RP2040_FEATHER_RFM95",
            77: "M5STACK_COREBASIC",
            78: "M5STACK_CORE2",
            79: "RPI_PICO2",
            80: "M5STACK_CORES3",
            81: "SEEED_XIAO_S3",
            82: "MS24SF1",
            83: "TLORA_C6",
            84: "WISMESH_TAP",
            85: "ROUTASTIC",
            86: "MESH_TAB",
            87: "MESHLINK",
            88: "XIAO_NRF52_KIT",
            89: "THINKNODE_M1",
            90: "THINKNODE_M2",
            91: "T_ETH_ELITE",
            92: "HELTEC_SENSOR_HUB",
            93: "RESERVED_FRIED_CHICKEN",
            94: "HELTEC_MESH_POCKET",
            95: "SEEED_SOLAR_NODE",
            96: "NOMADSTAR_METEOR_PRO",
            97: "CROWPANEL",
            98: "LINK_32",
            99: "SEEED_WIO_TRACKER_L1",
            100: "SEEED_WIO_TRACKER_L1_EINK",
            101: "QWANTZ_TINY_ARMS",
            102: "T_DECK_PRO",
            103: "T_LORA_PAGER",
            104: "GAT562_MESH_TRIAL_TRACKER",
            255: "PRIVATE_HW"
        }
        
        model_name = hardware_models.get(hw_model, f"UNKNOWN_HW_{hw_model}")
        return f"{model_name} ({hw_model})"

    def format_portnum(self, portnum):
        """Format port number with human-readable name"""
        port_names = {
            portnums_pb2.PortNum.UNKNOWN_APP: "UNKNOWN_APP",
            portnums_pb2.PortNum.TEXT_MESSAGE_APP: "TEXT_MESSAGE_APP",
            portnums_pb2.PortNum.REMOTE_HARDWARE_APP: "REMOTE_HARDWARE_APP",
            portnums_pb2.PortNum.POSITION_APP: "POSITION_APP",
            portnums_pb2.PortNum.NODEINFO_APP: "NODEINFO_APP",
            portnums_pb2.PortNum.ROUTING_APP: "ROUTING_APP",
            portnums_pb2.PortNum.ADMIN_APP: "ADMIN_APP",
            portnums_pb2.PortNum.TEXT_MESSAGE_COMPRESSED_APP: "TEXT_MESSAGE_COMPRESSED_APP",
            portnums_pb2.PortNum.WAYPOINT_APP: "WAYPOINT_APP",
            portnums_pb2.PortNum.AUDIO_APP: "AUDIO_APP",
            portnums_pb2.PortNum.DETECTION_SENSOR_APP: "DETECTION_SENSOR_APP",
            portnums_pb2.PortNum.REPLY_APP: "REPLY_APP",
            portnums_pb2.PortNum.IP_TUNNEL_APP: "IP_TUNNEL_APP",
            portnums_pb2.PortNum.PAXCOUNTER_APP: "PAXCOUNTER_APP",
            portnums_pb2.PortNum.SERIAL_APP: "SERIAL_APP",
            portnums_pb2.PortNum.STORE_FORWARD_APP: "STORE_FORWARD_APP",
            portnums_pb2.PortNum.RANGE_TEST_APP: "RANGE_TEST_APP",
            portnums_pb2.PortNum.TELEMETRY_APP: "TELEMETRY_APP",
            portnums_pb2.PortNum.ZPS_APP: "ZPS_APP",
            portnums_pb2.PortNum.SIMULATOR_APP: "SIMULATOR_APP",
            portnums_pb2.PortNum.TRACEROUTE_APP: "TRACEROUTE_APP",
            portnums_pb2.PortNum.NEIGHBORINFO_APP: "NEIGHBORINFO_APP",
            portnums_pb2.PortNum.ATAK_PLUGIN: "ATAK_PLUGIN",
            portnums_pb2.PortNum.PRIVATE_APP: "PRIVATE_APP",
            portnums_pb2.PortNum.ATAK_FORWARDER: "ATAK_FORWARDER"
        }
        
        port_name = port_names.get(portnum, f"UNKNOWN_PORT_{portnum}")
        return f"{port_name} ({portnum})"
    
    def decode_data_payload(self, data_msg):
        """Decode the Data protobuf message with detailed payload analysis"""
        interpretation = {}
        
        # Port number
        interpretation["Port"] = self.format_portnum(data_msg.portnum)
        
        # Detailed payload decoding based on port type
        if data_msg.payload:
            if data_msg.portnum == portnums_pb2.PortNum.TEXT_MESSAGE_APP:
                try:
                    text = data_msg.payload.decode('utf-8')
                    interpretation["📱 Message Text"] = f'"{text}"'
                except:
                    interpretation["Payload Data"] = f"bytes({len(data_msg.payload)}): {data_msg.payload.hex()[:40]}{'...' if len(data_msg.payload) > 20 else ''}"
                    
            elif data_msg.portnum == portnums_pb2.PortNum.TRACEROUTE_APP:
                try:
                    route = mesh_pb2.RouteDiscovery()
                    route.ParseFromString(data_msg.payload)
                    
                    if route.route:
                        route_nodes = [self.format_node_id(node) for node in route.route]
                        interpretation["🛣️ Route Path"] = " → ".join(route_nodes)
                        interpretation["🔢 Hop Count"] = f"{len(route.route)} nodes"
                        
                    if route.snr_towards:
                        snr_values = [f"{snr/4:.1f}dB" for snr in route.snr_towards]
                        interpretation["📶 SNR Forward"] = " → ".join(snr_values)
                        
                    if route.snr_back:
                        snr_back_values = [f"{snr/4:.1f}dB" for snr in route.snr_back]
                        interpretation["📶 SNR Return"] = " → ".join(snr_back_values)
                        
                except Exception as e:
                    interpretation["Payload Data"] = f"bytes({len(data_msg.payload)}): {data_msg.payload.hex()[:40]}{'...' if len(data_msg.payload) > 20 else ''}"
                    
            elif data_msg.portnum == portnums_pb2.PortNum.POSITION_APP:
                try:
                    position = mesh_pb2.Position()
                    position.ParseFromString(data_msg.payload)
                    
                    if position.latitude_i and position.longitude_i:
                        lat = position.latitude_i * 1e-7
                        lon = position.longitude_i * 1e-7
                        interpretation["🌍 Location"] = f"{lat:.6f}, {lon:.6f}"
                        interpretation["🗺️ Maps Link"] = f"https://maps.google.com/?q={lat},{lon}"
                    
                    if position.altitude:
                        interpretation["⛰️ Altitude"] = f"{position.altitude}m"
                        
                    if position.ground_speed:
                        interpretation["🏃 Speed"] = f"{position.ground_speed} km/h"
                        
                    if position.sats_in_view:
                        interpretation["🛰️ Satellites"] = f"{position.sats_in_view}"
                        
                except Exception as e:
                    # Try manual decoding
                    try:
                        if len(data_msg.payload) >= 8:
                            lat_i = struct.unpack('<i', data_msg.payload[0:4])[0]
                            lon_i = struct.unpack('<i', data_msg.payload[4:8])[0]
                            
                            if lat_i != 0 and lon_i != 0:
                                lat = lat_i * 1e-7
                                lon = lon_i * 1e-7
                                interpretation["🌍 Location"] = f"{lat:.6f}, {lon:.6f}"
                                interpretation["🗺️ Maps Link"] = f"https://maps.google.com/?q={lat},{lon}"
                    except:
                        pass
                    interpretation["Payload Data"] = f"bytes({len(data_msg.payload)}): {data_msg.payload.hex()[:40]}{'...' if len(data_msg.payload) > 20 else ''}"
                    
            elif data_msg.portnum == portnums_pb2.PortNum.NODEINFO_APP:
                try:
                    user = mesh_pb2.User()
                    user.ParseFromString(data_msg.payload)
                    
                    interpretation["📛 Node ID"] = user.id
                    interpretation["📝 Long Name"] = user.long_name
                    interpretation["🏷️ Short Name"] = user.short_name
                    
                    if user.macaddr:
                        mac = ':'.join(f'{b:02x}' for b in user.macaddr)
                        interpretation["🔗 MAC Address"] = mac
                        
                    if user.hw_model:
                        interpretation["💻 Hardware"] = self.format_hardware_model(user.hw_model)
                        
                except Exception as e:
                    interpretation["Payload Data"] = f"bytes({len(data_msg.payload)}): {data_msg.payload.hex()[:40]}{'...' if len(data_msg.payload) > 20 else ''}"
                    
            elif data_msg.portnum == portnums_pb2.PortNum.TELEMETRY_APP:
                # Proper telemetry decoding using protobuf definitions
                try:
                    telemetry = telemetry_pb2.Telemetry()
                    telemetry.ParseFromString(data_msg.payload)
                    
                    # Check which telemetry variant is present
                    variant = telemetry.WhichOneof('variant')
                    
                    if variant == 'device_metrics':
                        device_metrics = telemetry.device_metrics
                        
                        # Battery level (percentage)
                        if hasattr(device_metrics, 'battery_level') and device_metrics.battery_level > 0:
                            interpretation["🔋 Battery"] = f"{device_metrics.battery_level}%"
                        
                        # Voltage
                        if hasattr(device_metrics, 'voltage') and device_metrics.voltage > 0:
                            interpretation["⚡ Voltage"] = f"{device_metrics.voltage:.2f}V"
                        
                        # Channel utilization
                        if hasattr(device_metrics, 'channel_utilization') and device_metrics.channel_utilization > 0:
                            interpretation["📡 Channel Util"] = f"{device_metrics.channel_utilization:.1f}%"
                        
                        # Air utilization TX
                        if hasattr(device_metrics, 'air_util_tx') and device_metrics.air_util_tx > 0:
                            interpretation["📶 Air Util TX"] = f"{device_metrics.air_util_tx:.1f}%"
                        
                        # Uptime
                        if hasattr(device_metrics, 'uptime_seconds') and device_metrics.uptime_seconds > 0:
                            uptime_hours = device_metrics.uptime_seconds / 3600
                            if uptime_hours < 24:
                                interpretation["⏱️ Uptime"] = f"{uptime_hours:.1f} hours"
                            else:
                                uptime_days = uptime_hours / 24
                                interpretation["⏱️ Uptime"] = f"{uptime_days:.1f} days"
                    
                    elif variant == 'environment_metrics':
                        env_metrics = telemetry.environment_metrics
                        
                        # Temperature
                        if hasattr(env_metrics, 'temperature') and env_metrics.temperature != 0:
                            interpretation["🌡️ Temperature"] = f"{env_metrics.temperature:.1f}°C"
                        
                        # Relative humidity
                        if hasattr(env_metrics, 'relative_humidity') and env_metrics.relative_humidity > 0:
                            interpretation["💧 Humidity"] = f"{env_metrics.relative_humidity:.1f}%"
                        
                        # Barometric pressure
                        if hasattr(env_metrics, 'barometric_pressure') and env_metrics.barometric_pressure > 0:
                            interpretation["🌪️ Pressure"] = f"{env_metrics.barometric_pressure:.1f} hPa"
                        
                        # Gas resistance (air quality)
                        if hasattr(env_metrics, 'gas_resistance') and env_metrics.gas_resistance > 0:
                            interpretation["🌬️ Gas Resistance"] = f"{env_metrics.gas_resistance:.0f} Ω"
                        
                        # Voltage (some environmental sensors report this)
                        if hasattr(env_metrics, 'voltage') and env_metrics.voltage > 0:
                            interpretation["⚡ Voltage"] = f"{env_metrics.voltage:.2f}V"
                    
                    elif variant == 'air_quality_metrics':
                        air_metrics = telemetry.air_quality_metrics
                        
                        # PM1.0
                        if hasattr(air_metrics, 'pm10_standard') and air_metrics.pm10_standard > 0:
                            interpretation["🌫️ PM1.0"] = f"{air_metrics.pm10_standard} μg/m³"
                        
                        # PM2.5
                        if hasattr(air_metrics, 'pm25_standard') and air_metrics.pm25_standard > 0:
                            interpretation["🌫️ PM2.5"] = f"{air_metrics.pm25_standard} μg/m³"
                        
                        # PM10
                        if hasattr(air_metrics, 'pm100_standard') and air_metrics.pm100_standard > 0:
                            interpretation["🌫️ PM10"] = f"{air_metrics.pm100_standard} μg/m³"
                    
                    elif variant == 'power_metrics':
                        power_metrics = telemetry.power_metrics
                        
                        # Voltage
                        if hasattr(power_metrics, 'ch1_voltage') and power_metrics.ch1_voltage > 0:
                            interpretation["⚡ CH1 Voltage"] = f"{power_metrics.ch1_voltage:.2f}V"
                        
                        # Current
                        if hasattr(power_metrics, 'ch1_current') and power_metrics.ch1_current > 0:
                            interpretation["🔌 CH1 Current"] = f"{power_metrics.ch1_current:.2f}A"
                        
                        # Additional channels if present
                        if hasattr(power_metrics, 'ch2_voltage') and power_metrics.ch2_voltage > 0:
                            interpretation["⚡ CH2 Voltage"] = f"{power_metrics.ch2_voltage:.2f}V"
                        
                        if hasattr(power_metrics, 'ch2_current') and power_metrics.ch2_current > 0:
                            interpretation["🔌 CH2 Current"] = f"{power_metrics.ch2_current:.2f}A"
                    
                    # Add timestamp if available
                    if hasattr(telemetry, 'time') and telemetry.time > 0:
                        interpretation["🕐 Telemetry Time"] = self.format_timestamp(telemetry.time)
                    
                    # Add size info
                    interpretation["📊 Telemetry Size"] = f"{len(data_msg.payload)} bytes"
                    
                except Exception as e:
                    # Fallback to manual decoding if protobuf parsing fails
                    try:
                        if len(data_msg.payload) >= 4:
                            # Try to extract voltage (common first field)
                            voltage = struct.unpack('<f', data_msg.payload[0:4])[0]
                            if 0 < voltage < 10:  # Reasonable voltage range
                                interpretation["⚡ Voltage"] = f"{voltage:.2f}V"
                                
                        if len(data_msg.payload) >= 8:
                            # Try to extract temperature
                            temp = struct.unpack('<f', data_msg.payload[4:8])[0]
                            if -50 < temp < 100:  # Reasonable temperature range
                                interpretation["🌡️ Temperature"] = f"{temp:.1f}°C"
                                
                        interpretation["📊 Telemetry Size"] = f"{len(data_msg.payload)} bytes"
                        interpretation["⚠️ Parse Status"] = f"Protobuf parsing failed: {e}"
                        
                    except Exception as e2:
                        interpretation["Payload Data"] = f"bytes({len(data_msg.payload)}): {data_msg.payload.hex()[:40]}{'...' if len(data_msg.payload) > 20 else ''}"
                        interpretation["⚠️ Parse Error"] = f"Both protobuf and manual parsing failed"
                    
            elif data_msg.portnum == portnums_pb2.PortNum.ROUTING_APP:
                try:
                    # Try to parse as routing message
                    routing = mesh_pb2.Routing()
                    routing.ParseFromString(data_msg.payload)
                    
                    variant = routing.WhichOneof('variant')
                    if variant == 'route_request':
                        interpretation["🔄 Routing Type"] = "Route Request (Traceroute)"
                    elif variant == 'route_reply':
                        interpretation["🔄 Routing Type"] = "Route Reply (Traceroute Response)"
                    elif variant == 'error_reason':
                        error_names = {
                            0: "NONE (Success/ACK)",
                            1: "NO_ROUTE", 
                            2: "GOT_NAK",
                            3: "TIMEOUT",
                            4: "NO_INTERFACE",
                            5: "MAX_RETRANSMIT",
                            6: "NO_CHANNEL",
                            7: "TOO_LARGE",
                            8: "NO_RESPONSE",
                            9: "DUTY_CYCLE_LIMIT"
                        }
                        error_code = routing.error_reason
                        error_name = error_names.get(error_code, f"UNKNOWN_ERROR_{error_code}")
                        interpretation["🔄 Routing Type"] = f"Status: {error_name}"
                        if error_code == 0:
                            interpretation["✅ Status"] = "Success/ACK"
                    else:
                        # Check if this is just a simple ACK (no variant set)
                        if len(data_msg.payload) <= 4:
                            interpretation["🔄 Routing Message"] = "Simple ACK packet"
                        else:
                            interpretation["🔄 Routing Message"] = "Control message"
                        
                    interpretation["📦 Routing Data"] = f"bytes({len(data_msg.payload)}): {data_msg.payload.hex()}"
                    
                except Exception as e:
                    # This is likely a simple ACK or control message that doesn't parse as Routing protobuf
                    if len(data_msg.payload) <= 4:
                        interpretation["🔄 Routing Message"] = "Simple ACK packet"
                        interpretation["✅ Status"] = "Message acknowledged"
                    else:
                        interpretation["🔄 Routing Message"] = "Control packet"
                    interpretation["📦 Routing Data"] = f"bytes({len(data_msg.payload)}): {data_msg.payload.hex()}"
                    
            else:
                interpretation["Payload Data"] = f"bytes({len(data_msg.payload)}): {data_msg.payload.hex()[:40]}{'...' if len(data_msg.payload) > 20 else ''}"
        
        # Other fields
        if data_msg.want_response:
            interpretation["🔄 Wants Response"] = "Yes"
        
        if data_msg.dest:
            interpretation["🎯 Destination"] = self.format_node_id(data_msg.dest)
        
        if data_msg.source:
            interpretation["📡 Source"] = self.format_node_id(data_msg.source)
        
        if data_msg.request_id:
            interpretation["🆔 Request ID"] = f"0x{data_msg.request_id:08x}"
        
        if data_msg.reply_id:
            interpretation["↩️ Reply ID"] = f"0x{data_msg.reply_id:08x}"
        
        return interpretation
    
    def decode_routing_payload(self, routing_msg):
        """Decode the Routing protobuf message"""
        interpretation = {}
        interpretation["Message Type"] = "ROUTING"
        
        # Check which variant is set
        variant = routing_msg.WhichOneof('variant')
        if variant == 'route_request':
            interpretation["Routing Type"] = "Route Request (Traceroute)"
            route_req = routing_msg.route_request
            if hasattr(route_req, 'route') and route_req.route:
                route_nodes = [self.format_node_id(node) for node in route_req.route]
                interpretation["Route"] = " → ".join(route_nodes)
            if hasattr(route_req, 'snr_towards') and route_req.snr_towards:
                snr_values = [f"{snr/4:.1f}dB" for snr in route_req.snr_towards]  # SNR is scaled by 4
                interpretation["SNR Values"] = " → ".join(snr_values)
                
        elif variant == 'route_reply':
            interpretation["Routing Type"] = "Route Reply (Traceroute Response)"
            route_reply = routing_msg.route_reply
            if hasattr(route_reply, 'route') and route_reply.route:
                route_nodes = [self.format_node_id(node) for node in route_reply.route]
                interpretation["Forward Route"] = " → ".join(route_nodes)
            if hasattr(route_reply, 'route_back') and route_reply.route_back:
                route_back_nodes = [self.format_node_id(node) for node in route_reply.route_back]
                interpretation["Return Route"] = " → ".join(route_back_nodes)
            if hasattr(route_reply, 'snr_towards') and route_reply.snr_towards:
                snr_values = [f"{snr/4:.1f}dB" for snr in route_reply.snr_towards]
                interpretation["Forward SNR"] = " → ".join(snr_values)
            if hasattr(route_reply, 'snr_back') and route_reply.snr_back:
                snr_back_values = [f"{snr/4:.1f}dB" for snr in route_reply.snr_back]
                interpretation["Return SNR"] = " → ".join(snr_back_values)
                
        elif variant == 'error_reason':
            error_names = {
                0: "NONE",
                1: "NO_ROUTE", 
                2: "GOT_NAK",
                3: "TIMEOUT",
                4: "NO_INTERFACE",
                5: "MAX_RETRANSMIT",
                6: "NO_CHANNEL",
                7: "TOO_LARGE",
                8: "NO_RESPONSE",
                9: "DUTY_CYCLE_LIMIT"
            }
            error_name = error_names.get(routing_msg.error_reason, f"UNKNOWN_ERROR_{routing_msg.error_reason}")
            interpretation["Routing Type"] = f"Error: {error_name}"
        else:
            # Handle the case where it might be a RouteDiscovery message (like Android app expects)
            # Try to access route list directly if it's a RouteDiscovery
            if hasattr(routing_msg, 'route') and routing_msg.route:
                interpretation["Routing Type"] = "Route Discovery (Traceroute Response)"
                route_nodes = [self.format_node_id(node) for node in routing_msg.route]
                interpretation["Route Path"] = " → ".join(route_nodes)
                interpretation["Route Details"] = f"Path through {len(route_nodes)} nodes"
        
        return interpretation
    
    def process_packet(self, data, addr, original_timestamp=None):
        """Process a received packet and choose output format based on verbose flag"""
        if self.verbose:
            # Use verbose output (existing detailed format)
            self.print_packet_verbose(data, addr, original_timestamp)
        else:
            # Use simple output - need to decode packet first
            try:
                mesh_packet = mesh_pb2.MeshPacket()
                mesh_packet.ParseFromString(data)
                
                decoded_info = None
                
                # Handle payload decoding
                if mesh_packet.WhichOneof('payload_variant') == 'decoded':
                    data_msg = mesh_packet.decoded
                    decoded_info = self.decode_data_payload(data_msg)
                    
                elif mesh_packet.WhichOneof('payload_variant') == 'encrypted':
                    # Attempt decryption
                    encrypted_data = mesh_packet.encrypted
                    decrypted_data, status, data_msg = self.decrypt_payload(
                        encrypted_data, mesh_packet.id, getattr(mesh_packet, 'from'), mesh_packet.channel)
                    
                    if decrypted_data and data_msg:
                        # Check if it's a Data or Routing message
                        if hasattr(data_msg, 'portnum'):  # It's a Data message
                            decoded_info = self.decode_data_payload(data_msg)
                        else:  # It's a Routing message
                            decoded_info = self.decode_routing_payload(data_msg)
                    else:
                        # Failed to decrypt - show basic info
                        decoded_info = {
                            "Port": "ENCRYPTED",
                            "🔒 Status": "Unable to decrypt"
                        }
                
                # Use simple output format
                self.print_packet_simple(data, addr, mesh_packet, decoded_info, original_timestamp)
                
            except Exception as e:
                # If packet parsing fails completely, fall back to verbose mode for this packet
                print(f"Error parsing packet, showing verbose output: {e}")
                self.print_packet_verbose(data, addr, original_timestamp)
    
    def print_packet_simple(self, data, addr, mesh_packet, decoded_info, original_timestamp=None):
        """Print simplified packet information"""
        if original_timestamp:
            timestamp = datetime.fromtimestamp(original_timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        else:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        with self.stats_lock:
            self.packet_count += 1
            self.total_bytes += len(data)
            packet_num = self.packet_count
        
        print(f"{'='*80}")
        print(f"Packet #{packet_num} - {timestamp}")
        
        # Format the from/to line
        from_node = self.format_node_id(getattr(mesh_packet, 'from'))
        if mesh_packet.to == 0xFFFFFFFF:
            to_node = "Broadcast"
        else:
            to_node = self.format_node_id(mesh_packet.to)
        
        print(f"From: {from_node} → To: {to_node}")
        
        # Channel and hop info
        channel_info = f"Channel: {mesh_packet.channel}"
        if mesh_packet.hop_limit and mesh_packet.hop_start:
            hops_used = mesh_packet.hop_start - mesh_packet.hop_limit
            hops_info = f"Hops: {hops_used} of {mesh_packet.hop_start}"
        elif mesh_packet.hop_limit:
            hops_info = f"Hops: {mesh_packet.hop_limit} remaining"
        else:
            hops_info = ""
        
        # Signal quality
        signal_parts = []
        if mesh_packet.rx_rssi:
            signal_parts.append(self.format_rssi(mesh_packet.rx_rssi))
        if mesh_packet.rx_snr:
            signal_parts.append(f"{mesh_packet.rx_snr:.1f} dB SNR")
        
        signal_info = f"Signal: {', '.join(signal_parts)}" if signal_parts else ""
        
        # Combine channel, hops, and signal info
        info_parts = [part for part in [channel_info, hops_info, signal_info] if part]
        print(" | ".join(info_parts))
        
        # Message content
        if decoded_info:
            port_info = decoded_info.get("Port", "UNKNOWN")
            port_name = port_info.split("(")[0].strip()  # Get just the name part
            
            # Create a more readable port description
            port_descriptions = {
                "TEXT_MESSAGE_APP": "Text Message",
                "NODEINFO_APP": "Node Information Update", 
                "POSITION_APP": "Position Update",
                "TELEMETRY_APP": "Telemetry Data",
                "TRACEROUTE_APP": "Network Traceroute",
                "ROUTING_APP": "Routing Control",
                "ADMIN_APP": "Administration",
                "NEIGHBORINFO_APP": "Neighbor Discovery"
            }
            
            description = port_descriptions.get(port_name, port_name.replace("_", " ").title())
            print(f"\n{port_name}: {description}")
            
            # Show key information based on message type
            for key, value in decoded_info.items():
                if key != "Port":  # Skip the port since we already showed it
                    print(f"  {key}: {value}")
        
        print()  # Empty line for separation
    
    def print_packet_verbose(self, data, addr, original_timestamp=None):
        """Print detailed packet information with proper protobuf decoding"""
        if original_timestamp:
            timestamp = datetime.fromtimestamp(original_timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        else:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        with self.stats_lock:
            self.packet_count += 1
            self.total_bytes += len(data)
            packet_num = self.packet_count
        
        print(f"{'='*80}")
        print(f"Packet #{packet_num} - {timestamp}")
        print(f"Source: {addr[0]}:{addr[1]}")
        print(f"Size: {len(data)} bytes")
        
        # Try to decode as MeshPacket protobuf
        try:
            mesh_packet = mesh_pb2.MeshPacket()
            mesh_packet.ParseFromString(data)
            
            print(f"\nDECODED MESHPACKET:")
            print(f"  From Node: {self.format_node_id(getattr(mesh_packet, 'from'))}")
            
            if mesh_packet.to == 0xFFFFFFFF:
                print(f"  To: Broadcast (all nodes)")
            else:
                print(f"  To: {self.format_node_id(mesh_packet.to)}")
            
            print(f"  Channel Hash: {mesh_packet.channel}")
            print(f"  Packet ID: 0x{mesh_packet.id:08x}")
            
            if mesh_packet.rx_time:
                print(f"  Received Time: {self.format_timestamp(mesh_packet.rx_time)}")
            
            if mesh_packet.rx_snr:
                print(f"  SNR: {self.format_rssi_snr(mesh_packet.rx_snr)}")
            
            if mesh_packet.hop_limit:
                print(f"  Hop Limit: {mesh_packet.hop_limit} hops remaining")
            
            if mesh_packet.want_ack:
                print(f"  Wants ACK: Yes")
            
            if mesh_packet.priority:
                print(f"  Priority: {self.format_priority(mesh_packet.priority)}")
            
            if mesh_packet.rx_rssi:
                print(f"  RSSI: {self.format_rssi(mesh_packet.rx_rssi)}")
            
            if mesh_packet.hop_start:
                print(f"  Started with: {mesh_packet.hop_start} hops")
            
            # Handle payload
            if mesh_packet.WhichOneof('payload_variant') == 'decoded':
                print(f"\n  DECODED PAYLOAD:")
                data_msg = mesh_packet.decoded
                decoded_info = self.decode_data_payload(data_msg)
                for desc, value in decoded_info.items():
                    print(f"    {desc}: {value}")
                    
            elif mesh_packet.WhichOneof('payload_variant') == 'encrypted':
                print(f"\n  ENCRYPTED PAYLOAD:")
                encrypted_data = mesh_packet.encrypted
                print(f"    Size: {len(encrypted_data)} bytes")
                print(f"    Data: {encrypted_data.hex()[:40]}{'...' if len(encrypted_data) > 20 else ''}")
                
                # Attempt decryption
                decrypted_data, status, data_msg = self.decrypt_payload(
                    encrypted_data, mesh_packet.id, getattr(mesh_packet, 'from'), mesh_packet.channel)
                
                print(f"\n  DECRYPTION ATTEMPT:")
                print(f"    Status: {status}")
                
                # Add debugging info for failed decryption
                if not decrypted_data:
                    print(f"    Debug: Packet ID=0x{mesh_packet.id:08x}, From=0x{getattr(mesh_packet, 'from'):08x}")
                    print(f"    Debug: Channel Hash={mesh_packet.channel}, Payload Size={len(encrypted_data)}")
                    print(f"    Debug: First few bytes of encrypted data: {encrypted_data[:8].hex()}")
                
                if decrypted_data and data_msg:
                    print(f"    Decrypted Data ({len(decrypted_data)} bytes):")
                    print(self.format_hex_dump(decrypted_data, 16))
                    
                    print(f"    Decoded Message:")
                    # Check if it's a Data or Routing message
                    if hasattr(data_msg, 'portnum'):  # It's a Data message
                        decoded_info = self.decode_data_payload(data_msg)
                    else:  # It's a Routing message
                        decoded_info = self.decode_routing_payload(data_msg)
                    
                    for desc, value in decoded_info.items():
                        print(f"      {desc}: {value}")
                        
        except Exception as e:
            print(f"\nError parsing MeshPacket: {e}")
            print("Raw packet data:")
            print(self.format_hex_dump(data))
        
        print(f"\nRAW PACKET DATA:")
        print(self.format_hex_dump(data))
        print()
    
    def print_statistics(self):
        """Print monitoring statistics"""
        if self.start_time is None:
            return
            
        elapsed = time.time() - self.start_time
        if elapsed == 0:
            return
            
        with self.stats_lock:
            packets_per_sec = self.packet_count / elapsed
            bytes_per_sec = self.total_bytes / elapsed
            
        print(f"\n{'='*80}")
        print(f"STATISTICS")
        print(f"Runtime: {elapsed:.1f} seconds")
        print(f"Total packets: {self.packet_count}")
        print(f"Total bytes: {self.total_bytes}")
        print(f"Rate: {packets_per_sec:.2f} packets/sec, {bytes_per_sec:.1f} bytes/sec")
        print(f"{'='*80}")
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n\nReceived signal {signum}, shutting down...")
        self.running = False
        if self.sock:
            self.sock.close()
        self.print_statistics()
        sys.exit(0)
    
    def replay_file(self, filename):
        """Replay packets from a single TSV file"""
        print(f"Replaying packets from: {filename}")
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                        
                    try:
                        # Parse TSV format: timestamp<TAB>hex_data
                        parts = line.split('\t')
                        if len(parts) != 2:
                            print(f"Warning: Invalid line format at line {line_num}: {line[:50]}...")
                            continue
                            
                        timestamp_str, hex_data = parts
                        original_timestamp = float(timestamp_str)
                        
                        # Convert hex back to bytes
                        packet_data = bytes.fromhex(hex_data)
                        
                        # Create fake address for replay
                        fake_addr = ('127.0.0.1', 4403)
                        
                        # Process the packet with original timestamp
                        self.process_packet(packet_data, fake_addr, original_timestamp)
                        
                    except ValueError as e:
                        print(f"Warning: Invalid hex data at line {line_num}: {e}")
                        continue
                    except Exception as e:
                        print(f"Warning: Error processing line {line_num}: {e}")
                        continue
                        
        except FileNotFoundError:
            print(f"Error: File not found: {filename}")
        except Exception as e:
            print(f"Error reading file {filename}: {e}")
    
    def replay_directory(self, directory):
        """Replay packets from all TSV files in a directory"""
        print(f"Replaying packets from directory: {directory}")
        
        # Find all .tsv files in the directory
        pattern = os.path.join(directory, "*.tsv")
        tsv_files = sorted(glob.glob(pattern))
        
        if not tsv_files:
            print(f"No .tsv files found in {directory}")
            return
            
        print(f"Found {len(tsv_files)} capture files")
        
        for tsv_file in tsv_files:
            print(f"\n--- Processing {os.path.basename(tsv_file)} ---")
            self.replay_file(tsv_file)
    
    def replay_stdin(self):
        """Replay packets from stdin (for piping)"""
        print("Reading packets from stdin...")
        
        try:
            for line_num, line in enumerate(sys.stdin, 1):
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    # Parse TSV format: timestamp<TAB>hex_data
                    parts = line.split('\t')
                    if len(parts) != 2:
                        print(f"Warning: Invalid line format at line {line_num}: {line[:50]}...")
                        continue
                        
                    timestamp_str, hex_data = parts
                    original_timestamp = float(timestamp_str)
                    
                    # Convert hex back to bytes
                    packet_data = bytes.fromhex(hex_data)
                    
                    # Create fake address for replay
                    fake_addr = ('127.0.0.1', 4403)
                    
                    # Process the packet with original timestamp
                    self.process_packet(packet_data, fake_addr, original_timestamp)
                    
                except ValueError as e:
                    print(f"Warning: Invalid hex data at line {line_num}: {e}")
                    continue
                except Exception as e:
                    print(f"Warning: Error processing line {line_num}: {e}")
                    continue
                    
        except KeyboardInterrupt:
            print("\nReplay interrupted by user")
        except Exception as e:
            print(f"Error reading from stdin: {e}")

    def setup_capture(self):
        """Set up packet capture to file"""
        if not self.capture_dir:
            return
            
        # Create capture directory if it doesn't exist
        os.makedirs(self.capture_dir, exist_ok=True)
        
        # Get current date for filename
        current_date = datetime.now().strftime("%Y-%m-%d")
        self.current_capture_date = current_date
        
        # Open capture file
        capture_filename = os.path.join(self.capture_dir, f"{current_date}.tsv")
        self.capture_file = open(capture_filename, 'a', encoding='utf-8')
        
        print(f"Capturing packets to: {capture_filename}")
    
    def capture_packet(self, data):
        """Capture packet to file in TSV format"""
        if not self.capture_file:
            return
            
        # Check if date has changed (for daily rotation)
        current_date = datetime.now().strftime("%Y-%m-%d")
        if current_date != self.current_capture_date:
            # Close current file and open new one
            self.capture_file.close()
            self.current_capture_date = current_date
            capture_filename = os.path.join(self.capture_dir, f"{current_date}.tsv")
            self.capture_file = open(capture_filename, 'a', encoding='utf-8')
            print(f"Rotated capture to: {capture_filename}")
        
        # Write timestamp and hex data
        timestamp = time.time()
        hex_data = data.hex()
        self.capture_file.write(f"{timestamp}\t{hex_data}\n")
        self.capture_file.flush()  # Ensure data is written immediately

    def start_monitoring(self):
        """Start monitoring UDP packets"""
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Set up capture if requested
        if self.capture_dir:
            self.setup_capture()
        
        if not self.setup_socket():
            return
        
        self.running = True
        self.start_time = time.time()
        
        try:
            while self.running:
                try:
                    # Receive packet (with timeout to allow checking self.running)
                    self.sock.settimeout(1.0)
                    data, addr = self.sock.recvfrom(4096)
                    
                    if data:
                        # Capture packet if requested
                        if self.capture_file:
                            self.capture_packet(data)
                        
                        # Process packet for display
                        self.process_packet(data, addr)
                        
                except socket.timeout:
                    # Timeout is expected, just continue
                    continue
                except Exception as e:
                    if self.running:  # Only print error if we're still supposed to be running
                        print(f"Error receiving packet: {e}")
                    break
                    
        except KeyboardInterrupt:
            pass
        finally:
            if self.sock:
                self.sock.close()
            if self.capture_file:
                self.capture_file.close()
                print(f"Capture file closed")
            self.print_statistics()
