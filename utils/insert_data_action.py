import time
import binascii
from typing import List, Dict, Any, Optional, Tuple

class InsertDataAction:
    def __init__(self, insert_data_rules: List[Dict[str, Any]], proxy_start_time: float):
        self.rules = insert_data_rules if insert_data_rules else []
        self.proxy_start_time = proxy_start_time

    def get_data_to_insert(self, message: Dict[str, Any], current_time: float) -> Optional[Tuple[bytes, str]]:
        '''
        Checks if the message matches any insert_data rule and if the rule is active.
        Returns a tuple of (data_to_insert, position) or None.
        '''
        if not isinstance(message, dict):
            return None

        action = message.get('action')
        if action is None:
            return None

        for rule in self.rules:
            if rule.get('action') == action:
                # Check time delay
                delay_sec = rule.get('delay_sec', 0)
                if current_time < self.proxy_start_time + delay_sec:
                    # Rule is not active yet
                    continue

                data_str = rule.get('data')
                data_type = rule.get('data_type', 'bytes').lower()
                position = rule.get('position', 'before').lower()

                if not data_str:
                    continue

                processed_data: bytes
                if data_type == 'hex':
                    try:
                        processed_data = binascii.unhexlify(data_str)
                    except binascii.Error as e:
                        print(f"[!] Error unhexlifying data for action '{action}': {e}")
                        continue # Skip this rule if data is malformed
                elif data_type == 'bytes':
                    processed_data = data_str.encode('utf-8') # Assuming utf-8 for byte strings
                else:
                    print(f"[!] Unknown data_type '{data_type}' for action '{action}'. Skipping.")
                    continue

                if position not in ['before', 'after']:
                    print(f"[!] Unknown position '{position}' for action '{action}'. Defaulting to 'before'.")
                    position = 'before'
                
                print(f"[*] Matched insert_data rule for action: {action}, data: {processed_data!r}, position: {position}, delay_sec: {delay_sec}")
                return processed_data, position
        
        return None
