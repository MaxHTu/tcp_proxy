import yaml
import asyncio
import time # Added
from typing import Dict, Any, Tuple, Optional, List, Set
from utils.delay_action import DelayAction
from utils.block_action import BlockAction
from utils.insert_data_action import InsertDataAction # Added

class PayloadHandler:
    def __init__(self, config_path: str = "config/config.yaml", proxy_start_time: Optional[float] = None): # Modified
        self.config = self.load_config(config_path)
        self.proxy_start_time = proxy_start_time if proxy_start_time is not None else time.time() # Added
        self.global_rules = self.parse_global_rules()
        self.direction_rules = self.parse_direction_rules()
        self.global_delay_action = DelayAction(self.global_rules.get("delay", {})) # Modified (get with default)
        self.global_block_action = BlockAction(self.global_rules.get("block", set())) # Modified (get with default)
        self.global_insert_data_action = InsertDataAction(self.global_rules.get("insert_data", []), self.proxy_start_time) # Added

    def load_config(self, config_path: str):
        with open(config_path, "r") as f:
            return yaml.safe_load(f)

    def parse_global_rules(self) -> Dict[str, Any]:
        payload_handling = self.config.get("payload_handling", {}) # get with default
        global_rules_config = payload_handling.get("global", {})

        delay_rules = {}
        for rule in global_rules_config.get("delay", []):
            if isinstance(rule, dict) and "action" in rule and "delay_ms" in rule:
                action = rule["action"]
                delay_ms = rule.get("delay_ms", 0)
                if delay_ms is not None and delay_ms > 0:
                    delay_rules[action] = delay_ms
                else:
                    print(f"[!] Warning: Global delay rule for action '{action}' has non‑positive delay_ms. Ignoring.")

        block_rules = set()
        for rule in global_rules_config.get("block", []):
            if isinstance(rule, dict) and "action" in rule:
                block_rules.add(rule["action"])
        
        insert_data_rules = [] # Added
        for rule in global_rules_config.get("insert_data", []): # Added
            if isinstance(rule, dict) and "action" in rule and "data" in rule: # Added
                insert_data_rules.append({ # Added
                    "action": rule["action"], # Added
                    "data": rule["data"], # Added
                    "data_type": rule.get("data_type", "bytes"), # Added
                    "position": rule.get("position", "before"), # Added
                    "delay_sec": rule.get("delay_sec", 0) # Added
                }) # Added
            else: # Added
                print(f"[!] Warning: Global insert_data rule missing 'action' or 'data'. Rule: {rule}. Ignoring.") # Added


        return {"delay": delay_rules, "block": block_rules, "insert_data": insert_data_rules} # Modified

    def parse_direction_rules(self) -> Dict[str, Dict[str, Any]]:
        payload_handling = self.config.get("payload_handling", {}) # get with default
        direction_rules_output = {}
        
        for direction_name, direction_config in payload_handling.get("directions", {}).items():
            delay_rules = {}
            for rule in direction_config.get("delay", []):
                if isinstance(rule, dict) and "action" in rule and "delay_ms" in rule:
                    action = rule["action"]
                    delay_ms = rule.get("delay_ms", 0)
                    if delay_ms is not None and delay_ms > 0:
                        delay_rules[action] = delay_ms
                    else:
                        print(f"[!] Warning: Direction '{direction_name}' delay rule for action '{action}' has non‑positive delay_ms. Ignoring.")

            block_rules = set()
            for rule in direction_config.get("block", []):
                if isinstance(rule, dict) and "action" in rule:
                    block_rules.add(rule["action"])
            
            insert_data_rules = [] # Added
            for rule in direction_config.get("insert_data", []): # Added
                if isinstance(rule, dict) and "action" in rule and "data" in rule: # Added
                    insert_data_rules.append({ # Added
                        "action": rule["action"], # Added
                        "data": rule["data"], # Added
                        "data_type": rule.get("data_type", "bytes"), # Added
                        "position": rule.get("position", "before"), # Added
                        "delay_sec": rule.get("delay_sec", 0) # Added
                    }) # Added
                else: # Added
                    print(f"[!] Warning: Direction '{direction_name}' insert_data rule missing 'action' or 'data'. Rule: {rule}. Ignoring.") # Added

            direction_rules_output[direction_name] = {
                "source_ip": direction_config.get("source_ip"),
                "target_ip": direction_config.get("target_ip"),
                "delay": delay_rules,
                "block": block_rules,
                "insert_data": insert_data_rules # Added
            }

        return direction_rules_output

    def get_matching_direction(self, source_ip: str, target_ip: str) -> Optional[str]:
        for direction_name, direction_config in self.direction_rules.items():
            if (direction_config.get("source_ip") == source_ip and  # get with default
                direction_config.get("target_ip") == target_ip): # get with default
                return direction_name
        return None

    async def process_messages(self, message: Any, source_ip: str, target_ip: str) -> Tuple[bool, Optional[Tuple[bytes, str]], List[Any]]: # Modified
        data_to_insert: Optional[Tuple[bytes, str]] = None # Added
        replayed_messages: List[Any] = [] # Assuming this is still needed, though not used in provided logic

        if not isinstance(message, dict):
            return True, None, replayed_messages

        # Check global block rules first
        if self.global_block_action.should_block(message):
            print(f"[BLOCK] Blocking message with action: {message.get('action')} (global rule)")
            return False, None, replayed_messages

        # Check direction-specific block rules
        direction = self.get_matching_direction(source_ip, target_ip)
        if direction:
            direction_config = self.direction_rules[direction]
            block_action = BlockAction(direction_config.get("block", set())) # get with default
            if block_action.should_block(message):
                print(f"[BLOCK] Blocking message with action: {message.get('action')} (direction: {direction})")
                return False, None, replayed_messages

        # Check global delay rules
        delayed = await self.global_delay_action.should_delay(message)
        if delayed:
            print(f"[DELAY] Delayed message with action: {message.get('action')} (global rule)")

        # Check direction-specific delay rules
        if direction:
            direction_config = self.direction_rules[direction]
            delay_action = DelayAction(direction_config.get("delay", {})) # get with default
            delayed = await delay_action.should_delay(message)
            if delayed:
                print(f"[DELAY] Delayed message with action: {message.get('action')} (direction: {direction})")
        
        # Check global insert_data rules
        global_insert_result = self.global_insert_data_action.get_data_to_insert(message, time.time()) # Added
        if global_insert_result: # Added
            data_to_insert = global_insert_result # Added

        # Check direction-specific insert_data rules if no global match
        if direction and data_to_insert is None: # Added
            direction_config = self.direction_rules[direction] # Added
            direction_insert_rules = direction_config.get("insert_data", []) # Added
            if direction_insert_rules: # Added - only create if rules exist
                direction_insert_action = InsertDataAction(direction_insert_rules, self.proxy_start_time) # Added
                direction_insert_result = direction_insert_action.get_data_to_insert(message, time.time()) # Added
                if direction_insert_result: # Added
                    data_to_insert = direction_insert_result # Added
        
        return True, data_to_insert, replayed_messages # Modified
