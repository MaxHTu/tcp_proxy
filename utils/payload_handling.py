import yaml
import asyncio
from typing import Dict, Any, Tuple, Optional, List, Set
from utils.delay_action import DelayAction
from utils.block_action import BlockAction
from utils.insert_action import InsertAction

class PayloadHandler:
    def __init__(self, config_path: str = "config/config.yaml"):
        self.config = self.load_config(config_path)
        self.global_rules = self.parse_global_rules()
        self.direction_rules = self.parse_direction_rules()
        self.global_delay_action = DelayAction(self.global_rules["delay"])
        self.global_block_action = BlockAction(self.global_rules["block"])
        self.global_insert_action = InsertAction(self.global_rules["insert"])
        self.attack_mode = self.parse_attack_mode()

    def load_config(self, config_path: str):
        with open(config_path, "r") as f:
            return yaml.safe_load(f)

    def parse_global_rules(self) -> Dict[str, Any]:
        payload_handling = self.config["payload_handling"]
        global_rules = payload_handling.get("global", {})

        delay_rules = {}
        for rule in global_rules.get("delay", []):
            if isinstance(rule, dict) and "action" in rule and "delay_ms" in rule:
                action = rule["action"]
                delay_ms = rule.get("delay_ms", 0)
                # Robustly handle None, empty string, missing, or invalid delay_ms
                try:
                    if delay_ms is None or delay_ms == "":
                        delay_ms = 0
                    else:
                        delay_ms = int(delay_ms)
                except (ValueError, TypeError):
                    delay_ms = 0
                if delay_ms > 0:
                    delay_rules[action] = delay_ms
                else:
                    print(f"[!] Warning: Delay rule for action '{action}' has non-positive or invalid delay_ms ({delay_ms}). Ignoring.")

        block_rules = set()
        for rule in global_rules.get("block", []):
            if isinstance(rule, dict) and "action" in rule:
                block_rules.add(rule["action"])

        insert_rules = []
        for rule in global_rules.get("insert", []):
            if isinstance(rule, dict) and "action" in rule and "data" in rule:
                insert_rules.append(rule)

        return {
            "delay": delay_rules,
            "block": block_rules,
            "insert": insert_rules
        }

    def parse_direction_rules(self) -> Dict[str, Dict[str, Any]]:
        payload_handling = self.config["payload_handling"]
        direction_rules = {}
        
        for direction_name, direction_config in payload_handling.get("directions", {}).items():
            delay_rules = {}
            for rule in direction_config.get("delay", []):
                if isinstance(rule, dict) and "action" in rule and "delay_ms" in rule:
                    action = rule["action"]
                    delay_ms = rule.get("delay_ms", 0)
                    # Robustly handle None, empty string, missing, or invalid delay_ms
                    try:
                        if delay_ms is None or delay_ms == "":
                            delay_ms = 0
                        else:
                            delay_ms = int(delay_ms)
                    except (ValueError, TypeError):
                        delay_ms = 0
                    if delay_ms > 0:
                        delay_rules[action] = delay_ms
                    else:
                        print(f"[!] Warning: Direction '{direction_name}' delay rule for action '{action}' has non-positive or invalid delay_ms ({delay_ms}). Ignoring.")

            block_rules = set()
            for rule in direction_config.get("block", []):
                if isinstance(rule, dict) and "action" in rule:
                    block_rules.add(rule["action"])

            insert_rules = []
            for rule in direction_config.get("insert", []):
                if isinstance(rule, dict) and "action" in rule and "data" in rule:
                    insert_rules.append(rule)

            direction_rules[direction_name] = {
                "source_ip": direction_config.get("source_ip"),
                "target_ip": direction_config.get("target_ip"),
                "delay": delay_rules,
                "block": block_rules,
                "insert": insert_rules
            }

        return direction_rules

    def parse_attack_mode(self) -> Dict[str, Dict[str, Any]]:
        attack_mode = self.config.get("attack_mode", {})
        parsed = {}
        for direction, settings in attack_mode.items():
            parsed[direction] = {
                "enabled": settings.get("enabled", False),
                "malicious_pickle_payload": settings.get("malicious_pickle_payload", ""),
                "log": settings.get("log", False)
            }
        return parsed

    def is_attack_mode_enabled(self, direction: str) -> bool:
        return self.attack_mode.get(direction, {}).get("enabled", False)

    def get_attack_payload(self, direction: str) -> str:
        return self.attack_mode.get(direction, {}).get("malicious_pickle_payload", "")

    def should_log_attack(self, direction: str) -> bool:
        return self.attack_mode.get(direction, {}).get("log", False)

    def get_matching_direction(self, source_ip: str, target_ip: str) -> Optional[str]:
        for direction_name, direction_config in self.direction_rules.items():
            if (direction_config["source_ip"] == source_ip and 
                direction_config["target_ip"] == target_ip):
                return direction_name
        return None

    async def process_messages(self, message: Any, source_ip: str, target_ip: str) -> Tuple[bool, List[Any]]:
        if not isinstance(message, dict):
            return True, []

        if self.global_block_action.should_block(message):
            print(f"[BLOCK] Blocking message with action: {message.get('action')} (global rule)")
            return False, []

        direction = self.get_matching_direction(source_ip, target_ip)
        if direction:
            direction_config = self.direction_rules[direction]
            block_action = BlockAction(direction_config["block"])
            if block_action.should_block(message):
                print(f"[BLOCK] Blocking message with action: {message.get('action')} (direction: {direction})")
                return False, []

        delayed = await self.global_delay_action.should_delay(message)
        if delayed:
            print(f"[DELAY] Delayed message with action: {message.get('action')} (global rule)")

        if direction:
            direction_config = self.direction_rules[direction]
            delay_action = DelayAction(direction_config["delay"])
            delayed = await delay_action.should_delay(message)
            if delayed:
                print(f"[DELAY] Delayed message with action: {message.get('action')} (direction: {direction})")

        insertions = []
        
        global_insertions = await self.global_insert_action.get_insertions(message)
        insertions.extend(global_insertions)
        
        if direction:
            direction_config = self.direction_rules[direction]
            insert_action = InsertAction(direction_config["insert"])
            direction_insertions = await insert_action.get_insertions(message)
            insertions.extend(direction_insertions)

        return True, insertions
