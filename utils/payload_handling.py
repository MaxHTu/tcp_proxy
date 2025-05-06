import yaml
import asyncio
from typing import Dict, Any, Tuple, Optional, List, Set
from utils.delay_action import DelayAction
from utils.block_action import BlockAction

class PayloadHandler:
    def __init__(self, config_path: str = "config/config.yaml"):
        self.config = self.load_config(config_path)
        self.delay, self.block = self.parse_rules()
        self.delay_action = DelayAction(self.delay)
        self.block_action = BlockAction(self.block)


    def load_config(self, config_path: str):
        with open(config_path, "r") as f:
            return yaml.safe_load(f)

    def parse_rules(self) -> Tuple[Dict[str, int], Set[str]]:
        payload_handling = self.config["payload_handling"]

        delay_rules = {}
        for rule in payload_handling.get("delay", []):
            if isinstance(rule, dict) and "action" in rule and "delay_ms" in rule:
                action = rule["action"]
                delay_ms = rule.get("delay_ms", 0)
                if delay_ms > 0:
                    delay_rules[action] = delay_ms
                else:
                    print(f"[!] Warning: Delay rule for action '{action}' has non‑positive delay_ms. Ignoring.")

        block_rules = set()
        for rule in payload_handling.get("block", []):
            if isinstance(rule, dict) and "action" in rule:
                block_rules.add(rule["action"])

        return delay_rules, block_rules

    async def process_messages(self, message:Any):
        if not isinstance(message, dict):
            return True, []

        if self.block_action.should_block(message):
            print(f"[BLOCK] Blocking message with action: {message.get('action')}")
            return False, []

        delayed = await self.delay_action.should_delay(message)
        if delayed:
            print(f"[DELAY] Delayed message with action: {message.get('action')}")

        return True, []
