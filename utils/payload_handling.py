import yaml
import asyncio
from typing import Dict, Any, Tuple, Optional, List, Set
from utils.block_action import BlockAction
from utils.delay_action import DelayAction
from utils.replay_action import ReplayAction

class PayloadHandler:
    def __init__(self, config_path: str = "config/config.yaml"):
        self.config = self.load_config(config_path)
        self.delay_rules, self.block_rules, self.replay_rules = self.parse_rules()
        self.block_action = BlockAction(self.block_rules)
        self.delay_action = DelayAction(self.delay_rules)
        self.replay_action = ReplayAction(self.replay_rules)

    def load_config(self, config_path: str):
        with open(config_path, "r") as f:
            return yaml.safe_load(f)

    def parse_rules(self) -> Tuple[Dict[str, int], Set[str], Dict[str, int]]:
        """
        Parse rules from the config file.

        Returns:
            Tuple containing:
            - Dictionary mapping actions to delay times in milliseconds
            - Set of actions that should be blocked
            - Dictionary mapping actions to replay counts
        """
        payload_handling = self.config.get("payload_handling", {})

        # Parse delay rules
        delay_rules = {}
        delay_config = payload_handling.get("delay", {})
        if delay_config:
            action = delay_config.get("action")
            delay_ms = delay_config.get("delay_ms", 0)
            if action and delay_ms > 0:
                delay_rules[action] = delay_ms

        # Parse block rules
        block_rules = set()
        block_config = payload_handling.get("block", {})
        if block_config:
            action = block_config.get("action")
            if action:
                block_rules.add(action)

        # Parse replay rules
        replay_rules = {}
        replay_config = payload_handling.get("replay", {})
        if replay_config:
            action = replay_config.get("action")
            count = replay_config.get("count", 0)
            if action and count > 0:
                replay_rules[action] = count

        return delay_rules, block_rules, replay_rules

    async def process_message(self, message: Any) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Process a message according to the rules.

        Args:
            message: The decoded message

        Returns:
            Tuple containing:
            - True if the message should be forwarded, False if it should be blocked
            - List of replayed messages (empty if no replay rule matches)
        """
        if not isinstance(message, dict):
            return True, []  # Forward non-dictionary messages, no replay

        # Check if message should be blocked
        if self.block_action.should_block(message):
            print(f"[BLOCK] Blocking message with action: {message.get('action')}")
            return False, []

        # Apply delay if needed
        was_delayed = await self.delay_action.delay_if_needed(message)
        if was_delayed:
            print(f"[DELAY] Delayed message with action: {message.get('action')}")

        # Check if message should be replayed
        replayed_messages = []
        if self.replay_action.should_replay(message):
            replayed_messages = self.replay_action.get_replayed_messages(message)
            print(f"[REPLAY] Replaying message with action: {message.get('action')} ({len(replayed_messages)} times)")

        return True, replayed_messages  # Forward the message with any replays
