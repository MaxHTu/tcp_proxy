from typing import Set, Dict, Any

class BlockAction:

    def __init__(self, block_rules: Set[str]):
        self.block_rules = block_rules

    def should_block(self, message:Dict[str, Any]) -> bool:
        if not isinstance(message, dict):
            return False

        action = message.get('action')
        if action is None:
            return False

        return action in self.block_rules