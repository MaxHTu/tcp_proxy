import asyncio
from typing import Dict, Any, Optional

class DelayAction:

    def __init__(self, delay_rules: Dict[str, int]):
        self.delay_rules = delay_rules

    def get_delay(self, message:Dict[str, Any]) -> Optional[int]:
        if not isinstance(message, dict):
            return None

        action = message.get('action')
        if action is None:
            return None

        return self.delay_rules.get(action)

    async def should_delay(self, message: Dict[str, Any]) -> bool:
        delay_ms = self.get_delay(message)
        if delay_ms is not None:
            await asyncio.sleep(delay_ms / 1000.0)
            return True
        return False
