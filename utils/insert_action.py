import asyncio
from typing import List, Tuple, Any, Dict

class InsertAction:
    def __init__(self, insert_rules: List[Dict[str, Any]]):
        self.insert_rules = insert_rules
        self.processed_actions = {}

    async def get_insertions(self, message: Any) -> List[Tuple[bytes, str, int]]:
        insertions = []
        
        for rule in self.insert_rules:
            if not isinstance(rule, dict):
                continue
                
            action = rule.get("action")
            if not action or (isinstance(message, dict) and message.get("action") != action):
                continue
                
            position = rule.get("position", "before")
            if position not in ["before", "after"]:
                continue
                
            data = rule.get("data", "")
            if not data:
                continue
                
            try:
                hex_data = bytes.fromhex(data)
            except ValueError:
                print(f"[!] Warning: Invalid hex data '{data}' in insert rule")
                continue
                
            repeat = rule.get("repeat", 1)
            
            if repeat is False:
                if action in self.processed_actions:
                    continue
                repeat = 1
            elif repeat is True:
                repeat = 1
            elif not isinstance(repeat, int) or repeat < 1:
                print(f"[!] Warning: Invalid repeat value '{repeat}' for action '{action}'. Using 1.")
                repeat = 1
                
            if action not in self.processed_actions:
                self.processed_actions[action] = 0
            self.processed_actions[action] += 1
                
            delay_ms = rule.get("delay_ms", 0)
            if not isinstance(delay_ms, (int, float)) or delay_ms < 0:
                delay_ms = 0
                
            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)
                
            for _ in range(repeat):
                insertions.append((hex_data, position, delay_ms))
                
        return insertions 