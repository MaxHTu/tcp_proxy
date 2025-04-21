import asyncio
from typing import Dict, Any, Optional

class DelayAction:
    """
    Class responsible for checking if a message should be delayed based on its action.
    """
    
    def __init__(self, delay_rules: Dict[str, int]):
        """
        Initialize with a dictionary mapping actions to delay times.
        
        Args:
            delay_rules: Dictionary mapping action names to delay times in milliseconds
        """
        self.delay_rules = delay_rules
    
    def get_delay(self, message: Dict[str, Any]) -> Optional[int]:
        """
        Get the delay time for a message based on its action.
        
        Args:
            message: The decoded message dictionary
            
        Returns:
            Delay time in milliseconds if the message should be delayed, None otherwise
        """
        if not isinstance(message, dict):
            return None
            
        action = message.get("action")
        if not action:
            return None
            
        return self.delay_rules.get(action)
    
    async def delay_if_needed(self, message: Dict[str, Any]) -> bool:
        """
        Delay processing if the message matches a delay rule.
        
        Args:
            message: The decoded message dictionary
            
        Returns:
            True if the message was delayed, False otherwise
        """
        delay_ms = self.get_delay(message)
        if delay_ms is not None:
            await asyncio.sleep(delay_ms / 1000.0)  # Convert ms to seconds
            return True
        return False