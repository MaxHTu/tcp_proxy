from typing import Set, Dict, Any

class BlockAction:
    """
    Class responsible for checking if a message should be blocked based on its action.
    """
    
    def __init__(self, block_rules: Set[str]):
        """
        Initialize with a set of actions that should be blocked.
        
        Args:
            block_rules: Set of action names that should be blocked
        """
        self.block_rules = block_rules
    
    def should_block(self, message: Dict[str, Any]) -> bool:
        """
        Check if a message should be blocked based on its action.
        
        Args:
            message: The decoded message dictionary
            
        Returns:
            True if the message should be blocked, False otherwise
        """
        if not isinstance(message, dict):
            return False
            
        action = message.get("action")
        if not action:
            return False
            
        return action in self.block_rules