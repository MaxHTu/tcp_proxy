import asyncio
from typing import Dict, Any, List, Tuple, Optional
from collections import defaultdict
import time

class ReplayAction:
    
    def __init__(self, replay_rules: List[Dict[str, Any]]):
        self.replay_rules = replay_rules
        self.active_replays = defaultdict(list)
        self.replay_counters = defaultdict(int)
        self.blocking_sessions = defaultdict(dict)
        
    def parse_replay_rules(self) -> Dict[str, Dict[str, Any]]:
        parsed_rules = {}
        
        for rule in self.replay_rules:
            if not isinstance(rule, dict):
                continue
                
            action = rule.get('action')
            if not action:
                continue
                
            parsed_rules[action] = {
                'count': rule.get('count', 1),
                'block_original': rule.get('block_original', False),
                'delay_ms': rule.get('delay_ms', 0) if not rule.get('block_original', False) else 0,
                'data': rule.get('data'),
                'position': rule.get('position', 'after')
            }
            
        return parsed_rules
    
    def should_replay(self, message: Dict[str, Any]) -> bool:
        if not isinstance(message, dict):
            return False
            
        action = message.get('action')
        if not action:
            return False
            
        parsed_rules = self.parse_replay_rules()
        rule = parsed_rules.get(action)
        
        if not rule:
            return False
            
        if rule['block_original']:
            return False
        else:
            if action not in self.active_replays:
                return True
            
        return False
    
    def should_block_original(self, message: Dict[str, Any]) -> bool:
        if not isinstance(message, dict):
            return False
            
        action = message.get('action')
        if not action:
            return False
            
        if action in self.blocking_sessions:
            blocking_session = self.blocking_sessions[action]
            if blocking_session['blocks_remaining'] > 0:
                blocking_session['blocks_remaining'] -= 1
                
                replay_executed = self._execute_single_blocking_replay(action)
                
                if replay_executed:
                    print(f"[REPLAY] Blocking {action} call ({blocking_session['blocks_remaining']} blocks remaining, {blocking_session['replay_count']} replays remaining)")
                else:
                    print(f"[REPLAY] Blocking {action} call ({blocking_session['blocks_remaining']} blocks remaining, {blocking_session['replay_count']} replays remaining)")
                
                if blocking_session['blocks_remaining'] == 0 or blocking_session['replay_count'] == 0:
                    self._complete_blocking_session(action)
                
                return True
        
        return False
    
    def start_replay(self, action: str, original_message: Dict[str, Any]) -> None:
        parsed_rules = self.parse_replay_rules()
        rule = parsed_rules.get(action)
        
        if not rule:
            return
            
        replay_session = {
            'action': action,
            'original_message': original_message.copy(),
            'remaining_count': rule['count'],
            'delay_ms': rule['delay_ms'],
            'data': rule['data'],
            'position': rule['position'],
            'start_time': time.time(),
            'last_replay_time': 0
        }
        
        self.active_replays[action].append(replay_session)
        
        if rule['block_original']:
            self.blocking_sessions[action] = {
                'blocks_remaining': rule['count'],
                'replay_count': rule['count'],
                'start_time': time.time()
            }
            print(f"[REPLAY] Started blocking session for action '{action}' - will block next {rule['count']} calls and replay {rule['count']} times")
        else:
            print(f"[REPLAY] Started replay session for action '{action}' - {rule['count']} replays remaining")
    
    def get_replay_insertions(self, message: Dict[str, Any]) -> List[Tuple[bytes, str, str]]:
        if not isinstance(message, dict):
            return []
            
        action = message.get('action')
        if not action or action not in self.active_replays:
            return []
            
        insertions = []
        current_time = time.time()
        
        sessions_to_remove = []
        
        for session in self.active_replays[action]:
            if action in self.blocking_sessions:
                continue
                
            if session['delay_ms'] > 0:
                if (current_time - session['last_replay_time']) * 1000 < session['delay_ms']:
                    continue
                
            replay_data = self._create_replay_data(session, message)
            if replay_data:
                insertions.append((replay_data, session['position'], f"replay_{action}"))
                session['remaining_count'] -= 1
                session['last_replay_time'] = current_time
                
                print(f"[REPLAY] Executed replay for action '{action}' - {session['remaining_count']} remaining")
                
                if session['remaining_count'] <= 0:
                    sessions_to_remove.append(session)
        
        for session in sessions_to_remove:
            self.active_replays[action].remove(session)
            self.replay_counters[action] += 1
            
        if not self.active_replays[action]:
            del self.active_replays[action]
            print(f"[REPLAY] Completed replay session for action '{action}' - Total replays: {self.replay_counters[action]}")
            
        return insertions
    
    def _execute_single_blocking_replay(self, action: str) -> bool:
        if action not in self.blocking_sessions:
            return False
            
        blocking_session = self.blocking_sessions[action]
        if blocking_session['replay_count'] <= 0:
            return False
        
        blocking_session['replay_count'] -= 1
        
        if action in self.active_replays and self.active_replays[action]:
            original_message = self.active_replays[action][0]['original_message']
            
            replay_data = self._create_replay_data(self.active_replays[action][0], original_message)
            if replay_data:
                print(f"[REPLAY] Executed blocking replay for {action} ({blocking_session['replay_count']} replays remaining)")
                self.replay_counters[action] += 1
                return True
        
        return False
    
    def _complete_blocking_session(self, action: str) -> None:
        if action not in self.blocking_sessions:
            return
            
        blocking_session = self.blocking_sessions[action]
        
        if blocking_session['blocks_remaining'] == 0:
            print(f"[REPLAY] Completed blocking session for action '{action}' - all blocks consumed")
        elif blocking_session['replay_count'] == 0:
            print(f"[REPLAY] Completed blocking session for action '{action}' - all replays executed")
        
        del self.blocking_sessions[action]
        
        if action in self.active_replays:
            del self.active_replays[action]
    
    def _execute_blocking_replays(self, action: str) -> None:
        if action not in self.blocking_sessions:
            return
            
        blocking_session = self.blocking_sessions[action]
        replay_count = blocking_session['replay_count']
        
        print(f"[REPLAY] Executing {replay_count} replays for {action} after blocking {replay_count} calls")
        
        if action in self.active_replays and self.active_replays[action]:
            original_message = self.active_replays[action][0]['original_message']
            
            replay_data = self._create_replay_data(self.active_replays[action][0], original_message)
            if replay_data:
                for i in range(replay_count):
                    print(f"[REPLAY] Executed blocking replay {i+1}/{replay_count} for {action}")
                    self.replay_counters[action] += 1
        
        del self.blocking_sessions[action]
        
        if action in self.active_replays:
            del self.active_replays[action]
            print(f"[REPLAY] Completed blocking session for action '{action}'")
    
    def _create_replay_data(self, session: Dict[str, Any], original_message: Dict[str, Any]) -> Optional[bytes]:
        if session['data']:
            if isinstance(session['data'], str):
                return session['data'].encode('utf-8')
            elif isinstance(session['data'], bytes):
                return session['data']
            else:
                return str(session['data']).encode('utf-8')
        else:
            original_data = original_message.get('data')
            if original_data:
                if isinstance(original_data, str):
                    return original_data.encode('utf-8')
                elif isinstance(original_data, bytes):
                    return original_data
                else:
                    return str(original_data).encode('utf-8')
        
        return None
    
    def get_active_replay_count(self, action: str) -> int:
        if action not in self.active_replays:
            return 0
        return len(self.active_replays[action])
    
    def get_total_replay_count(self, action: str) -> int:
        return self.replay_counters.get(action, 0)
    
    def clear_replays(self, action: str = None) -> None:
        if action is None:
            self.active_replays.clear()
            self.replay_counters.clear()
            self.blocking_sessions.clear()
            print("[REPLAY] Cleared all replay sessions and blocking sessions")
        else:
            if action in self.active_replays:
                del self.active_replays[action]
                print(f"[REPLAY] Cleared replay sessions for action '{action}'")
            if action in self.blocking_sessions:
                del self.blocking_sessions[action]
                print(f"[REPLAY] Cleared blocking sessions for action '{action}'")
    
    def get_replay_status(self) -> Dict[str, Any]:
        status = {
            'active_replays': {},
            'total_replays': dict(self.replay_counters),
            'total_active_sessions': sum(len(sessions) for sessions in self.active_replays.values()),
            'blocking_sessions': {}
        }
        
        for action, sessions in self.active_replays.items():
            status['active_replays'][action] = [
                {
                    'remaining_count': session['remaining_count'],
                    'delay_ms': session['delay_ms'],
                    'start_time': session['start_time'],
                    'last_replay_time': session['last_replay_time']
                }
                for session in sessions
            ]
        
        for action, blocking_session in self.blocking_sessions.items():
            status['blocking_sessions'][action] = {
                'blocks_remaining': blocking_session['blocks_remaining'],
                'replay_count': blocking_session['replay_count'],
                'start_time': blocking_session['start_time']
            }
            
        return status
