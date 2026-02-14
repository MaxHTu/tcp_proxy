from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from utils.contracts import Insertion


@dataclass
class ReplayRule:
    action: str
    count: int
    block_original: bool
    delay_ms: int
    data: Any
    position: str


@dataclass
class ReplaySession:
    session_id: int
    action: str
    original_message: Dict[str, Any]
    remaining_count: int
    block_remaining: int
    block_original: bool
    delay_ms: int
    data: Any
    position: str
    next_emit_at: float
    emitted_count: int = 0


class ReplayAction:
    def __init__(self, replay_rules: List[Dict[str, Any]]):
        self.rules = self._parse_replay_rules(replay_rules)
        self.sessions: Dict[str, ReplaySession] = {}
        self.replay_counters = defaultdict(int)
        self._session_counter = 0

    def _parse_replay_rules(self, replay_rules: List[Dict[str, Any]]) -> Dict[str, ReplayRule]:
        parsed_rules: Dict[str, ReplayRule] = {}

        for rule in replay_rules:
            if not isinstance(rule, dict):
                continue

            action = rule.get("action")
            if not action:
                continue

            count = rule.get("count", 1)
            if not isinstance(count, int) or count < 1:
                print(f"[!] Warning: Replay rule for '{action}' has invalid count '{count}'. Ignoring.")
                continue

            block_original = bool(rule.get("block_original", False))
            delay_ms = rule.get("delay_ms", 0)
            if not isinstance(delay_ms, (int, float)) or delay_ms < 0:
                delay_ms = 0
            delay_ms = int(delay_ms)
            if block_original:
                delay_ms = 0

            position = rule.get("position", "after")
            if position not in ("before", "after"):
                position = "after"

            parsed_rules[action] = ReplayRule(
                action=action,
                count=count,
                block_original=block_original,
                delay_ms=delay_ms,
                data=rule.get("data"),
                position=position,
            )

        return parsed_rules

    def _message_action(self, message: Dict[str, Any]) -> Optional[str]:
        if not isinstance(message, dict):
            return None
        action = message.get("action")
        return action if isinstance(action, str) else None

    def _create_session(self, action: str, message: Dict[str, Any], rule: ReplayRule) -> ReplaySession:
        self._session_counter += 1
        session = ReplaySession(
            session_id=self._session_counter,
            action=action,
            original_message=message.copy(),
            remaining_count=rule.count,
            block_remaining=rule.count if rule.block_original else 0,
            block_original=rule.block_original,
            delay_ms=rule.delay_ms,
            data=rule.data,
            position=rule.position,
            next_emit_at=time.monotonic(),
        )
        self.sessions[action] = session
        print(
            f"[REPLAY] Started session action='{action}' session_id={session.session_id} "
            f"count={rule.count} block_original={rule.block_original}"
        )
        return session

    def check_replay_block(self, message: Dict[str, Any]) -> bool:
        action = self._message_action(message)
        if not action:
            return False

        rule = self.rules.get(action)
        session = self.sessions.get(action)

        if session is None and rule and rule.block_original:
            session = self._create_session(action, message, rule)

        if session and session.block_remaining > 0:
            session.block_remaining -= 1
            print(
                f"[REPLAY] Blocking action='{action}' session_id={session.session_id} "
                f"blocks_remaining={session.block_remaining}"
            )
            return True

        return False

    def start_replay_if_needed(self, message: Dict[str, Any]) -> bool:
        action = self._message_action(message)
        if not action:
            return False

        if action in self.sessions:
            return False

        rule = self.rules.get(action)
        if not rule:
            return False

        self._create_session(action, message, rule)
        return True

    def get_replay_insertions(self, message: Dict[str, Any]) -> List[Insertion]:
        action = self._message_action(message)
        if not action:
            return []

        session = self.sessions.get(action)
        if not session:
            return []

        insertions: List[Insertion] = []
        now = time.monotonic()
        max_emits = 1 if session.block_original else None

        while session.remaining_count > 0:
            if session.delay_ms > 0 and now < session.next_emit_at:
                break

            replay_data = self._create_replay_data(session, message)
            if replay_data is None:
                print(
                    f"[REPLAY] Session action='{action}' session_id={session.session_id} has no replay data; ending"
                )
                session.remaining_count = 0
                break

            session.remaining_count -= 1
            session.emitted_count += 1
            self.replay_counters[action] += 1

            insertions.append(
                Insertion(
                    data=replay_data,
                    position=session.position,
                    tag=f"replay_{action}_{session.session_id}_{session.emitted_count}",
                )
            )

            print(
                f"[REPLAY] Emitted replay action='{action}' session_id={session.session_id} "
                f"remaining={session.remaining_count}"
            )

            if session.delay_ms > 0:
                session.next_emit_at = now + (session.delay_ms / 1000.0)
                break

            if max_emits is not None and len(insertions) >= max_emits:
                break

        if session.remaining_count == 0 and session.block_remaining == 0:
            del self.sessions[action]
            print(
                f"[REPLAY] Completed session action='{action}' session_id={session.session_id} "
                f"total_emitted={session.emitted_count}"
            )

        return insertions

    def _create_replay_data(self, session: ReplaySession, current_message: Dict[str, Any]) -> Optional[bytes]:
        if session.data is not None:
            return self._coerce_bytes(session.data)

        original_data = current_message.get("data")
        if original_data is None:
            original_data = session.original_message.get("data")

        return self._coerce_bytes(original_data)

    def _coerce_bytes(self, value: Any) -> Optional[bytes]:
        if value is None:
            return None
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            return value.encode("utf-8")
        return str(value).encode("utf-8")

    def get_active_replay_count(self, action: str) -> int:
        return 1 if action in self.sessions else 0

    def get_total_replay_count(self, action: str) -> int:
        return self.replay_counters.get(action, 0)

    def clear_replays(self, action: str = None) -> None:
        if action is None:
            self.sessions.clear()
            self.replay_counters.clear()
            print("[REPLAY] Cleared all replay sessions")
            return

        if action in self.sessions:
            del self.sessions[action]
            print(f"[REPLAY] Cleared replay session for action '{action}'")

    def get_replay_status(self) -> Dict[str, Any]:
        status = {
            "active_sessions": {},
            "total_replays": dict(self.replay_counters),
            "total_active_sessions": len(self.sessions),
        }

        for action, session in self.sessions.items():
            status["active_sessions"][action] = {
                "session_id": session.session_id,
                "remaining_count": session.remaining_count,
                "block_remaining": session.block_remaining,
                "delay_ms": session.delay_ms,
                "emitted_count": session.emitted_count,
            }

        return status
