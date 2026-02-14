from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass(frozen=True)
class MessageFrame:
    length_prefix: bytes
    payload: bytes
    raw_frame: bytes
    decoded: Any
    decode_error: Optional[str] = None


@dataclass(frozen=True)
class Insertion:
    data: bytes
    position: str
    tag: str


@dataclass
class RuleDecision:
    forward_original: bool
    before_insertions: List[Insertion] = field(default_factory=list)
    after_insertions: List[Insertion] = field(default_factory=list)
    drop_reason: Optional[str] = None
    delayed_ms: int = 0


@dataclass
class DirectionContext:
    source_ip: str
    target_ip: str
    direction_name: str
    delay_action: Any
    block_action: Any
    insert_action: Any
    replay_action: Any
