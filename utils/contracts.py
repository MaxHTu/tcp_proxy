from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Set, Tuple


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


class DelayActionProtocol(Protocol):
    def get_delay(self, message: Dict[str, Any]) -> Optional[int]:
        ...


class BlockActionProtocol(Protocol):
    def should_block(self, message: Dict[str, Any]) -> bool:
        ...


class InsertActionProtocol(Protocol):
    async def get_insertions(self, message: Any) -> List["Insertion"]:
        ...


class ReplayActionProtocol(Protocol):
    def check_replay_block(self, message: Dict[str, Any]) -> bool:
        ...

    def start_replay_if_needed(self, message: Dict[str, Any]) -> bool:
        ...

    def get_replay_insertions(self, message: Dict[str, Any]) -> List["Insertion"]:
        ...


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
    delay_action: DelayActionProtocol
    block_action: BlockActionProtocol
    insert_action: InsertActionProtocol
    replay_action: ReplayActionProtocol


@dataclass(frozen=True)
class RuleSetConfig:
    delay_rules: Dict[str, int] = field(default_factory=dict)
    block_rules: Set[str] = field(default_factory=set)
    insert_rules: List[Dict[str, Any]] = field(default_factory=list)
    replay_rules: List[Dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class DirectionRuleSetConfig:
    direction_name: str
    source_ip: Optional[str]
    target_ip: Optional[str]
    rules: RuleSetConfig = field(default_factory=RuleSetConfig)


@dataclass(frozen=True)
class SourceConfig:
    host: str = "0.0.0.0"
    port: int = 8000


@dataclass(frozen=True)
class ProxyConfig:
    source: SourceConfig = field(default_factory=SourceConfig)
    global_rules: RuleSetConfig = field(default_factory=RuleSetConfig)
    directions: Tuple[DirectionRuleSetConfig, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ForwardingContext:
    connection_id: str
    direction_label: str
    source_ip: str
    target_ip: str
