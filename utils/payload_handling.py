from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional, Tuple

from utils.block_action import BlockAction
from utils.config_loading import ConfigValidationError, normalize_proxy_config
from utils.contracts import (
    DirectionContext,
    ForwardingContext,
    Insertion,
    MessageFrame,
    ProxyConfig,
    RuleDecision,
)
from utils.delay_action import DelayAction
from utils.insert_action import InsertAction
from utils.replay_action import ReplayAction


class PayloadHandler:
    """Applies normalized global and direction-specific payload rules."""

    def __init__(self, config: Optional[ProxyConfig | Dict[str, Any]] = None, config_version: int = 0):
        # Normalize once at construction so frame handling avoids YAML-shaped config parsing.
        self.config = self._normalize_config(config)
        self.config_version = config_version
        self.direction_lookup: Dict[Tuple[str, str], DirectionContext] = {}
        self.global_delay_action = DelayAction(self.config.global_rules.delay_rules)
        self.global_block_action = BlockAction(self.config.global_rules.block_rules)
        self.global_insert_action = InsertAction(self.config.global_rules.insert_rules)
        self.global_replay_action = ReplayAction(self.config.global_rules.replay_rules)

        for direction in self.config.directions:
            if not direction.source_ip or not direction.target_ip:
                continue

            self.direction_lookup[(direction.source_ip, direction.target_ip)] = DirectionContext(
                source_ip=direction.source_ip,
                target_ip=direction.target_ip,
                direction_name=direction.direction_name,
                delay_action=DelayAction(direction.rules.delay_rules),
                block_action=BlockAction(direction.rules.block_rules),
                insert_action=InsertAction(direction.rules.insert_rules),
                replay_action=ReplayAction(direction.rules.replay_rules),
            )

    @staticmethod
    def validate_config(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate raw config through the same normalization path used at runtime."""
        try:
            normalize_proxy_config(config)
        except ConfigValidationError as exc:
            return False, exc.errors
        return True, []

    def _normalize_config(self, config: Optional[ProxyConfig | Dict[str, Any]]) -> ProxyConfig:
        if isinstance(config, ProxyConfig):
            return config
        if config is None:
            return ProxyConfig()
        return normalize_proxy_config(config).config

    def get_matching_direction(self, source_ip: str, target_ip: str) -> Optional[DirectionContext]:
        return self.direction_lookup.get((source_ip, target_ip))

    def _log_event(self, **fields: Any) -> None:
        payload = {
            "component": "payload_handler",
            "config_version": self.config_version,
            **fields,
        }
        print(json.dumps(payload, default=str))

    def _add_insertions(self, decision: RuleDecision, insertions: List[Insertion]) -> None:
        for insertion in insertions:
            if insertion.position == "before":
                decision.before_insertions.append(insertion)
            else:
                decision.after_insertions.append(insertion)

    async def process_frame(
        self,
        frame: MessageFrame,
        context: ForwardingContext,
    ) -> RuleDecision:
        """Evaluate one decoded frame and return the writes/drop decision."""
        decision = RuleDecision(forward_original=True)

        if frame.decode_error:
            self._log_event(
                event="decode_error",
                connection_id=context.connection_id,
                direction=context.direction_label,
                source_ip=context.source_ip,
                target_ip=context.target_ip,
                decode_error=frame.decode_error,
                decision="forward_raw_frame",
            )
            return decision

        message = frame.decoded
        if not isinstance(message, dict):
            self._log_event(
                event="non_dict_message",
                connection_id=context.connection_id,
                direction=context.direction_label,
                source_ip=context.source_ip,
                target_ip=context.target_ip,
                decision="forward_raw_frame",
            )
            return decision

        action = message.get("action")
        direction_ctx = self.get_matching_direction(context.source_ip, context.target_ip)

        replay_blocked = self.global_replay_action.check_replay_block(message)
        replay_block_scope = "global" if replay_blocked else None
        if not replay_blocked and direction_ctx:
            replay_blocked = direction_ctx.replay_action.check_replay_block(message)
            if replay_blocked:
                replay_block_scope = direction_ctx.direction_name

        if replay_blocked:
            decision.forward_original = False
            decision.drop_reason = f"replay_block:{replay_block_scope}"

        if decision.forward_original and self.global_block_action.should_block(message):
            decision.forward_original = False
            decision.drop_reason = "block:global"

        if decision.forward_original and direction_ctx and direction_ctx.block_action.should_block(message):
            decision.forward_original = False
            decision.drop_reason = f"block:{direction_ctx.direction_name}"

        if not decision.forward_original and not decision.drop_reason.startswith("replay_block"):
            self._log_event(
                event="frame_decision",
                connection_id=context.connection_id,
                direction=context.direction_label,
                source_ip=context.source_ip,
                target_ip=context.target_ip,
                action=action,
                decision="drop",
                drop_reason=decision.drop_reason,
            )
            return decision

        if decision.forward_original:
            global_delay = self.global_delay_action.get_delay(message)
            if global_delay:
                await asyncio.sleep(global_delay / 1000.0)
                decision.delayed_ms += int(global_delay)

            if direction_ctx:
                direction_delay = direction_ctx.delay_action.get_delay(message)
                if direction_delay:
                    await asyncio.sleep(direction_delay / 1000.0)
                    decision.delayed_ms += int(direction_delay)

            self.global_replay_action.start_replay_if_needed(message)
            if direction_ctx:
                direction_ctx.replay_action.start_replay_if_needed(message)

        self._add_insertions(decision, self.global_replay_action.get_replay_insertions(message))
        if direction_ctx:
            self._add_insertions(decision, direction_ctx.replay_action.get_replay_insertions(message))

        if decision.forward_original:
            self._add_insertions(decision, await self.global_insert_action.get_insertions(message))
            if direction_ctx:
                self._add_insertions(decision, await direction_ctx.insert_action.get_insertions(message))

        self._log_event(
            event="frame_decision",
            connection_id=context.connection_id,
            direction=context.direction_label,
            source_ip=context.source_ip,
            target_ip=context.target_ip,
            action=action,
            decision="forward" if decision.forward_original else "drop",
            drop_reason=decision.drop_reason,
            delayed_ms=decision.delayed_ms,
            before_insertions=len(decision.before_insertions),
            after_insertions=len(decision.after_insertions),
            matched_direction=direction_ctx.direction_name if direction_ctx else None,
        )

        return decision
