from __future__ import annotations

import asyncio
import copy
import json
from typing import Any, Dict, List, Optional, Set, Tuple

from utils.block_action import BlockAction
from utils.contracts import DirectionContext, Insertion, MessageFrame, RuleDecision
from utils.delay_action import DelayAction
from utils.insert_action import InsertAction
from utils.replay_action import ReplayAction


class PayloadHandler:
    def __init__(self, config: Optional[Dict[str, Any]] = None, config_version: int = 0):
        self.config = config or {}
        self.config_version = config_version
        self.direction_lookup: Dict[Tuple[str, str], DirectionContext] = {}
        self.reload_from_config(self.config)

    @staticmethod
    def validate_config(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if not isinstance(config, dict):
            return False, ["config must be a dictionary"]

        payload_handling = config.get("payload_handling")
        if payload_handling is None:
            errors.append("missing top-level key: payload_handling")
        elif not isinstance(payload_handling, dict):
            errors.append("payload_handling must be a dictionary")

        src = config.get("src")
        if src is not None and not isinstance(src, dict):
            errors.append("src must be a dictionary when present")

        return len(errors) == 0, errors

    def reload_from_config(self, config: Dict[str, Any]) -> None:
        self.config = copy.deepcopy(config)
        self.global_rules = self.parse_global_rules()
        self.direction_rules = self.parse_direction_rules()

        self.global_delay_action = DelayAction(self.global_rules["delay"])
        self.global_block_action = BlockAction(self.global_rules["block"])
        self.global_insert_action = InsertAction(self.global_rules["insert"])
        self.global_replay_action = ReplayAction(self.global_rules["replay"])

        self.direction_lookup = {}
        for direction_name, direction_config in self.direction_rules.items():
            source_ip = direction_config.get("source_ip")
            target_ip = direction_config.get("target_ip")
            if not source_ip or not target_ip:
                continue

            self.direction_lookup[(source_ip, target_ip)] = DirectionContext(
                source_ip=source_ip,
                target_ip=target_ip,
                direction_name=direction_name,
                delay_action=DelayAction(direction_config["delay"]),
                block_action=BlockAction(direction_config["block"]),
                insert_action=InsertAction(direction_config["insert"]),
                replay_action=ReplayAction(direction_config["replay"]),
            )

    def load_config(self, config_path: str) -> Dict[str, Any]:
        try:
            import yaml
        except ModuleNotFoundError as exc:
            raise RuntimeError("PyYAML is required to load config files") from exc

        with open(config_path, "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)

    def parse_global_rules(self) -> Dict[str, Any]:
        payload_handling = self.config.get("payload_handling", {})
        global_rules = payload_handling.get("global", {})

        delay_rules: Dict[str, int] = {}
        for rule in global_rules.get("delay", []):
            if isinstance(rule, dict) and "action" in rule and "delay_ms" in rule:
                action = rule["action"]
                delay_ms = rule.get("delay_ms", 0)
                if delay_ms is not None and delay_ms > 0:
                    delay_rules[action] = int(delay_ms)
                else:
                    print(f"[!] Warning: Delay rule for action '{action}' has non-positive delay_ms. Ignoring.")

        block_rules: Set[str] = set()
        for rule in global_rules.get("block", []):
            if isinstance(rule, dict) and "action" in rule:
                block_rules.add(rule["action"])

        insert_rules: List[Dict[str, Any]] = []
        for rule in global_rules.get("insert", []):
            if isinstance(rule, dict) and "action" in rule and "data" in rule:
                insert_rules.append(rule)

        replay_rules: List[Dict[str, Any]] = []
        for rule in global_rules.get("replay", []):
            if isinstance(rule, dict) and "action" in rule and "count" in rule:
                replay_rules.append(rule)

        return {
            "delay": delay_rules,
            "block": block_rules,
            "insert": insert_rules,
            "replay": replay_rules,
        }

    def parse_direction_rules(self) -> Dict[str, Dict[str, Any]]:
        payload_handling = self.config.get("payload_handling", {})
        direction_rules: Dict[str, Dict[str, Any]] = {}

        for direction_name, direction_config in payload_handling.get("directions", {}).items():
            delay_rules: Dict[str, int] = {}
            for rule in direction_config.get("delay", []):
                if isinstance(rule, dict) and "action" in rule and "delay_ms" in rule:
                    action = rule["action"]
                    delay_ms = rule.get("delay_ms", 0)
                    if delay_ms is not None and delay_ms > 0:
                        delay_rules[action] = int(delay_ms)
                    else:
                        print(
                            f"[!] Warning: Direction '{direction_name}' delay rule "
                            f"for action '{action}' has non-positive delay_ms. Ignoring."
                        )

            block_rules: Set[str] = set()
            for rule in direction_config.get("block", []):
                if isinstance(rule, dict) and "action" in rule:
                    block_rules.add(rule["action"])

            insert_rules: List[Dict[str, Any]] = []
            for rule in direction_config.get("insert", []):
                if isinstance(rule, dict) and "action" in rule and "data" in rule:
                    insert_rules.append(rule)

            replay_rules: List[Dict[str, Any]] = []
            for rule in direction_config.get("replay", []):
                if isinstance(rule, dict) and "action" in rule and "count" in rule:
                    replay_rules.append(rule)

            direction_rules[direction_name] = {
                "source_ip": direction_config.get("source_ip"),
                "target_ip": direction_config.get("target_ip"),
                "delay": delay_rules,
                "block": block_rules,
                "insert": insert_rules,
                "replay": replay_rules,
            }

        return direction_rules

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
        source_ip: str,
        target_ip: str,
        connection_id: str,
        direction_label: str,
    ) -> RuleDecision:
        decision = RuleDecision(forward_original=True)

        if frame.decode_error:
            self._log_event(
                event="decode_error",
                connection_id=connection_id,
                direction=direction_label,
                source_ip=source_ip,
                target_ip=target_ip,
                decode_error=frame.decode_error,
                decision="forward_raw_frame",
            )
            return decision

        message = frame.decoded
        if not isinstance(message, dict):
            self._log_event(
                event="non_dict_message",
                connection_id=connection_id,
                direction=direction_label,
                source_ip=source_ip,
                target_ip=target_ip,
                decision="forward_raw_frame",
            )
            return decision

        action = message.get("action")
        direction_ctx = self.get_matching_direction(source_ip, target_ip)

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
                connection_id=connection_id,
                direction=direction_label,
                source_ip=source_ip,
                target_ip=target_ip,
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
            connection_id=connection_id,
            direction=direction_label,
            source_ip=source_ip,
            target_ip=target_ip,
            action=action,
            decision="forward" if decision.forward_original else "drop",
            drop_reason=decision.drop_reason,
            delayed_ms=decision.delayed_ms,
            before_insertions=len(decision.before_insertions),
            after_insertions=len(decision.after_insertions),
            matched_direction=direction_ctx.direction_name if direction_ctx else None,
        )

        return decision
