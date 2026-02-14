from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

import yaml

from utils.contracts import DirectionRuleSetConfig, ProxyConfig, RuleSetConfig, SourceConfig


class ConfigValidationError(ValueError):
    def __init__(self, errors: List[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


@dataclass(frozen=True)
class LoadedProxyConfig:
    config: ProxyConfig
    warnings: Tuple[str, ...] = ()


def load_proxy_config(config_path: str) -> LoadedProxyConfig:
    with open(config_path, "r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)

    if loaded is None:
        loaded = {}

    if not isinstance(loaded, dict):
        raise ConfigValidationError(["config root must be a mapping"])

    return normalize_proxy_config(loaded)


def normalize_proxy_config(config: Dict[str, Any]) -> LoadedProxyConfig:
    errors: List[str] = []
    warnings: List[str] = []

    payload_handling = config.get("payload_handling")
    if payload_handling is None:
        errors.append("missing top-level key: payload_handling")
        payload_handling = {}
    elif not isinstance(payload_handling, dict):
        errors.append("payload_handling must be a dictionary")
        payload_handling = {}

    src = config.get("src", {})
    if src is None:
        src = {}
    elif not isinstance(src, dict):
        errors.append("src must be a dictionary when present")
        src = {}

    source = _parse_source_config(src, errors)
    global_rules = _parse_rule_set(payload_handling.get("global", {}), "payload_handling.global", errors, warnings)
    directions = _parse_directions(payload_handling.get("directions", {}), errors, warnings)

    if errors:
        raise ConfigValidationError(errors)

    return LoadedProxyConfig(
        config=ProxyConfig(
            source=source,
            global_rules=global_rules,
            directions=tuple(directions),
        ),
        warnings=tuple(warnings),
    )


def _parse_source_config(src: Dict[str, Any], errors: List[str]) -> SourceConfig:
    host = src.get("host", "0.0.0.0")
    if not isinstance(host, str) or not host.strip():
        errors.append("src.host must be a non-empty string")
        host = "0.0.0.0"

    port = src.get("port", 8000)
    if not isinstance(port, int):
        errors.append("src.port must be an integer")
        port = 8000
    elif port < 1 or port > 65535:
        errors.append("src.port must be between 1 and 65535")
        port = 8000

    return SourceConfig(host=host, port=port)


def _parse_directions(raw_directions: Any, errors: List[str], warnings: List[str]) -> List[DirectionRuleSetConfig]:
    if raw_directions is None:
        return []
    if not isinstance(raw_directions, dict):
        errors.append("payload_handling.directions must be a dictionary when present")
        return []

    directions: List[DirectionRuleSetConfig] = []
    for direction_name, direction_config in raw_directions.items():
        if not isinstance(direction_config, dict):
            warnings.append(f"Skipping direction '{direction_name}': configuration must be a dictionary.")
            continue

        source_ip = direction_config.get("source_ip")
        if source_ip is not None and not isinstance(source_ip, str):
            warnings.append(f"Direction '{direction_name}' has non-string source_ip. Ignoring match constraint.")
            source_ip = None

        target_ip = direction_config.get("target_ip")
        if target_ip is not None and not isinstance(target_ip, str):
            warnings.append(f"Direction '{direction_name}' has non-string target_ip. Ignoring match constraint.")
            target_ip = None

        directions.append(
            DirectionRuleSetConfig(
                direction_name=direction_name,
                source_ip=source_ip,
                target_ip=target_ip,
                rules=_parse_rule_set(
                    direction_config,
                    f"payload_handling.directions.{direction_name}",
                    errors,
                    warnings,
                ),
            )
        )

    return directions


def _parse_rule_set(raw_rules: Any, scope: str, errors: List[str], warnings: List[str]) -> RuleSetConfig:
    if raw_rules is None:
        raw_rules = {}
    if not isinstance(raw_rules, dict):
        errors.append(f"{scope} must be a dictionary")
        return RuleSetConfig()

    delay_rules: Dict[str, int] = {}
    for rule in _coerce_rule_list(raw_rules.get("delay", []), f"{scope}.delay", warnings):
        action = rule.get("action")
        delay_ms = rule.get("delay_ms", 0)
        if not isinstance(action, str) or not action:
            warnings.append(f"Skipping {scope}.delay rule without a valid action.")
            continue
        if not isinstance(delay_ms, (int, float)) or delay_ms <= 0:
            warnings.append(f"Skipping {scope}.delay rule for action '{action}' with non-positive delay_ms.")
            continue
        delay_rules[action] = int(delay_ms)

    block_rules = {
        action
        for action in (
            rule.get("action")
            for rule in _coerce_rule_list(raw_rules.get("block", []), f"{scope}.block", warnings)
        )
        if isinstance(action, str) and action
    }

    insert_rules = [
        dict(rule)
        for rule in _coerce_rule_list(raw_rules.get("insert", []), f"{scope}.insert", warnings)
        if isinstance(rule.get("action"), str)
        and bool(rule.get("action"))
        and "data" in rule
    ]

    replay_rules = [
        dict(rule)
        for rule in _coerce_rule_list(raw_rules.get("replay", []), f"{scope}.replay", warnings)
        if isinstance(rule.get("action"), str)
        and bool(rule.get("action"))
        and "count" in rule
    ]

    return RuleSetConfig(
        delay_rules=delay_rules,
        block_rules=block_rules,
        insert_rules=insert_rules,
        replay_rules=replay_rules,
    )


def _coerce_rule_list(value: Any, scope: str, warnings: List[str]) -> List[Dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        warnings.append(f"Skipping {scope}: expected a list of rules.")
        return []

    rules: List[Dict[str, Any]] = []
    for rule in value:
        if not isinstance(rule, dict):
            warnings.append(f"Skipping non-dictionary rule in {scope}.")
            continue
        rules.append(rule)
    return rules
