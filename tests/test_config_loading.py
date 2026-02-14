from utils.config_loading import ConfigValidationError, normalize_proxy_config


def test_normalize_proxy_config_builds_typed_rule_sets():
    loaded = normalize_proxy_config(
        {
            "src": {"host": "127.0.0.1", "port": 9000},
            "payload_handling": {
                "global": {
                    "delay": [{"action": "slow", "delay_ms": 5}],
                    "block": [{"action": "drop"}],
                    "insert": [{"action": "insert", "position": "before", "data": "aa", "repeat": 1}],
                    "replay": [{"action": "echo", "count": 2, "position": "after", "data": "bb"}],
                },
                "directions": {
                    "client_to_server": {
                        "source_ip": "10.0.0.1",
                        "target_ip": "10.0.0.2",
                        "block": [{"action": "dir_drop"}],
                    }
                },
            },
        }
    )

    assert loaded.warnings == ()
    assert loaded.config.source.host == "127.0.0.1"
    assert loaded.config.source.port == 9000
    assert loaded.config.global_rules.delay_rules == {"slow": 5}
    assert loaded.config.global_rules.block_rules == {"drop"}
    assert len(loaded.config.global_rules.insert_rules) == 1
    assert len(loaded.config.global_rules.replay_rules) == 1
    assert len(loaded.config.directions) == 1
    assert loaded.config.directions[0].direction_name == "client_to_server"
    assert loaded.config.directions[0].rules.block_rules == {"dir_drop"}


def test_normalize_proxy_config_rejects_invalid_port():
    try:
        normalize_proxy_config(
            {
                "src": {"host": "127.0.0.1", "port": "bad"},
                "payload_handling": {"global": {}},
            }
        )
    except ConfigValidationError as exc:
        assert exc.errors == ["src.port must be an integer"]
    else:
        raise AssertionError("Expected invalid src.port to fail validation")


def test_normalize_proxy_config_warns_and_skips_invalid_direction_entries():
    loaded = normalize_proxy_config(
        {
            "payload_handling": {
                "global": {},
                "directions": {
                    "broken": "nope",
                    "partial": {
                        "source_ip": 123,
                        "target_ip": ["bad"],
                    },
                },
            }
        }
    )

    assert len(loaded.config.directions) == 1
    assert loaded.config.directions[0].source_ip is None
    assert loaded.config.directions[0].target_ip is None
    assert any("Skipping direction 'broken'" in warning for warning in loaded.warnings)
    assert any("non-string source_ip" in warning for warning in loaded.warnings)
    assert any("non-string target_ip" in warning for warning in loaded.warnings)
