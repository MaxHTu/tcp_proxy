import asyncio

from utils.contracts import ForwardingContext, MessageFrame
from utils.payload_handling import PayloadHandler


def make_frame(action, decode_error=None):
    message = {"action": action, "data": "body"}
    return MessageFrame(
        length_prefix=b"\x00\x00\x00\x04",
        payload=b"data",
        raw_frame=b"\x00\x00\x00\x04data",
        decoded=message if decode_error is None else None,
        decode_error=decode_error,
    )


def run_process(handler, frame, source_ip="10.0.0.1", target_ip="10.0.0.2"):
    return asyncio.run(
        handler.process_frame(
            frame=frame,
            context=ForwardingContext(
                connection_id="conn-1",
                direction_label="unit-test",
                source_ip=source_ip,
                target_ip=target_ip,
            ),
        )
    )


def test_block_rule_drops_and_prevents_insertions():
    handler = PayloadHandler(
        {
            "payload_handling": {
                "global": {
                    "block": [{"action": "drop_me"}],
                    "insert": [{"action": "drop_me", "position": "after", "data": "aa", "repeat": 1}],
                }
            }
        }
    )

    decision = run_process(handler, make_frame("drop_me"))
    assert decision.forward_original is False
    assert decision.drop_reason == "block:global"
    assert decision.before_insertions == []
    assert decision.after_insertions == []


def test_insert_repeat_false_runs_once_with_persistent_state():
    handler = PayloadHandler(
        {
            "payload_handling": {
                "global": {
                    "insert": [{"action": "once", "position": "before", "data": "aa", "repeat": False}],
                }
            }
        }
    )

    first = run_process(handler, make_frame("once"))
    second = run_process(handler, make_frame("once"))

    assert first.forward_original is True
    assert len(first.before_insertions) == 1
    assert second.forward_original is True
    assert second.before_insertions == []


def test_replay_non_blocking_emits_count_and_forwards_original():
    handler = PayloadHandler(
        {
            "payload_handling": {
                "global": {
                    "replay": [
                        {
                            "action": "echo",
                            "count": 2,
                            "block_original": False,
                            "position": "after",
                            "data": "R",
                        }
                    ]
                }
            }
        }
    )

    decision = run_process(handler, make_frame("echo"))
    assert decision.forward_original is True
    assert len(decision.after_insertions) == 2
    assert all(insertion.data == b"R" for insertion in decision.after_insertions)


def test_replay_block_original_blocks_and_replays_once_per_blocked_call():
    handler = PayloadHandler(
        {
            "payload_handling": {
                "global": {
                    "replay": [
                        {
                            "action": "ping",
                            "count": 3,
                            "block_original": True,
                            "position": "after",
                            "data": "X",
                        }
                    ]
                }
            }
        }
    )

    first = run_process(handler, make_frame("ping"))
    second = run_process(handler, make_frame("ping"))
    third = run_process(handler, make_frame("ping"))

    for decision in (first, second, third):
        assert decision.forward_original is False
        assert decision.drop_reason.startswith("replay_block")
        assert len(decision.after_insertions) == 1
        assert decision.after_insertions[0].data == b"X"


def test_direction_rules_match_by_ip_pair_and_add_insertion():
    handler = PayloadHandler(
        {
            "payload_handling": {
                "global": {},
                "directions": {
                    "a_to_b": {
                        "source_ip": "10.0.0.1",
                        "target_ip": "10.0.0.2",
                        "insert": [
                            {
                                "action": "dir",
                                "position": "after",
                                "data": "deadbeef",
                                "repeat": 1,
                            }
                        ],
                    }
                },
            }
        }
    )

    matched = run_process(handler, make_frame("dir"), source_ip="10.0.0.1", target_ip="10.0.0.2")
    unmatched = run_process(handler, make_frame("dir"), source_ip="10.0.0.3", target_ip="10.0.0.4")

    assert len(matched.after_insertions) == 1
    assert matched.after_insertions[0].data == bytes.fromhex("deadbeef")
    assert unmatched.after_insertions == []


def test_decode_error_frame_forwards_without_rule_evaluation():
    handler = PayloadHandler({"payload_handling": {"global": {"block": [{"action": "x"}]}}})
    frame = make_frame("x", decode_error="broken pickle")

    decision = run_process(handler, frame)
    assert decision.forward_original is True
    assert decision.before_insertions == []
    assert decision.after_insertions == []


def test_delay_ms_is_applied_from_global_and_direction_rules():
    handler = PayloadHandler(
        {
            "payload_handling": {
                "global": {"delay": [{"action": "slow", "delay_ms": 1}]},
                "directions": {
                    "a_to_b": {
                        "source_ip": "10.0.0.1",
                        "target_ip": "10.0.0.2",
                        "delay": [{"action": "slow", "delay_ms": 2}],
                    }
                },
            }
        }
    )

    decision = run_process(handler, make_frame("slow"), source_ip="10.0.0.1", target_ip="10.0.0.2")
    assert decision.forward_original is True
    assert decision.delayed_ms == 3
