import asyncio

from utils.block_action import BlockAction
from utils.delay_action import DelayAction
from utils.insert_action import InsertAction
from utils.replay_action import ReplayAction


def test_block_action_matches_only_configured_actions():
    action = BlockAction({"drop_me"})

    assert action.should_block({"action": "drop_me"}) is True
    assert action.should_block({"action": "keep_me"}) is False
    assert action.should_block("not-a-dict") is False


def test_delay_action_gets_and_applies_delay():
    action = DelayAction({"slow": 1})

    assert action.get_delay({"action": "slow"}) == 1
    assert action.get_delay({"action": "fast"}) is None
    assert asyncio.run(action.should_delay({"action": "slow"})) is True
    assert asyncio.run(action.should_delay({"action": "fast"})) is False


def test_insert_action_repeat_false_runs_only_once():
    action = InsertAction(
        [
            {
                "action": "once",
                "position": "before",
                "data": "aa",
                "repeat": False,
            }
        ]
    )

    first = asyncio.run(action.get_insertions({"action": "once"}))
    second = asyncio.run(action.get_insertions({"action": "once"}))

    assert len(first) == 1
    assert first[0].data == b"\xaa"
    assert second == []


def test_insert_action_skips_invalid_hex_payloads():
    action = InsertAction([{"action": "bad", "position": "after", "data": "xyz", "repeat": 1}])

    assert asyncio.run(action.get_insertions({"action": "bad"})) == []


def test_replay_action_blocks_and_emits_expected_replays():
    action = ReplayAction(
        [
            {
                "action": "ping",
                "count": 2,
                "block_original": True,
                "position": "after",
                "data": "X",
            }
        ]
    )
    message = {"action": "ping", "data": "body"}

    assert action.check_replay_block(message) is True
    first = action.get_replay_insertions(message)
    assert len(first) == 1
    assert first[0].data == b"X"

    assert action.check_replay_block(message) is True
    second = action.get_replay_insertions(message)
    assert len(second) == 1
    assert second[0].data == b"X"
    assert action.get_active_replay_count("ping") == 0
    assert action.get_total_replay_count("ping") == 2
