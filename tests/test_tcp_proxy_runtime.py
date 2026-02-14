import asyncio
from pathlib import Path

from tcp_proxy import ProxyRuntimeState
from utils.contracts import ForwardingContext, MessageFrame


def write_config(path: Path, *, host: str, port: int, blocked_action: str) -> None:
    path.write_text(
        "\n".join(
            [
                "src:",
                f'  host: "{host}"',
                f"  port: {port}",
                "payload_handling:",
                "  global:",
                "    block:",
                f'      - action: "{blocked_action}"',
                "",
            ]
        ),
        encoding="utf-8",
    )


def make_frame(action: str) -> MessageFrame:
    return MessageFrame(
        length_prefix=b"\x00\x00\x00\x04",
        payload=b"data",
        raw_frame=b"\x00\x00\x00\x04data",
        decoded={"action": action},
    )


def test_runtime_reload_updates_handler_but_keeps_boot_listener(tmp_path):
    config_path = tmp_path / "config.yaml"
    write_config(config_path, host="127.0.0.1", port=9000, blocked_action="first")

    runtime_state = ProxyRuntimeState(str(config_path))
    runtime_state.load_initial()

    initial_snapshot = runtime_state.snapshot()
    assert initial_snapshot.source.host == "127.0.0.1"
    assert initial_snapshot.source.port == 9000

    write_config(config_path, host="127.0.0.2", port=9001, blocked_action="second")
    assert runtime_state.reload_from_file() is True

    reloaded_snapshot = runtime_state.snapshot()
    assert reloaded_snapshot.source.host == "127.0.0.1"
    assert reloaded_snapshot.source.port == 9000
    assert reloaded_snapshot.config_version == 1

    context = ForwardingContext(
        connection_id="conn-1",
        direction_label="unit-test",
        source_ip="10.0.0.1",
        target_ip="10.0.0.2",
    )
    first_decision = asyncio.run(
        initial_snapshot.payload_handler.process_frame(frame=make_frame("first"), context=context)
    )
    second_decision = asyncio.run(
        reloaded_snapshot.payload_handler.process_frame(frame=make_frame("second"), context=context)
    )

    assert first_decision.forward_original is False
    assert first_decision.drop_reason == "block:global"
    assert second_decision.forward_original is False
    assert second_decision.drop_reason == "block:global"


def test_runtime_initial_load_rejects_invalid_src_port(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "src:",
                '  host: "127.0.0.1"',
                '  port: "bad"',
                "payload_handling:",
                "  global: {}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    runtime_state = ProxyRuntimeState(str(config_path))

    try:
        runtime_state.load_initial()
    except Exception as exc:
        assert "src.port must be an integer" in str(exc)
    else:
        raise AssertionError("Expected invalid port configuration to raise")
