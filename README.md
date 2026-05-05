# TCP Proxy

Transparent, application-aware TCP proxy for controlled fault-injection experiments on
QKD classical-channel traffic.

The proxy is built for Linux TPROXY deployments. It accepts transparently redirected
TCP connections, recovers the original destination with `SO_ORIGINAL_DST`, opens a
matching outbound socket with `IP_TRANSPARENT`, and forwards bytes in both
directions. When rules are configured, it decodes the stream as 4-byte big-endian
length-prefixed Python Pickle messages and applies payload actions by message
`action`.

## Features

- transparent on-path forwarding without changing endpoint configuration
- frame-aware decoding of length-prefixed Pickle payloads
- rule actions: delay, block, insert, replay
- global and direction-specific rules
- YAML config with runtime reload when `watchdog` is installed
- JSON event logs on stdout
- raw pass-through when no payload rules are active

## Requirements

- Linux with TPROXY support
- Python 3.12+
- privileges or capabilities required for transparent sockets and firewall/routing setup
- Python dependencies from `pyproject.toml`

Install the runtime dependencies:

```bash
python3 -m pip install -e ".[runtime]"
```

## Configuration

Rules live in `config/config.yaml`.

```yaml
src:
  host: "0.0.0.0"
  port: 8000

payload_handling:
  global:
    delay:
      - action: "example_action"
        delay_ms: 10
    block:
      - action: "example_action"
    insert:
      - action: "example_action"
        position: "before"
        data: "deadbeef"
        repeat: 1
    replay:
      - action: "example_action"
        count: 3
        block_original: true
        position: "after"

  directions:
    alice_to_bob:
      source_ip: "10.10.20.11"
      target_ip: "10.10.20.13"
```

`src` defines the transparent listener. `payload_handling.global` applies to all
decoded messages. `payload_handling.directions` limits rules to a specific source and
target IP pair.

## Running

Configure the host firewall and routing rules so the target TCP flows are redirected to
the configured proxy port, then start:

```bash
python3 tcp_proxy.py
```

The proxy logs connection, config, decode, and frame-decision events as JSON lines.
Decode errors and non-dict messages are forwarded unchanged.

## Ethical Use

Use this proxy only in systems you own or are explicitly authorized to test. It was
created for isolated lab experiments on research equipment, not for production traffic
or third-party networks.
