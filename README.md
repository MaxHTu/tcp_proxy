# Transparent TCP Proxy

This project provides a transparent TCP proxy that can intercept and modify network traffic based on configurable rules. It leverages TPROXY functionality in Linux for true transparency, meaning the client application does not need to be configured to use the proxy, and the server application sees the connection as coming directly from the original client.

## Features

*   **Transparent Interception**: Uses Linux TPROXY to intercept TCP connections.
*   **Payload Decoding**: Includes a basic pickle-based message decoder.
*   **Rule-Based Actions**: Allows defining rules to:
    *   Delay specific messages.
    *   Block specific messages.
    *   Insert custom data before or after specific messages/chunks.
*   **Global and Direction-Specific Rules**: Rules can be applied globally to all traffic or to specific source-target IP pairs.
*   **Asynchronous I/O**: Built with `asyncio` and `uvloop` for high performance.

## Requirements

*   Linux (for TPROXY functionality)
*   Python 3.7+
*   `uvloop` (recommended for performance)
*   `PyYAML` (for configuration)
*   Root privileges or `CAP_NET_ADMIN` and `CAP_NET_RAW` capabilities for the Python interpreter to enable TPROXY and bind to privileged ports/IPs.

## Configuration (`config/config.yaml`)

The proxy's behavior is controlled by `config/config.yaml`.

### Source Configuration

Defines the address and port the proxy listens on.

```yaml
src:
  host: "0.0.0.0"  # Host IP for the proxy to listen on
  port: 8000       # Port for the proxy to listen on
```

### Payload Handling

This section defines how messages should be handled.

#### Global Rules

Rules under `payload_handling.global` apply to all traffic passing through the proxy.

```yaml
payload_handling:
  global:
    delay:
      # - action: "action_name_to_delay" # Action name from your decoded message
      #   delay_ms: 1000                # Milliseconds to delay
    block:
      # - action: "action_name_to_block"  # Action name to block
    insert_data:
      # - action: "action_name_for_insert"
      #   data: "Hello from global rule"
      #   data_type: "bytes" 
      #   position: "before" 
      #   delay_sec: 0 
```

#### Direction-Specific Rules

Rules can also be defined for specific traffic directions (e.g., from Alice to Bob).

```yaml
  directions:
    alice_to_bob:
      source_ip: "192.168.1.100"  # Source IP of the client
      target_ip: "192.168.1.101"  # Target IP of the server
      delay:
        # - action: "specific_action"
        #   delay_ms: 500
      block:
        # - action: "another_action"
      insert_data:
        # - action: "alice_insert_test_bytes"
        #   data: "Data for Bob"
        #   data_type: "bytes"
        #   position: "before"
        #   delay_sec: 0
    # ... other directions
```

### Rule Types

#### Delaying Traffic

You can delay messages based on their decoded `action`.

*   `action`: The action string that, if matched in a decoded message, will trigger the delay.
*   `delay_ms`: The duration in milliseconds to delay the message.

Example:
```yaml
delay:
  - action: "user_login"
    delay_ms: 2000 # Delay login confirmation by 2 seconds
```

#### Blocking Traffic

You can block messages (and the data chunk they belong to) based on their `action`.

*   `action`: The action string that, if matched, will cause the message and its containing data chunk to be dropped.

Example:
```yaml
block:
  - action: "admin_command" # Block messages with this action
```

#### Inserting Data

You can insert custom data into the TCP stream, either before or after a data chunk that contains a message with a matching `action`.

*   `action`: (Required) The string from the decoded message that triggers this insertion rule.
*   `data`: (Required) The data to be inserted.
*   `data_type`: (Optional) Specifies how the `data` string should be interpreted.
    *   `"bytes"`: The `data` string is encoded using UTF-8. (Default if not specified)
    *   `"hex"`: The `data` string is a sequence of hexadecimal characters (e.g., "aabbccddeeff") that will be converted to raw bytes.
*   `position`: (Optional) Where to insert the data relative to the original data chunk.
    *   `"before"`: Inserts the data before the original chunk. (Default if not specified)
    *   `"after"`: Inserts the data after the original chunk.
*   `delay_sec`: (Optional) Integer number of seconds to wait after the proxy has started before this rule becomes active. Default is `0` (active immediately). This allows scheduling insertions for later in a connection's lifecycle or after the proxy has been running for a while.

Example:
```yaml
insert_data:
  - action: "initial_handshake"
    data: "0102030405" # Hex data
    data_type: "hex"
    position: "before"
    delay_sec: 0
  - action: "data_transfer_complete"
    data: "ACK_FROM_PROXY"
    data_type: "bytes"
    position: "after"
    delay_sec: 5 # This rule becomes active 5 seconds after proxy start
```
If multiple messages within a single received data chunk trigger `insert_data` rules, the **first** rule encountered will be used for the entire chunk.

## Running the Proxy

1.  **Configure `config/config.yaml`** to suit your needs.
2.  **Setup TPROXY rules**: This is crucial and system-dependent. You'll need `iptables` rules to redirect traffic to the proxy's listening port. An example for redirecting traffic destined for `192.168.1.101:80` (Original Target Server) to the proxy listening on `*:8000`:

    ```bash
    # Ensure 'ip_forward' is enabled
    sudo sysctl -w net.ipv4.ip_forward=1

    # Create a new chain for TPROXY
    sudo iptables -t mangle -N DIVERT

    # Mark packets to be diverted
    sudo iptables -t mangle -A PREROUTING -p tcp -d <ORIGINAL_TARGET_IP> --dport <ORIGINAL_TARGET_PORT> -j DIVERT
    # Example: sudo iptables -t mangle -A PREROUTING -p tcp -d 192.168.1.101 --dport 80 -j DIVERT
    
    # Add rule to DIVERT chain to TPROXY packets to the proxy's port
    sudo iptables -t mangle -A DIVERT -j MARK --set-mark 1
    sudo iptables -t mangle -A DIVERT -j ACCEPT

    # Route marked packets locally
    sudo ip rule add fwmark 1 lookup 100
    sudo ip route add local default dev lo table 100

    # TPROXY rule for redirecting to the proxy's listening port (e.g., 8000)
    sudo iptables -t mangle -A PREROUTING -p tcp -m socket --transparent -j TPROXY --tproxy-mark 0x1/0x1 --on-port <PROXY_LISTENING_PORT>
    # Example: sudo iptables -t mangle -A PREROUTING -p tcp -m socket --transparent -j TPROXY --tproxy-mark 0x1/0x1 --on-port 8000
    ```
    **Note**: These `iptables` rules are illustrative. Your specific setup might require adjustments, especially concerning interfaces and IP addresses. The `socket` match (`-m socket --transparent`) is important for ensuring that locally generated traffic from the proxy itself is not re-intercepted.

3.  **Run the script**:
    ```bash
    sudo python tcp_proxy.py 
    # (or with capabilities: sudo setcap cap_net_admin,cap_net_raw+eip $(which python) && python tcp_proxy.py)
    ```

## Development

### Dependencies
Install dependencies (preferably in a virtual environment):
```bash
pip install pyyaml uvloop
```

### Running Tests
Unit tests are located in the `tests/` directory.
```bash
python -m unittest discover -s tests
```
The integration tests (`tests/test_insert_feature.py`) are currently placeholders and require a specific setup to run.

## How It Works

1.  **TPROXY Interception**: `iptables` rules redirect TCP traffic to the proxy's listening socket without altering the destination IP/port visible to the proxy via `getsockopt(SO_ORIGINAL_DST)`.
2.  **Connection Handling**: The proxy accepts the connection. To maintain transparency, it then creates a *new* outgoing socket, binds it to the original client's IP and port (using `IP_TRANSPARENT` socket option), and connects to the original destination IP/port. This makes the server see the connection as coming directly from the client.
3.  **Data Forwarding**: Data is read from both client and server sides.
4.  **Message Decoding**: A `PickleDecoder` attempts to decode messages from the raw byte stream. This decoder is basic and would need to be adapted to the specific protocol you are proxying.
5.  **Payload Processing**: Decoded messages are passed to `PayloadHandler`. Based on rules in `config.yaml`, actions like delaying, blocking, or data insertion are performed.
    *   `InsertDataAction`: Handles the logic for inserting data based on time delays, data types (bytes/hex), and position (before/after).
6.  **Data Writing**: Original or modified data is written to the respective peer.

## Disclaimer
This proxy is a proof-of-concept and includes basic error handling. For production use, it would require more robust error management, logging, and security considerations. The TPROXY setup can be complex and requires a good understanding of Linux networking.
The `PickleDecoder` is illustrative; using `pickle` for untrusted network data is insecure. Replace it with a proper protocol parser for your use case.