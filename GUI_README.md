# TCP Proxy Terminal GUI

This document describes how to use the terminal GUI for the TCP proxy.

## Overview

The terminal GUI provides a user-friendly interface for monitoring and controlling the transparent TCP proxy. It displays real-time information about connections, messages, and rule application, and allows you to manage rules without editing the config file directly.

## Starting the GUI

To start the TCP proxy with the GUI, use the `--gui` command-line argument:

```bash
python tcp_proxy.py --gui
```

You can also specify a custom config file:

```bash
python tcp_proxy.py --gui --config path/to/config.yaml
```

## GUI Layout

The GUI is divided into several panels:

1. **Message Log** (top left): Displays decoded messages passing through the proxy
2. **Connection Log** (top right): Shows connection events (new connections, closed connections)
3. **Statistics Panel** (bottom left): Shows counts of messages (total, blocked, delayed, replayed)
4. **Rule Management Panel** (bottom right): Allows viewing and editing rules

## Keyboard Shortcuts

- **q**: Quit the application
- **r**: Reload rules from the config file
- **c**: Clear logs

## Rule Management

The Rule Management panel allows you to view and edit rules without directly editing the config file.

### Block Rules

To add a block rule:
1. Enter the action name in the "Action to block" input field
2. Click "Add Block Rule"

### Delay Rules

To add a delay rule:
1. Enter the action name in the "Action to delay" input field
2. Enter the delay time in milliseconds in the "Delay (ms)" input field
3. Click "Add Delay Rule"

### Replay Rules

To add a replay rule:
1. Enter the action name in the "Action to replay" input field
2. Enter the number of times to replay in the "Count" input field
3. Click "Add Replay Rule"

After making changes, click "Save Rules" to apply them.

## Statistics

The Statistics panel shows:
- Total number of messages processed
- Number of blocked messages
- Number of delayed messages
- Number of replayed messages
- Number of active connections

## Logs

The Message Log and Connection Log panels display real-time information about the proxy's operation:

- **Message Log**: Shows decoded messages, including their content and direction (client to server or server to client)
- **Connection Log**: Shows connection events, such as new connections, closed connections, and status messages

## Requirements

The GUI requires the Textual library, which can be installed with:

```bash
pip install textual
```

## Troubleshooting

If you encounter issues with the GUI:

1. Make sure you have the Textual library installed
2. Check that you're running the proxy with the `--gui` argument
3. If the GUI doesn't display correctly, try resizing your terminal window
4. If you see errors about missing CSS files, make sure the `gui.css` file is in the same directory as `tcp_proxy.py`