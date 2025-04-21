import asyncio
import yaml
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, Log, Button, Input, Label
from textual.reactive import reactive
from textual import events
from textual.binding import Binding
import time
from typing import Dict, List, Any, Optional, Tuple

class MessageLog(Log):
    """A log widget for displaying decoded messages."""
    pass

class ConnectionLog(Log):
    """A log widget for displaying connection events."""
    pass

class StatisticsPanel(Static):
    """A panel for displaying proxy statistics."""
    total_messages = reactive(0)
    blocked_messages = reactive(0)
    delayed_messages = reactive(0)
    replayed_messages = reactive(0)
    active_connections = reactive(0)

    def compose(self) -> ComposeResult:
        yield Static("Statistics", classes="panel-title")
        yield Static(id="total-messages")
        yield Static(id="blocked-messages")
        yield Static(id="delayed-messages")
        yield Static(id="replayed-messages")
        yield Static(id="active-connections")

    def on_mount(self) -> None:
        self.update_statistics()

    def watch_total_messages(self, total_messages: int) -> None:
        self.update_statistics()

    def watch_blocked_messages(self, blocked_messages: int) -> None:
        self.update_statistics()

    def watch_delayed_messages(self, delayed_messages: int) -> None:
        self.update_statistics()

    def watch_replayed_messages(self, replayed_messages: int) -> None:
        self.update_statistics()

    def watch_active_connections(self, active_connections: int) -> None:
        self.update_statistics()

    def update_statistics(self) -> None:
        self.query_one("#total-messages", Static).update(f"Total Messages: {self.total_messages}")
        self.query_one("#blocked-messages", Static).update(f"Blocked Messages: {self.blocked_messages}")
        self.query_one("#delayed-messages", Static).update(f"Delayed Messages: {self.delayed_messages}")
        self.query_one("#replayed-messages", Static).update(f"Replayed Messages: {self.replayed_messages}")
        self.query_one("#active-connections", Static).update(f"Active Connections: {self.active_connections}")

class RulePanel(Static):
    """A panel for displaying and editing proxy rules."""

    def compose(self) -> ComposeResult:
        yield Static("Rules", classes="panel-title")

        # Block Rules Section
        yield Static("Block Rules:", classes="section-title")
        yield Horizontal(
            Input(placeholder="Action to block", id="block-action-input"),
            Button("Add Block Rule", id="add-block-rule"),
            classes="rule-input"
        )
        yield Static(id="block-rules-list")

        # Delay Rules Section
        yield Static("Delay Rules:", classes="section-title")
        yield Horizontal(
            Input(placeholder="Action to delay", id="delay-action-input"),
            Input(placeholder="Delay (ms)", id="delay-ms-input"),
            Button("Add Delay Rule", id="add-delay-rule"),
            classes="rule-input"
        )
        yield Static(id="delay-rules-list")

        # Replay Rules Section
        yield Static("Replay Rules:", classes="section-title")
        yield Horizontal(
            Input(placeholder="Action to replay", id="replay-action-input"),
            Input(placeholder="Count", id="replay-count-input"),
            Button("Add Replay Rule", id="add-replay-rule"),
            classes="rule-input"
        )
        yield Static(id="replay-rules-list")

        # Save Button
        yield Button("Save Rules", id="save-rules")

    def on_mount(self) -> None:
        self.load_rules()

    def load_rules(self) -> None:
        """Load rules from config file and display them."""
        try:
            with open("config/config.yaml", "r") as f:
                config = yaml.safe_load(f)

            payload_handling = config.get("payload_handling", {})

            # Display block rules
            block_config = payload_handling.get("block", {})
            block_action = block_config.get("action", "")
            block_rules_text = f"• {block_action}" if block_action else "No block rules"
            self.query_one("#block-rules-list", Static).update(block_rules_text)

            # Display delay rules
            delay_config = payload_handling.get("delay", {})
            delay_action = delay_config.get("action", "")
            delay_ms = delay_config.get("delay_ms", 0)
            delay_rules_text = f"• {delay_action} ({delay_ms} ms)" if delay_action else "No delay rules"
            self.query_one("#delay-rules-list", Static).update(delay_rules_text)

            # Display replay rules
            replay_config = payload_handling.get("replay", {})
            replay_action = replay_config.get("action", "")
            replay_count = replay_config.get("count", 0)
            replay_rules_text = f"• {replay_action} ({replay_count} times)" if replay_action else "No replay rules"
            self.query_one("#replay-rules-list", Static).update(replay_rules_text)

        except Exception as e:
            self.app.message_log.write_line(f"Error loading rules: {e}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses for rule management."""
        button_id = event.button.id

        if button_id == "add-block-rule":
            block_action = self.query_one("#block-action-input", Input).value
            if block_action:
                self.update_rule("block", {"action": block_action})
                self.query_one("#block-action-input", Input).value = ""

        elif button_id == "add-delay-rule":
            delay_action = self.query_one("#delay-action-input", Input).value
            delay_ms_str = self.query_one("#delay-ms-input", Input).value

            try:
                delay_ms = int(delay_ms_str) if delay_ms_str else 0
                if delay_action and delay_ms > 0:
                    self.update_rule("delay", {"action": delay_action, "delay_ms": delay_ms})
                    self.query_one("#delay-action-input", Input).value = ""
                    self.query_one("#delay-ms-input", Input).value = ""
            except ValueError:
                self.app.message_log.write_line("Delay must be a valid integer")

        elif button_id == "add-replay-rule":
            replay_action = self.query_one("#replay-action-input", Input).value
            replay_count_str = self.query_one("#replay-count-input", Input).value

            try:
                replay_count = int(replay_count_str) if replay_count_str else 0
                if replay_action and replay_count > 0:
                    self.update_rule("replay", {"action": replay_action, "count": replay_count})
                    self.query_one("#replay-action-input", Input).value = ""
                    self.query_one("#replay-count-input", Input).value = ""
            except ValueError:
                self.app.message_log.write_line("Count must be a valid integer")

        elif button_id == "save-rules":
            self.save_rules()

    def update_rule(self, rule_type: str, rule_data: Dict[str, Any]) -> None:
        """Update a rule in memory."""
        try:
            with open("config/config.yaml", "r") as f:
                config = yaml.safe_load(f)

            if "payload_handling" not in config:
                config["payload_handling"] = {}

            config["payload_handling"][rule_type] = rule_data

            with open("config/config.yaml", "w") as f:
                yaml.dump(config, f, default_flow_style=False)

            self.load_rules()
            self.app.message_log.write_line(f"Updated {rule_type} rule: {rule_data}")
        except Exception as e:
            self.app.message_log.write_line(f"Error updating rule: {e}")

    def save_rules(self) -> None:
        """Save all rules to the config file."""
        try:
            with open("config/config.yaml", "r") as f:
                config = yaml.safe_load(f)

            # The rules are already saved when updated, so we just need to notify the user
            self.app.message_log.write_line("Rules saved successfully")

            # Signal the proxy to reload the rules
            self.app.reload_rules_requested = True
        except Exception as e:
            self.app.message_log.write_line(f"Error saving rules: {e}")

class ProxyGUI(App):
    """A terminal GUI for the TCP proxy."""
    CSS_PATH = "gui.css"
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "reload_rules", "Reload Rules"),
        Binding("c", "clear_logs", "Clear Logs"),
    ]

    message_log: MessageLog
    connection_log: ConnectionLog
    statistics: StatisticsPanel
    rule_panel: RulePanel
    reload_rules_requested: bool = False

    def __init__(self, proxy_queue: asyncio.Queue, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.proxy_queue = proxy_queue
        self.proxy_task = None

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header()
        yield Container(
            Horizontal(
                Vertical(
                    Static("Message Log", classes="panel-title"),
                    MessageLog(id="message-log", highlight=True),
                    classes="left-panel"
                ),
                Vertical(
                    Static("Connection Log", classes="panel-title"),
                    ConnectionLog(id="connection-log", highlight=True),
                    classes="right-panel"
                ),
                id="top-container"
            ),
            Horizontal(
                StatisticsPanel(id="statistics-panel", classes="stats-panel"),
                RulePanel(id="rule-panel", classes="rule-panel"),
                id="bottom-container"
            ),
            id="main-container"
        )
        yield Footer()

    def on_mount(self) -> None:
        """Set up the application on mount."""
        self.message_log = self.query_one("#message-log", MessageLog)
        self.connection_log = self.query_one("#connection-log", ConnectionLog)
        self.statistics = self.query_one("#statistics-panel", StatisticsPanel)
        self.rule_panel = self.query_one("#rule-panel", RulePanel)

        # Start the task to process messages from the proxy
        self.proxy_task = asyncio.create_task(self.process_proxy_messages())

    async def process_proxy_messages(self) -> None:
        """Process messages from the proxy queue."""
        while True:
            try:
                message = await self.proxy_queue.get()
                message_type = message.get("type", "")

                if message_type == "message":
                    # Display decoded message
                    direction = message.get("direction", "")
                    content = message.get("content", "")
                    self.message_log.write_line(f"[{direction}] {content}")
                    self.statistics.total_messages += 1

                elif message_type == "connection":
                    # Display connection event
                    event_type = message.get("event", "")
                    details = message.get("details", "")
                    self.connection_log.write_line(f"[{event_type}] {details}")

                    if event_type == "new":
                        self.statistics.active_connections += 1
                    elif event_type == "closed":
                        self.statistics.active_connections = max(0, self.statistics.active_connections - 1)

                elif message_type == "block":
                    # Display blocked message
                    action = message.get("action", "")
                    self.message_log.write_line(f"[BLOCK] Blocking message with action: {action}")
                    self.statistics.blocked_messages += 1

                elif message_type == "delay":
                    # Display delayed message
                    action = message.get("action", "")
                    delay_ms = message.get("delay_ms", 0)
                    self.message_log.write_line(f"[DELAY] Delayed message with action: {action} ({delay_ms} ms)")
                    self.statistics.delayed_messages += 1

                elif message_type == "replay":
                    # Display replayed message
                    action = message.get("action", "")
                    count = message.get("count", 0)
                    self.message_log.write_line(f"[REPLAY] Replaying message with action: {action} ({count} times)")
                    self.statistics.replayed_messages += count

                elif message_type == "error":
                    # Display error message
                    error = message.get("error", "")
                    self.message_log.write_line(f"[ERROR] {error}")

                elif message_type == "status":
                    # Display status message
                    status = message.get("status", "")
                    self.connection_log.write_line(f"[STATUS] {status}")

                self.proxy_queue.task_done()

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.message_log.write_line(f"Error processing message: {e}")

    def action_reload_rules(self) -> None:
        """Reload rules from the config file."""
        self.rule_panel.load_rules()
        self.message_log.write_line("Rules reloaded")
        self.reload_rules_requested = True

    def action_clear_logs(self) -> None:
        """Clear all logs."""
        self.message_log.clear()
        self.connection_log.clear()
        self.message_log.write_line("Logs cleared")

    def on_unmount(self) -> None:
        """Clean up when the app is unmounted."""
        if self.proxy_task:
            self.proxy_task.cancel()

# This function will be called from tcp_proxy.py to start the GUI
async def start_gui(proxy_queue: asyncio.Queue) -> None:
    """Start the terminal GUI."""
    app = ProxyGUI(proxy_queue)
    await app.run_async()
