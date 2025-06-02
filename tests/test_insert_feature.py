import unittest
import asyncio
import subprocess
import time
import yaml
import os
import socket

# This is a placeholder for integration tests.
# Actual implementation would require setting up the proxy, sending data,
# and capturing output, which can be complex in a generic environment.

class TestInsertFeatureIntegration(unittest.TestCase):

    PROXY_SCRIPT = os.path.join(os.path.dirname(__file__), '..', 'tcp_proxy.py')
    PROXY_HOST = "127.0.0.1"
    PROXY_PORT = 8889 # Using a distinct port for testing to avoid conflicts
    TARGET_SERVER_PORT = 9998 # Dummy target server port
    CONFIG_FILE_PATH = os.path.join(os.path.dirname(__file__),"temp_config_integration.yaml")
    PYTHON_EXEC = "python" # Or python3, depending on environment

    proxy_process = None
    dummy_server_socket = None


    @classmethod
    def setUpClass(cls):
        # Find python executable
        try:
            subprocess.check_output(["python3", "--version"])
            cls.PYTHON_EXEC = "python3"
        except FileNotFoundError:
            try:
                subprocess.check_output(["python", "--version"])
                cls.PYTHON_EXEC = "python"
            except FileNotFoundError:
                raise unittest.SkipTest("Python interpreter not found for integration tests.")
        except subprocess.CalledProcessError: # Handle cases where command exists but returns error
             try:
                subprocess.check_output(["python", "--version"])
                cls.PYTHON_EXEC = "python"
             except (FileNotFoundError, subprocess.CalledProcessError):
                raise unittest.SkipTest("Python interpreter not found or non-functional for integration tests.")
    
    def setUp(self):
        self.remove_temp_config() # Clean up from previous runs if any

    def tearDown(self):
        if self.proxy_process and self.proxy_process.poll() is None: # Check if process is running
            try:
                self.proxy_process.terminate()
                self.proxy_process.wait(timeout=5) # Wait for process to terminate
            except Exception as e:
                print(f"Error terminating proxy process: {e}")
                # Fallback to kill if terminate fails or times out
                if self.proxy_process.poll() is None:
                    self.proxy_process.kill()
                    self.proxy_process.wait(timeout=2)
            self.proxy_process = None
        
        if self.dummy_server_socket:
            try:
                self.dummy_server_socket.close()
            except Exception as e:
                print(f"Error closing dummy server socket: {e}")
            self.dummy_server_socket = None
        
        self.remove_temp_config()

    def remove_temp_config(self):
        if os.path.exists(self.CONFIG_FILE_PATH):
            try:
                os.remove(self.CONFIG_FILE_PATH)
            except Exception as e:
                print(f"Error removing temp config file: {e}")


    def create_temp_config_file(self, global_insert_rules=None, direction_rules=None):
        config_data = {
            "src": {"host": "0.0.0.0", "port": self.PROXY_PORT}, # Proxy listens on this
            "payload_handling": {
                "global": {"insert_data": global_insert_rules if isinstance(global_insert_rules, list) else []},
                "directions": direction_rules if direction_rules else {
                    # Example: Define a default forwarding if needed for your test setup
                    # "default_forward": {
                    # "source_ip": self.PROXY_HOST, # This might need to be the client's actual IP
                    # "target_ip": self.PROXY_HOST, # Target server IP
                    # "delay": [], "block": [], "insert_data": [] 
                    # }
                }
            }
        }
        # Ensure parent directory for config exists if it's nested, though here it's flat in 'tests/'
        os.makedirs(os.path.dirname(self.CONFIG_FILE_PATH), exist_ok=True)
        with open(self.CONFIG_FILE_PATH, "w") as f:
            yaml.dump(config_data, f)
        # print(f"Created temp config: {self.CONFIG_FILE_PATH} with content: {config_data}")
        return self.CONFIG_FILE_PATH

    def start_dummy_target_server(self):
        self.dummy_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.dummy_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.dummy_server_socket.bind((self.PROXY_HOST, self.TARGET_SERVER_PORT))
            self.dummy_server_socket.listen(1)
            # print(f"Dummy target server listening on {self.PROXY_HOST}:{self.TARGET_SERVER_PORT}")
        except Exception as e:
            print(f"Dummy server bind or listen failed on {self.PROXY_HOST}:{self.TARGET_SERVER_PORT}: {e}")
            if self.dummy_server_socket: self.dummy_server_socket.close()
            self.dummy_server_socket = None # Ensure it's None if setup fails
            raise # Re-raise the exception to fail the test early
        return self.dummy_server_socket


    def start_proxy(self):
        if not os.path.exists(self.CONFIG_FILE_PATH):
            raise FileNotFoundError(f"Proxy config file not found: {self.CONFIG_FILE_PATH}. Create it first.")

        if self.proxy_process and self.proxy_process.poll() is None:
            print("Proxy process already running. Terminating existing one.")
            self.proxy_process.terminate()
            self.proxy_process.wait(timeout=2)

        # Construct PYTHONPATH: current dir for utils, parent dir for tcp_proxy.py if tests is a subdir
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # up to 'TransparentTCPProxy'
        current_pythonpath = os.environ.get("PYTHONPATH", "")
        new_pythonpath = f".:{project_root}:{current_pythonpath}"
        
        env = os.environ.copy()
        env["PYTHONPATH"] = new_pythonpath
        env["CONFIG_PATH"] = self.CONFIG_FILE_PATH # Pass config path via env var if proxy supports it
                                                  # Alternatively, modify proxy to accept config path as CLI arg

        command = [self.PYTHON_EXEC, self.PROXY_SCRIPT, "--config", self.CONFIG_FILE_PATH]
        # If your proxy doesn't take --config, you'd need to ensure it loads CONFIG_FILE_PATH by default
        # or modify it. For now, assuming it can load from a fixed path or env var if not specified.
        # The provided tcp_proxy.py loads "config/config.yaml" by default.
        # For testing, we'd ideally pass the temp config path.
        # Let's modify PayloadHandler to accept config_path, and tcp_proxy.py to pass it if available.
        # This change is outside the scope of this current request, so we'll assume proxy loads default or
        # that we've manually pointed its default load path to our temp config for testing (hacky).
        # For a robust solution, tcp_proxy.py main() should accept a config path argument.
        # *Self-correction: The proxy script loads 'config/config.yaml'.
        # For integration tests, we should make the proxy load our temp_config_integration.yaml.
        # One way is to temporarily rename/move files, or better, modify proxy to accept config path.
        # Since I can't modify proxy now, test will rely on default loading path or require manual setup.
        # The PROXY_SCRIPT is in parent dir, so if CWD is tests/, it will look for ../config/config.yaml
        # This won't work unless we make PROXY_SCRIPT load self.CONFIG_FILE_PATH.
        # Let's assume for this skeleton that the proxy is modified to accept a config path argument.
        # If not, this start_proxy will need to use a fixed path that the proxy reads,
        # and create_temp_config_file would write to that fixed path.

        self.proxy_process = subprocess.Popen(
            command, # Assuming proxy.py is modified to take config path
            env=env,
            cwd=project_root, # Run proxy from project root
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        # print(f"Proxy starting with command: {' '.join(command)} in CWD: {project_root}")
        time.sleep(2.0) # Increased sleep for robust startup, especially on slower CI
        
        poll_result = self.proxy_process.poll()
        if poll_result is not None:
            stdout, stderr = self.proxy_process.communicate()
            raise Exception(
                f"Proxy process terminated prematurely (exit code {poll_result}).\n"
                f"Config: {self.CONFIG_FILE_PATH}\n"
                f"STDOUT: {stdout.decode(errors='ignore')}\n"
                f"STDERR: {stderr.decode(errors='ignore')}"
            )
        # print("Proxy started successfully.")


    @unittest.skip("Integration tests are placeholders and require careful environment setup, message crafting, and potentially proxy modification for config loading.")
    def test_example_integration_insert_before(self):
        # 1. Define rules
        action_name = "test_action_pickle" # This must match what PickleDecoder produces
        insert_data_content = "PREFIX::"
        original_message_content = "ThisIsTheMessage"
        
        # Assume PickleDecoder turns something like b"action:test_action_pickle\ndata:ThisIsTheMessage"
        # into {"action": "test_action_pickle", "some_data_field": "ThisIsTheMessage"}
        # The raw bytes sent must be constructable by your client and decodable by PickleDecoder.
        # For this example, let's assume a simple custom format for PickleDecoder for predictability.
        # e.g., PickleDecoder might expect: f"ACTION={action_name}\nDATA={original_message_content}".encode()
        
        raw_message_to_send = f"ACTION={action_name}\nDATA={original_message_content}".encode('utf-8')

        rules = [{
            "action": action_name, 
            "data": insert_data_content, 
            "data_type": "bytes", 
            "position": "before",
            "delay_sec": 0
        }]
        
        # 2. Create config and start proxy & server
        self.create_temp_config_file(global_insert_rules=rules)
        # IMPORTANT: This test assumes tcp_proxy.py is modified to accept a config path argument
        # or that its default config path is temporarily made to point to self.CONFIG_FILE_PATH
        self.start_proxy() 
        server_sock = self.start_dummy_target_server()
        
        client_sock = None
        conn = None

        try:
            # 3. Connect to proxy
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Client connects to the proxy's listening port
            client_sock.connect((self.PROXY_HOST, self.PROXY_PORT))
            
            # 4. Send data that triggers the rule
            client_sock.sendall(raw_message_to_send)
            
            # 5. Accept connection on dummy server and receive data
            # Server accepts connection that was proxied
            conn, addr = server_sock.accept() # This should be the connection from the proxy
            received_data = b""
            while True:
                part = conn.recv(1024)
                if not part:
                    break
                received_data += part
            
            # 6. Assert received data is as expected
            expected_data = insert_data_content.encode('utf-8') + raw_message_to_send
            self.assertEqual(received_data, expected_data, 
                             f"Expected '{expected_data!r}', got '{received_data!r}'")

        except socket.timeout:
            self.fail("Socket operation timed out.")
        except ConnectionRefusedError:
            self.fail(f"Connection refused. Is proxy running and forwarding to {self.PROXY_HOST}:{self.TARGET_SERVER_PORT}?")
        except Exception as e:
            self.fail(f"Integration test failed with exception: {e}")
        finally:
            if conn: conn.close()
            if client_sock: client_sock.close()
            # TearDown will handle proxy and server_sock cleanup

if __name__ == '__main__':
    print("Note: Integration tests are placeholders and marked as skipped.")
    # To run only unit tests for InsertDataAction:
    # python -m unittest tests.test_insert_data_action
    # To attempt running this integration test file (most tests will be skipped):
    # python -m unittest tests.test_insert_feature
    
    # For actual execution, you'd typically use a test runner:
    # python -m unittest discover -s tests 
    # (This would run all tests in the 'tests' directory)
```
