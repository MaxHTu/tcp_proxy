#!/usr/bin/env python3
"""
Test script for the TCP proxy GUI.
This script starts the proxy with the GUI and sends some test messages.
"""

import os
import sys
import time
import socket
import pickle
import struct
import subprocess
import argparse
from pathlib import Path

def send_pickle_message(sock, message):
    """Send a pickled message with length header."""
    # Pickle the message
    pickled_data = pickle.dumps(message)
    
    # Create a header with the message length
    header = struct.pack('>I', len(pickled_data))
    
    # Send the header and the pickled data
    sock.sendall(header + pickled_data)
    print(f"Sent message with action: {message.get('action', 'unknown')}")

def main():
    parser = argparse.ArgumentParser(description="Test the TCP proxy GUI")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=9000, help="Server port")
    args = parser.parse_args()

    # Start the proxy with GUI in a separate process
    proxy_process = None
    try:
        # Get the path to the tcp_proxy.py script
        repo_root = Path(__file__).parent.parent.absolute()
        proxy_script = repo_root / "tcp_proxy.py"
        
        # Start the proxy with GUI
        print("Starting TCP proxy with GUI...")
        proxy_process = subprocess.Popen(
            [sys.executable, str(proxy_script), "--gui"],
            cwd=str(repo_root)
        )
        
        # Wait for the proxy to start
        time.sleep(2)
        
        # Connect to the server
        print(f"Connecting to {args.host}:{args.port}...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((args.host, args.port))
            
            # Send test messages
            print("Sending test messages...")
            
            # Test message that should be blocked
            send_pickle_message(s, {
                "action": "update_tt_remote",
                "data": "This should be blocked"
            })
            time.sleep(1)
            
            # Test message that should be delayed
            send_pickle_message(s, {
                "action": "get_remote_time",
                "data": "This should be delayed"
            })
            time.sleep(1)
            
            # Test message that should be replayed
            send_pickle_message(s, {
                "action": "get_status",
                "data": "This should be replayed"
            })
            time.sleep(1)
            
            # Test normal message
            send_pickle_message(s, {
                "action": "normal_action",
                "data": "This should pass through normally"
            })
            time.sleep(1)
            
            print("All test messages sent. Check the GUI to see the results.")
            print("Press Ctrl+C to exit.")
            
            # Keep the connection open
            while True:
                time.sleep(1)
                
    except KeyboardInterrupt:
        print("\nTest script interrupted.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Clean up
        if proxy_process:
            print("Stopping TCP proxy...")
            proxy_process.terminate()
            proxy_process.wait()

if __name__ == "__main__":
    main()