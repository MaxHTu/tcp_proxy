import pickle
import struct
import numpy as np
from typing import Any, List, Optional, Tuple
import json


class PickleDecoder:
    def __init__(self):
        self.buffer = bytearray()

    def add_data(self, data: bytes) -> List[Tuple[Any, bytes]]:
        print(f"[DEBUG] add_data received {len(data) if data else 0} bytes")
        if not data:
            print("[DEBUG] No data received, returning empty list")
            return []

        self.buffer.extend(data)
        messages = []

        while len(self.buffer) > 4:
            msg_len = struct.unpack('>I', self.buffer[:4])[0]
            if len(self.buffer) >= 4 + msg_len:
                full_message = self.buffer[:4 + msg_len]
                payload = self.buffer[4:4 + msg_len]
                del self.buffer[:4 + msg_len]
                decoded_msg = self.decode_message(payload)

                messages.append((decoded_msg, full_message))
            else:
                break
        print(f"[DEBUG] add_data returning {len(messages)} messages")
        if not messages:
            print(f"[DEBUG] Buffer state: {self.get_buffer_info()}")

        return messages

    def get_buffer_info(self) -> str:
        if not self.buffer:
            return "Empty buffer"

        buffer_hex = self.buffer.hex()
        buffer_preview = buffer_hex[:100] + "..." if len(buffer_hex) > 100 else buffer_hex

        if len(self.buffer) >= 4:
            try:
                msg_len = struct.unpack('>I', self.buffer[:4])[0]
                return f"Buffer: {len(self.buffer)} bytes, Expected message length: {msg_len}, Preview: {buffer_preview}"
            except Exception as e:
                return f"Buffer: {len(self.buffer)} bytes, Error unpacking length: {e}, Preview: {buffer_preview}"
        else:
            return f"Buffer: {len(self.buffer)} bytes (insufficient for length header), Preview: {buffer_preview}"

    def decode_message(self, msg_data: bytes) -> Any:
        print(f"[DEBUG] decode_message received {len(msg_data)} bytes starting with {msg_data[:10].hex()}")
        if msg_data.startswith(b'\x80\x04\x95'):
            try:
                return pickle.loads(msg_data)
            except Exception as e:
                print(f"[DEBUG] Pickle decode error: {e}, data: {msg_data[:50].hex()}")
                return f"Failed to decode pickle: {e}"
        else:
            try:
                text = msg_data.decode('utf-8', errors='replace')
                if text.startswith('#'):
                    return text
                else:
                    return f"Text: {text}"
            except UnicodeDecodeError:
                print(f"[DEBUG] Binary data: {msg_data[:50].hex()}")
                return f"Raw binary ({len(msg_data)} bytes)"

    @staticmethod
    def format_message(msg: Any) -> str:
        if isinstance(msg, dict):
            formatted_dict = {}
            for k, v in msg.items():
                if isinstance(v, np.ndarray):
                    formatted_dict[k] = PickleDecoder.format_numpy_array(v)
                elif isinstance(v, dict):
                    nested_dict = {}
                    for nk, nv in v.items():
                        if isinstance(nv, np.ndarray):
                            nested_dict[nk] = PickleDecoder.format_numpy_array(nv)
                        else:
                            nested_dict[nk] = nv
                    formatted_dict[k] = nested_dict
                else:
                    formatted_dict[k] = v
            return json.dumps(formatted_dict, indent=2)
        elif isinstance(msg, np.ndarray):
            return PickleDecoder.format_numpy_array(msg)
        return str(msg)

    @staticmethod
    def format_numpy_array(arr: np.ndarray) -> str:
        if arr.size > 6:
            return f"array([{', '.join(map(str, arr[:3]))}, ..., {', '.join(map(str, arr[-3:]))}], dtype={arr.dtype})"
        return f"array({arr.tolist()}, dtype={arr.dtype})"
