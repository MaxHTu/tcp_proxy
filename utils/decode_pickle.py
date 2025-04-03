import pickle
import struct
import numpy as np
from typing import Any, List, Optional
import json


class PickleDecoder:
    def __init__(self):
        self.buffer = bytearray()

    def add_data(self, data: bytes) -> List[str]:
        if not data: # Handle empty chunks if they occur
            return []

        self.buffer.extend(data)
        messages = []

        while len(self.buffer) > 4:
            msg_len = struct.unpack('>I', self.buffer[:4])[0]
            if len(self.buffer) >= 4 + msg_len:
                payload = self.buffer[4: 4 + msg_len]
                del self.buffer[:4 + msg_len]
                decoded_msg = self.decode_message(payload)
                formatted_output = PickleDecoder.format_message(decoded_msg)
                messages.append(formatted_output)
            else:
                break
        return messages

    def decode_message(self, msg_data: bytes) -> Any:
        if msg_data.startswith(b'\x80\x04\x95'):
            try:
                return pickle.loads(msg_data)
            except Exception as e:
                return f"Failed to decode pickle: {e}"
        else:
            try:
                return msg_data.decode('ascii', errors='ignore')
            except UnicodeDecodeError:
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
