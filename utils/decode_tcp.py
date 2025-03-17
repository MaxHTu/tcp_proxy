import pickle
from io import BytesIO
import numpy as np
import json
from typing import Any, List, Optional
import argparse

def format_numpy_array(arr: np.ndarray) -> str:
    if arr.size > 6:
        return f"array([{', '.join(map(str, arr[:3]))}, ..., {', '.join(map(str, arr[-3:]))}], dtype={arr.dtype})"
    return f"array({arr.tolist()}, dtype={arr.dtype})"

def format_message(msg: Any) -> str:
    if isinstance(msg, dict):
        formatted_dict = {}
        for k, v in msg.items():
            if isinstance(v, np.ndarray):
                formatted_dict[k] = format_numpy_array(v)
            elif isinstance(v, dict):
                nested_dict = {}
                for nk, nv in v.items():
                    if isinstance(nv, np.ndarray):
                        nested_dict[nk] = format_numpy_array(nv)
                    else:
                        nested_dict[nk] = nv
                formatted_dict[k] = nested_dict
            else:
                formatted_dict[k] = v
        return json.dumps(formatted_dict, indent=2)
    elif isinstance(msg, np.ndarray):
        return format_numpy_array(msg)
    return str(msg)

def decode_tcp_message(hex_dump: str) -> List[Any]:
    hex_bytes = []
    for line in hex_dump.split('\n'):
        if not line.strip():
            continue

        try:
            hex_part = line.split('   ')[0]
            if hex_part.startswith('0'):
                hex_part = hex_part.split(' ', 1)[1]

            clean_bytes = []
            for b in hex_part.strip().split():
                if len(b) == 2 and all(c in '0123456789abcdefABCDEF' for c in b):
                    clean_bytes.append(b)
            hex_bytes.extend(clean_bytes)
        except (IndexError, ValueError):
            continue

    print(f"Cleaned hex bytes: {' '.join(hex_bytes[:32])}...")

    try:
        raw_data = bytes.fromhex(''.join(hex_bytes))
    except ValueError as e:
        print(f"Error parsing hex: {e}")
        return []

    messages = []
    stream = BytesIO(raw_data)

    while True:
        try:
            length_bytes = stream.read(4)
            if not length_bytes:
                break

            msg_len = int.from_bytes(length_bytes, 'big')
            msg_data = stream.read(msg_len)

            #pickle data strats with: \x80\x04\x95
            if msg_data.startswith(b'\x80\x04\x95'):
                try:
                    decoded = pickle.loads(msg_data)
                    messages.append(decoded)
                except Exception as e:
                    messages.append(f"Failed to decode pickle: {e}")
            else:
                try:
                    text = msg_data.decode('ascii', errors='ignore')
                    messages.append(text)
                except:
                    messages.append(f"Raw binary ({len(msg_data)} bytes)")
        except Exception as e:
            print(f"Error processing message: {e}")
            break

    return messages

def decode_tcp_stream_file(filename: str) -> List[Any]:
    with open(filename, 'r') as f:
        hex_dump = f.read()

    messages = decode_tcp_message(hex_dump)

    for i, msg in enumerate(messages, 1):
        print(f"\nMessage {i}:")
        print(format_message(msg))

    return messages

def save_decoded_messages_json(messages: List[Any], output_file: str, limit: Optional[int] = None) -> None:
    formatted_messages = {}
    for i, msg in enumerate(messages[:limit] if limit else messages, 1):
        key = f"Message {i}"
        if isinstance(msg, (dict, np.ndarray)):
            formatted_messages[key] = json.loads(format_message(msg))
        else:
            formatted_messages[key] = str(msg)

    with open(output_file, 'w') as f:
        json.dump(formatted_messages, indent=2, fp=f)

def save_decoded_messages_txt(messages: List[Any], output_file: str, limit: Optional[int] = None) -> None:
    with open(output_file, 'w') as f:
        for i, msg in enumerate(messages[:limit] if limit else messages, 1):
            f.write(f"Message {i}:\n")
            f.write("-" * 80 + "\n")

            if isinstance(msg, (dict, np.ndarray)):
                formatted = format_message(msg)
                formatted = "\n".join("    " + line for line in formatted.split("\n"))
                f.write(formatted)
            else:
                f.write(f"    {str(msg)}")

            f.write("\n\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Decode TCP stream files')
    parser.add_argument('file', help='Input TCP stream file')
    parser.add_argument('--limit', type=int, help='Limit number of messages to process')
    parser.add_argument('--format', choices=['json', 'txt', 'both'], default='json',
                      help='Output format (default: both)')
    args = parser.parse_args()

    messages = decode_tcp_stream_file(args.file)

    if args.format in ['json', 'both']:
        save_decoded_messages_json(messages, f"decoded_{args.file}.json", args.limit)
    if args.format in ['txt', 'both']:
        save_decoded_messages_txt(messages, f"decoded_{args.file}.txt", args.limit)