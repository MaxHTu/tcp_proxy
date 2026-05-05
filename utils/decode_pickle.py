import builtins
import importlib
import io
import json
import pickle  # nosec B403 - restricted unpickler below limits allowed globals
import struct
from typing import Any, List, Optional, Tuple

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ModuleNotFoundError:
    class _DummyNdarray:
        pass

    class _DummyNumpy:
        ndarray = _DummyNdarray

    np = _DummyNumpy()  # type: ignore[assignment]
    NUMPY_AVAILABLE = False

from utils.contracts import MessageFrame


SAFE_BUILTIN_GLOBALS = {
    name: getattr(builtins, name)
    for name in (
        "bool",
        "bytearray",
        "bytes",
        "complex",
        "dict",
        "float",
        "frozenset",
        "int",
        "list",
        "set",
        "str",
        "tuple",
    )
}

SAFE_GLOBALS = {("builtins", name): value for name, value in SAFE_BUILTIN_GLOBALS.items()}


def _import_optional_module(module_name: str) -> Any:
    try:
        return importlib.import_module(module_name)
    except ImportError:
        return None


def _register_numpy_globals() -> None:
    if not NUMPY_AVAILABLE:
        return

    dtype = getattr(np, "dtype", None)
    ndarray = getattr(np, "ndarray", None)
    if dtype is not None:
        SAFE_GLOBALS[("numpy", "dtype")] = dtype
    if ndarray is not None:
        SAFE_GLOBALS[("numpy", "ndarray")] = ndarray

    for module_name in ("numpy.core.multiarray", "numpy._core.multiarray"):
        module = _import_optional_module(module_name)
        if module is None:
            continue
        reconstruct = getattr(module, "_reconstruct", None)
        if reconstruct is None:
            continue
        SAFE_GLOBALS[(module_name, "_reconstruct")] = reconstruct


_register_numpy_globals()


class RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that refuses globals outside the proxy's supported message types."""

    def find_class(self, module: str, name: str) -> Any:
        allowed = SAFE_GLOBALS.get((module, name))
        if allowed is not None:
            return allowed
        raise pickle.UnpicklingError(f"global '{module}.{name}' is not allowed")


def restricted_loads(data: bytes) -> Any:
    """Decode pickle bytes without allowing arbitrary class/function loading."""
    return RestrictedUnpickler(io.BytesIO(data)).load()


class PickleDecoder:
    """Incrementally decode length-prefixed payload frames from a TCP byte stream."""

    def __init__(self):
        self.buffer = bytearray()

    def add_data_frames(self, data: bytes) -> List[MessageFrame]:
        """Append bytes and return every complete frame currently buffered."""
        if not data:
            return []

        self.buffer.extend(data)
        frames: List[MessageFrame] = []

        while len(self.buffer) >= 4:
            msg_len = struct.unpack(">I", self.buffer[:4])[0]
            total_len = 4 + msg_len
            if len(self.buffer) < total_len:
                break

            raw_frame = bytes(self.buffer[:total_len])
            payload = bytes(self.buffer[4:total_len])
            del self.buffer[:total_len]

            decoded_msg, decode_error = self._decode_message_with_error(payload)
            frames.append(
                MessageFrame(
                    length_prefix=raw_frame[:4],
                    payload=payload,
                    raw_frame=raw_frame,
                    decoded=decoded_msg,
                    decode_error=decode_error,
                )
            )

        return frames

    def add_data(self, data: bytes) -> List[Tuple[Any, bytes]]:
        messages = []
        for frame in self.add_data_frames(data):
            messages.append((frame.decoded, frame.raw_frame))
        return messages

    def add_data_with_raw(self, data: bytes) -> List[Tuple[Any, str]]:
        messages = []
        for frame in self.add_data_frames(data):
            if frame.decode_error:
                formatted_output = f"Decode error: {frame.decode_error}"
            else:
                formatted_output = PickleDecoder.format_message(frame.decoded)
            messages.append((frame.decoded, formatted_output))
        return messages

    def get_buffer_info(self) -> str:
        if not self.buffer:
            return "Empty buffer"

        buffer_hex = self.buffer.hex()
        buffer_preview = buffer_hex[:100] + "..." if len(buffer_hex) > 100 else buffer_hex

        if len(self.buffer) >= 4:
            try:
                msg_len = struct.unpack(">I", self.buffer[:4])[0]
                return (
                    f"Buffer: {len(self.buffer)} bytes, Expected message length: {msg_len}, "
                    f"Preview: {buffer_preview}"
                )
            except Exception as exc:
                return (
                    f"Buffer: {len(self.buffer)} bytes, Error unpacking length: {exc}, "
                    f"Preview: {buffer_preview}"
                )

        return f"Buffer: {len(self.buffer)} bytes (insufficient for length header), Preview: {buffer_preview}"

    def _decode_message_with_error(self, msg_data: bytes) -> Tuple[Any, Optional[str]]:
        if msg_data.startswith(b"\x80\x04\x95"):
            try:
                # Network pickles remain risky; the restricted loader is the safety boundary.
                return restricted_loads(msg_data), None
            except Exception as exc:
                return None, f"pickle decode failed: {exc}"

        try:
            text = msg_data.decode("utf-8", errors="replace")
            if text.startswith("#"):
                return text, None
            return f"Text: {text}", None
        except UnicodeDecodeError:
            return f"Raw binary ({len(msg_data)} bytes)", None

    @staticmethod
    def format_message(msg: Any) -> str:
        if isinstance(msg, dict):
            formatted_dict = {}
            for key, value in msg.items():
                if isinstance(value, np.ndarray):
                    formatted_dict[key] = PickleDecoder.format_numpy_array(value)
                elif isinstance(value, dict):
                    nested_dict = {}
                    for nested_key, nested_value in value.items():
                        if isinstance(nested_value, np.ndarray):
                            nested_dict[nested_key] = PickleDecoder.format_numpy_array(nested_value)
                        else:
                            nested_dict[nested_key] = nested_value
                    formatted_dict[key] = nested_dict
                else:
                    formatted_dict[key] = value
            return json.dumps(formatted_dict, indent=2)
        if isinstance(msg, np.ndarray):
            return PickleDecoder.format_numpy_array(msg)
        return str(msg)

    @staticmethod
    def format_numpy_array(arr: np.ndarray) -> str:
        if arr.size > 6:
            return f"array([{', '.join(map(str, arr[:3]))}, ..., {', '.join(map(str, arr[-3:]))}], dtype={arr.dtype})"
        return f"array({arr.tolist()}, dtype={arr.dtype})"
