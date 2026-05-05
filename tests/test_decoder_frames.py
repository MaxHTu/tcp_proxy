import pickle

from utils.decode_pickle import PickleDecoder


def encode_frame(message):
    payload = pickle.dumps(message, protocol=4)
    return len(payload).to_bytes(4, "big") + payload


def test_frame_assembly_with_segmented_data_and_trailing_partial():
    decoder = PickleDecoder()

    frame1 = encode_frame({"action": "a", "value": 1})
    frame2 = encode_frame({"action": "b", "value": 2})
    frame3 = encode_frame({"action": "c", "value": 3})

    chunk1 = frame1[:2]
    chunk2 = frame1[2:] + frame2 + frame3[:5]

    assert decoder.add_data_frames(chunk1) == []

    frames = decoder.add_data_frames(chunk2)
    assert len(frames) == 2
    assert frames[0].decoded["action"] == "a"
    assert frames[1].decoded["action"] == "b"
    assert len(decoder.buffer) == 5


def test_decode_error_is_captured_without_dropping_frame():
    decoder = PickleDecoder()
    broken_payload = b"\x80\x04\x95\x01\x00\x00\x00\x00\x00\x00\x00x"
    frame = len(broken_payload).to_bytes(4, "big") + broken_payload

    frames = decoder.add_data_frames(frame)
    assert len(frames) == 1
    assert frames[0].decoded is None
    assert frames[0].decode_error is not None


def test_non_pickle_text_decodes_to_text_string():
    decoder = PickleDecoder()
    payload = b"hello"
    frame = len(payload).to_bytes(4, "big") + payload

    frames = decoder.add_data_frames(frame)
    assert len(frames) == 1
    assert frames[0].decode_error is None
    assert frames[0].decoded == "Text: hello"


def test_restricted_unpickler_rejects_unsafe_globals():
    class DangerousPayload:
        def __reduce__(self):
            return (eval, ("1 + 1",))

    decoder = PickleDecoder()
    payload = pickle.dumps(DangerousPayload(), protocol=4)
    frame = len(payload).to_bytes(4, "big") + payload

    frames = decoder.add_data_frames(frame)
    assert len(frames) == 1
    assert frames[0].decoded is None
    assert "not allowed" in frames[0].decode_error
