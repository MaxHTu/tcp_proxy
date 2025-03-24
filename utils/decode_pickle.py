import pickle
import numpy as np


class Decoder:
    def __init__(self):
        self.buffer = bytearray()

    def decode_mes(self