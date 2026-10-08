"""Rewrites a tracev3 file's chunksets as LZBITMAP, with Apple's own
compressor (macOS's libcompression): the LZ4 chunksets are decompressed,
then compressed again with LZBITMAP; every other chunk is kept.

usage (macOS only): python3 -I lzbitmap.py in.tracev3 out.tracev3
"""

import ctypes
import struct
import sys

LZ4 = 0x100
LZBITMAP = 0x702
CHUNKSET = 0x600D

LIB = ctypes.CDLL("/usr/lib/libcompression.dylib")
for function in (LIB.compression_encode_buffer, LIB.compression_decode_buffer):
    function.restype = ctypes.c_size_t
    function.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                         ctypes.c_void_p, ctypes.c_int]


def run(function, data, algorithm, size):
    out = ctypes.create_string_buffer(size)
    written = function(out, size, data, len(data), None, algorithm)
    if written == 0:
        raise ValueError("libcompression failed")
    return out.raw[:written]


def padding(size):
    return (8 - size % 8) % 8


def main():
    data = open(sys.argv[1], "rb").read()
    out = bytearray()
    at = 0
    while at + 16 <= len(data):
        tag, sub_tag, size = struct.unpack_from("<IIQ", data, at)
        body = data[at + 16:at + 16 + size]
        if tag == CHUNKSET:
            plain = run(LIB.compression_decode_buffer, body, LZ4, 1 << 22)
            body = run(LIB.compression_encode_buffer, plain, LZBITMAP, 2 * len(plain) + 4096)
        out += struct.pack("<IIQ", tag, sub_tag, len(body)) + body
        out += b"\0" * padding(len(out))
        at += 16 + size
        at += padding(at)
    open(sys.argv[2], "wb").write(out)


if __name__ == "__main__":
    main()
