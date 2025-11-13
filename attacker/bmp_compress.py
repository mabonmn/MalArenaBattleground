#!/usr/bin/env python3
"""
bmp_compress.py

Usage:
  # Lossless PNG
  python bmp_compress.py png  input.bmp  output.png

  # Native reversible container (zlib-compressed planar RGB)
  python bmp_compress.py native  input.bmp  output.rbz

  # Native uncompressed planar RGB container (no zlib, good for systems without zlib)
  python bmp_compress.py native_uncompressed  input.bmp  output.rbz

Notes:
- Forces 24-bit RGB (no alpha), arbitrary dimensions are supported.
- Native format layout (header):
    magic: 4 bytes = b'RBZ1'
    width:  uint32 little-endian
    height: uint32 little-endian
    version: uint8 (1)
    channels: uint8 (3)
    reserved: 2 bytes = 0
    uncompressed_size: uint32 (R|G|B planar bytes len)
    compressed_size:   uint32
    payload: if compressed_size > 0, zlib-compressed bytes of [R-plane][G-plane][B-plane]
             if compressed_size == 0, raw bytes of [R-plane][G-plane][B-plane]
- The native_uncompressed mode avoids zlib entirely and is trivial to decode from C++.
"""

import struct
import sys
import zlib
from PIL import Image


def load_rgb24(path: str):
    im = Image.open(path)
    # Force 24-bit RGB (drop alpha if present)
    if im.mode != "RGB":
        im = im.convert("RGB")
    w, h = im.size
    rgb = im.tobytes()  # interleaved RGBRGB...
    return w, h, rgb


def save_png_lossless(input_bmp: str, output_png: str):
    w, h, rgb = load_rgb24(input_bmp)
    im = Image.frombytes("RGB", (w, h), rgb)
    # Pillow PNG save is lossless by default; set optimize to reduce size.
    im.save(output_png, format="PNG", optimize=True, compress_level=9)


def save_native_container(input_bmp: str, output_rbz: str, level: int = 9):
    """zlib-compressed RBZ (original behavior)."""
    w, h, rgb = load_rgb24(input_bmp)
    n = w * h

    # Split interleaved RGB to planar R|G|B for better compressibility
    r = bytearray(n)
    g = bytearray(n)
    b = bytearray(n)
    src = memoryview(rgb)
    r[:] = src[0::3]
    g[:] = src[1::3]
    b[:] = src[2::3]

    planar = bytes(r) + bytes(g) + bytes(b)
    comp = zlib.compress(planar, level)

    header = struct.pack(
        "<4sIIBB2sII",
        b"RBZ1",        # magic
        w,
        h,
        1,              # version
        3,              # channels
        b"\x00\x00",    # reserved
        len(planar),
        len(comp),
    )

    with open(output_rbz, "wb") as f:
        f.write(header)
        f.write(comp)


def save_native_uncompressed(input_bmp: str, output_rbz: str):
    """Uncompressed RBZ: payload is raw planar RGB bytes. No zlib required."""
    w, h, rgb = load_rgb24(input_bmp)
    n = w * h

    r = bytearray(n)
    g = bytearray(n)
    b = bytearray(n)
    src = memoryview(rgb)
    r[:] = src[0::3]
    g[:] = src[1::3]
    b[:] = src[2::3]

    planar = bytes(r) + bytes(g) + bytes(b)
    ulen = len(planar)
    clen = 0  # 0 signals "no compression" in our reader

    header = struct.pack(
        "<4sIIBB2sII",
        b"RBZ1",        # magic
        w,
        h,
        1,              # version
        3,              # channels
        b"\x00\x00",    # reserved
        ulen,
        clen,
    )

    with open(output_rbz, "wb") as f:
        f.write(header)
        f.write(planar)


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ("png", "native", "native_uncompressed"):
        print(__doc__)
        sys.exit(1)

    mode, inp, out = sys.argv[1], sys.argv[2], sys.argv[3]
    if mode == "png":
        save_png_lossless(inp, out)
    elif mode == "native":
        save_native_container(inp, out)
    else:
        save_native_uncompressed(inp, out)


if __name__ == "__main__":
    main()
