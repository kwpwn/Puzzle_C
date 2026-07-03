"""XOR encrypt/decrypt a file with a repeating key.

Usage: python xor_file.py <input> <key> <output>

The same command decrypts (XOR is symmetric).
"""
import sys

def xor_bytes(data, key_bytes):
    out = bytearray(len(data))
    k = len(key_bytes)
    for i, b in enumerate(data):
        out[i] = b ^ key_bytes[i % k]
    return out

def main():
    if len(sys.argv) != 4:
        print("Usage: python xor_file.py <input.bin> <key> <output.bin>")
        sys.exit(1)

    in_path, key_str, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    key = key_str.encode("utf-8")

    if not key:
        print("Empty key not allowed.")
        sys.exit(1)

    with open(in_path, "rb") as f:
        data = f.read()

    enc = xor_bytes(data, key)

    with open(out_path, "wb") as f:
        f.write(enc)

    print(f"[+] {len(data)} bytes processed -> {out_path}")

if __name__ == "__main__":
    main()
