"""Extract the SHA-1 resource hash from a WIM file.

Usage: python get_wim_hash.py <wim_path> <image> <internal_path>

Requires wimlib-imagex (Linux: sudo apt install wimtools).
On Windows, use: Get-FileHash -Algorithm SHA1 -Path <original_file>
"""
import subprocess, sys, os, re, uuid

WIMLIB_EXE = "wimlib-imagex"

WIM_MAGIC = b"MSWIM\x00\x00\x00"
WIM_GUID_OFFSET = 0x18
WIM_GUID_SIZE = 16

def get_wim_guid(wim_path):
    if not os.path.exists(wim_path):
        raise FileNotFoundError(f"WIM not found: {wim_path}")
    with open(wim_path, "rb") as f:
        hdr = f.read(208)
    if len(hdr) < 208:
        raise RuntimeError("File too small to be a WIM.")
    if hdr[:8] != WIM_MAGIC:
        raise RuntimeError("Not a WIM: magic != MSWIM.")
    guid_le = hdr[WIM_GUID_OFFSET:WIM_GUID_OFFSET + WIM_GUID_SIZE]
    return str(uuid.UUID(bytes_le=guid_le))

def get_wim_file_sha1(wim_path, image, internal_path, wimlib_exe=WIMLIB_EXE):
    if not os.path.exists(wim_path):
        raise FileNotFoundError(f"WIM not found: {wim_path}")
    internal_path = internal_path.replace("\\", "/")
    if not internal_path.startswith("/"):
        internal_path = "/" + internal_path
    cmd = [
        wimlib_exe, "dir", wim_path, str(image),
        f"--path={internal_path}", "--detailed", "--one-file-only",
    ]
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
        )
    except FileNotFoundError:
        raise RuntimeError(
            f"'{wimlib_exe}' not found. "
            "Install wimlib (e.g. 'sudo apt install wimtools')."
        )
    if proc.returncode != 0:
        raise RuntimeError(
            f"wimlib-imagex dir failed (rc={proc.returncode}).\n"
            f"STDERR:\n{proc.stderr}"
        )
    for line in proc.stdout.splitlines():
        m = re.search(r"\b([0-9a-fA-F]{40})\b", line)
        if m:
            return m.group(1).lower()
    raise ValueError(f"No SHA-1 found in output.\n{proc.stdout}")

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) != 3:
        print(
            "Usage:\n"
            "  python3 get_wim_hash.py <wim_path> <image> <internal_path>\n\n"
            "Examples:\n"
            "  python3 get_wim_hash.py payload.wim 1 hello.txt\n"
            "  python3 get_wim_hash.py payload.wim 'TestWOF' malware.exe\n",
            file=sys.stderr,
        )
        sys.exit(1)
    wim_path, image, internal_path = argv
    try:
        image = int(image)
    except ValueError:
        pass
    print(get_wim_guid(wim_path))
    print(get_wim_file_sha1(wim_path, image, internal_path))

if __name__ == "__main__":
    main()
