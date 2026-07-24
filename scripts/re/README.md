# `scripts/re/` — reverse-engineering tools for the game exe

Small capstone/pefile scripts used to locate the in-game music engine inside
`METAL GEAR SOLID2.exe`. See `docs/EXE_REVERSE.md` for the findings and the map
of addresses; this folder is just the tooling.

These contain **no game data** — only analysis code. They read the exe on the
dev machine in place and print addresses/disassembly.

## Requirements

```bash
pip install capstone pefile
```

## The exe must be un-packed first

The retail exe is SteamStub-DRM-packed: its code section is encrypted on disk, so
static analysis sees only garbage. Unpack it (e.g. with **Steamless**) to get
`METAL GEAR SOLID2.exe.unpacked.exe`, and point the scripts at that file. Each
script has the path near the top:

```python
EXE = r"C:\Games\Steam\steamapps\common\MGS2\METAL GEAR SOLID2.exe.unpacked.exe"
```

## Scripts

| Script | Purpose |
|--------|---------|
| `pe_map.py` | sections, image base, file-offset ↔ virtual address, locate strings |
| `xrefs.py` | RIP-relative `lea` references to a target string/address |
| `hunt.py` | occurrences of raven's 32-bit sound-code immediates; call xrefs |
| `data_xrefs.py` | read/write references to a data global (per `.pdata` function) |
| `analyze.py <VA>` | disassemble the function at VA, resolving strings/data/calls |
| `summarize.py <VA>` | same, but print only the calls and string/data refs |

Example:

```bash
python scripts/re/analyze.py 0x14006225B   # the sound-code dispatcher
```
