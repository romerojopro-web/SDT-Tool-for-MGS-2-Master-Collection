# `scripts/re/` — interoperability analysis tools

Small capstone/pefile scripts used to study how the game engine drives its audio,
so the tool can interoperate with it. See `docs/EXE_REVERSE.md` for the findings.
This folder is just the tooling.

**Interoperability research on your own legally-owned copy** — permitted under the
EU Software Directive (2009/24/EC, Art. 6) and French law (CPI L122-6-1). These
scripts contain **no game data and no game code** — only analysis code that reads
a binary on your own machine and prints addresses/disassembly. **No game
executable, protected or otherwise, is included in or distributed by this repo.**

## Requirements

```bash
pip install capstone pefile
```

## Pointing the scripts at a binary

Static analysis needs an image of the executable whose code section is readable
(a retail build may apply a technical protection measure that leaves the code
unreadable at rest). Obtaining such an image from your own copy, and the means of
doing so, are outside the scope of this repo. Once you have a locally-readable
image, set the path near the top of each script:

```python
EXE = r"...\an-image-readable-on-your-machine.exe"
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
