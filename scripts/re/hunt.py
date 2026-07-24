#!/usr/bin/env python3
"""Two targeted hunts in the unpacked EXE.

A. Callers of the mtrack error stub (0x1400692E6) — the real music-track code.
B. Code comparing against raven's 32-bit sound codes (0x01FFFF10 = alert, etc.).
   Those exact immediates in .text mark the music command dispatcher — the thing
   that turns a game event into "play song N / evasion / stop".
"""
import struct
import bisect
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = r"C:\Games\Steam\steamapps\common\MGS2\METAL GEAR SOLID2.exe.unpacked.exe"
pe = pefile.PE(EXE, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
data = pe.__data__
text = next(s for s in pe.sections if s.Name.startswith(b".text"))
tstart, tsize = text.PointerToRawData, text.Misc_VirtualSize
tva = base + text.VirtualAddress
tbytes = data[tstart:tstart + tsize]


def va_of(i):
    return tva + i


# function table for naming
pdata = next(s for s in pe.sections if s.Name.startswith(b".pdata"))
praw = data[pdata.PointerToRawData:pdata.PointerToRawData + pdata.Misc_VirtualSize]
fstarts = []
for i in range(0, len(praw) - 11, 12):
    b, e, u = struct.unpack_from("<III", praw, i)
    if b and e > b:
        fstarts.append(base + b)
fstarts.sort()


def func_of(va):
    i = bisect.bisect_right(fstarts, va) - 1
    return fstarts[i] if i >= 0 else None


# ---- A. call/jmp references to the mtrack stub -----------------------------
STUB = 0x1400692E6
print("=" * 74)
print("A. call/jmp -> mtrack stub 0x%X" % STUB)
print("=" * 74)
for op, mnem in ((0xE8, "call"), (0xE9, "jmp")):
    i = 0
    while i < len(tbytes) - 5:
        if tbytes[i] == op:
            rel = struct.unpack_from("<i", tbytes, i + 1)[0]
            if va_of(i) + 5 + rel == STUB:
                f = func_of(va_of(i))
                print("  %-4s at 0x%X   (in sub_%X)" % (mnem, va_of(i),
                                                        f if f else 0))
        i += 1

# ---- B. immediates matching raven sound codes ------------------------------
CODES = {
    0x01FFFF10: "EVASION/ALERT",
    0x01FFFFFF: "STOP",
    0x01FFFF01: "PAUSE",
    0x01FFFF02: "RESUME",
    0x01000001: "PLAY song1",
    0x01000008: "PLAY song8",
    0x01FFFF20: "FirstPerson on",
}
print("\n" + "=" * 74)
print("B. .text occurrences of raven sound-code immediates (LE u32)")
print("=" * 74)
for code, label in CODES.items():
    pat = struct.pack("<I", code)
    start = 0
    hits = []
    while (j := tbytes.find(pat, start)) != -1:
        hits.append(va_of(j))
        start = j + 1
        if len(hits) > 20:
            break
    if hits:
        print("  0x%08X %-16s : %d" % (code, label, len(hits)))
        for va in hits[:12]:
            f = func_of(va)
            print("       at 0x%X   (in sub_%X)" % (va, f if f else 0))

# ---- also: broad scan for the 0x01FFFFxx family (any) -----------------------
print("\n" + "=" * 74)
print("C. any immediate of the form 0x01FFFFxx or 0x010000xx in .text")
print("=" * 74)
fam = {}
i = 0
while i < len(tbytes) - 4:
    v = struct.unpack_from("<I", tbytes, i)[0]
    if (v & 0xFFFFFF00) == 0x01FFFF00 or (v & 0xFFFFFF00) == 0x01000000:
        fam.setdefault(func_of(va_of(i)), set()).add(v)
    i += 1
for f, vals in sorted(fam.items(), key=lambda kv: -len(kv[1]))[:15]:
    print("  sub_%X : %d distinct codes  %s"
          % (f if f else 0, len(vals),
             " ".join("0x%08X" % v for v in sorted(vals)[:8])))
