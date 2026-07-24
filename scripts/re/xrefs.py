#!/usr/bin/env python3
"""Find every code reference to our target strings (RIP-relative LEA + pointers).

An x64 string-address load is `lea reg, [rip+disp32]`: REX.W (0x48/0x4C) + 0x8D +
ModRM(mod=00,r/m=101). The target = end_of_insn + disp32. Enumerate those and
keep the ones pointing at our strings. Also scan every section for the absolute
8-byte pointer, in case the address sits in a table rather than inline code.
"""
import struct
import pefile

EXE = r"C:\Games\Steam\steamapps\common\MGS2\METAL GEAR SOLID2.exe"
pe = pefile.PE(EXE, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
data = pe.__data__

TARGETS = {
    0x14072FAC0: "pk_pattern  %s/stage/%s/pk%06x.sdx",
    0x14072FB00: "mtrack_err  SoundData(voi):mtrack=%x",
}

# also a few neighbours from the audio path table, for context
NEIGHBOURS = {
    0x14072FA48: "host0:./sound/vox1/",
    0x14072FA60: "host0:./sound/wvx1/",
    0x14072FA78: "host0:./sound/mdx1/",
    0x14072FA90: "host0:./sound/efx1/",
    0x14072FAA8: "host0:./sound/sdx1/",
}
ALL = {**TARGETS, **NEIGHBOURS}

text = next(s for s in pe.sections if s.Name.startswith(b".text"))
tstart = text.PointerToRawData
tend = tstart + text.SizeOfRawData
tva = base + text.VirtualAddress

LEA_MODRM = {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}
REGS = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"]


def va_of(fileoff):
    return tva + (fileoff - tstart)


print("scanning .text for lea [rip+disp] -> target strings ...\n")
hits = {va: [] for va in ALL}
i = tstart
blob = data
while i < tend - 7:
    b0 = blob[i]
    if b0 in (0x48, 0x4C) and blob[i + 1] == 0x8D and blob[i + 2] in LEA_MODRM:
        disp = struct.unpack_from("<i", blob, i + 3)[0]
        insn_va = va_of(i)
        target = insn_va + 7 + disp
        if target in ALL:
            reg = REGS[(blob[i + 2] >> 3) & 7]
            reg = ("r%d" % (8 + REGS.index(reg))) if b0 == 0x4C else "r" + reg
            hits[target].append((insn_va, reg))
    i += 1

for va, label in ALL.items():
    hs = hits[va]
    tag = "  <== TARGET" if va in TARGETS else ""
    print("0x%X  %-38s : %d ref(s)%s" % (va, label, len(hs), tag))
    for insn_va, reg in hs:
        print("      lea %-4s at 0x%X" % (reg, insn_va))

# pointer scan across sections (address stored as 8-byte value)
print("\nabsolute 8-byte pointer occurrences (tables), for TARGET strings:")
for va, label in TARGETS.items():
    pat = struct.pack("<Q", va)
    n = 0
    start = 0
    while (j := data.find(pat, start)) != -1:
        # which section?
        sec = "?"
        for s in pe.sections:
            if s.PointerToRawData <= j < s.PointerToRawData + s.SizeOfRawData:
                sec = s.Name.rstrip(b"\x00").decode("latin1")
                ptr_va = base + s.VirtualAddress + (j - s.PointerToRawData)
                break
        print("   %-38s at %s VA 0x%X" % (label, sec, ptr_va))
        start = j + 1
        n += 1
        if n > 10:
            break
    if n == 0:
        print("   %-38s : none" % label)
