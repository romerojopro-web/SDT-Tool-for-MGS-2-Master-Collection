#!/usr/bin/env python3
"""Find every instruction that references given data globals, read vs write.

Disassembles all of .text once, and for each instruction with a RIP-relative
memory operand computes the target; if it matches a watched global, records the
site and whether the global is written (it is the destination operand of a
mov/or/and/etc.) or read. The consumers (readers) of the "current music code"
global are the code that acts on a song request — the next link toward the data.
"""
import struct
import bisect
import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_AC_WRITE

EXE = r"C:\Games\Steam\steamapps\common\MGS2\METAL GEAR SOLID2.exe.unpacked.exe"
pe = pefile.PE(EXE, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
data = pe.__data__
text = next(s for s in pe.sections if s.Name.startswith(b".text"))
tstart, tsize = text.PointerToRawData, text.Misc_VirtualSize
tva = base + text.VirtualAddress
code = data[tstart:tstart + tsize]

# function table for naming the enclosing sub_
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
    return fstarts[i] if i >= 0 else 0


WATCH = {int(x, 16): x for x in sys.argv[1:]} or {
    0x141540854: "current_music_code",
    0x14177EAF8: "driver_state_ptr",
}

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
RIP = md.reg_name  # not used; keep detail

hits = {va: {"read": [], "write": []} for va in WATCH}
for ins in md.disasm(code, tva):
    if not ins.operands:
        continue
    for op in ins.operands:
        if op.type == CS_OP_MEM and ins.reg_name(op.mem.base or 0) == "rip":
            target = ins.address + ins.size + op.mem.disp
            if target in WATCH:
                kind = "write" if (op.access & CS_AC_WRITE) else "read"
                hits[target][kind].append((ins.address, func_of(ins.address),
                                           "%s %s" % (ins.mnemonic, ins.op_str)))

for va, name in WATCH.items():
    h = hits[va]
    print("=" * 78)
    print("0x%X  %s   (%d write, %d read)" % (va, name, len(h["write"]), len(h["read"])))
    print("=" * 78)
    for kind in ("write", "read"):
        if not h[kind]:
            continue
        print("  -- %s --" % kind.upper())
        seen = set()
        for addr, fn, txt in h[kind]:
            if fn in seen and kind == "read":
                continue
            seen.add(fn)
            print("    0x%X  in sub_%X   %s" % (addr, fn, txt[:52]))
    print()
