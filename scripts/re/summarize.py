#!/usr/bin/env python3
"""Summarise a function: its calls, string/data refs and notable immediates.

Full asm is noise for understanding structure. This walks the function (following
straight through, honouring the .pdata end) and prints only the meaningful edges:
what it calls, which strings/data globals it touches, and any 32-bit immediate
that looks like a sound code or a size. Enough to read what a loader does.
"""
import struct
import bisect
import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_IMM

EXE = r"C:\Games\Steam\steamapps\common\MGS2\METAL GEAR SOLID2.exe.unpacked.exe"
pe = pefile.PE(EXE, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
data = pe.__data__


def sec_of(va):
    for s in pe.sections:
        a = base + s.VirtualAddress
        if a <= va < a + s.Misc_VirtualSize:
            return s
    return None


def read(va, n):
    s = sec_of(va)
    if not s:
        return b""
    off = s.PointerToRawData + (va - (base + s.VirtualAddress))
    return data[off:off + n]


def cstr(va, m=80):
    b = read(va, m).split(b"\x00")[0]
    return b.decode("latin1") if b and all(9 <= c < 127 for c in b) else None


pdata = next(s for s in pe.sections if s.Name.startswith(b".pdata"))
praw = data[pdata.PointerToRawData:pdata.PointerToRawData + pdata.Misc_VirtualSize]
funcs = []
for i in range(0, len(praw) - 11, 12):
    b, e, u = struct.unpack_from("<III", praw, i)
    if b and e > b:
        funcs.append((base + b, base + e))
funcs.sort()
fstarts = [f[0] for f in funcs]


def frange(va):
    i = bisect.bisect_right(fstarts, va) - 1
    return funcs[i] if i >= 0 and funcs[i][0] <= va < funcs[i][1] else (va, va + 0x1000)


md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

for arg in (sys.argv[1:] or ["0x14006225B"]):
    fva = int(arg, 16)
    fs, fe = frange(fva)
    print("=" * 78)
    print("sub_%X   (0x%X..0x%X, %d bytes)" % (fs, fs, fe, fe - fs))
    print("=" * 78)
    body = read(fs, fe - fs)
    for ins in md.disasm(body, fs):
        line = None
        # calls / tail jumps
        if ins.mnemonic in ("call", "jmp"):
            try:
                t = int(ins.op_str, 16)
                line = "  0x%X  %-4s sub_%X" % (ins.address, ins.mnemonic, t)
            except ValueError:
                if "rip" in ins.op_str:
                    for op in ins.operands:
                        if op.type == CS_OP_MEM and ins.reg_name(op.mem.base or 0) == "rip":
                            t = ins.address + ins.size + op.mem.disp
                            line = "  0x%X  %-4s [import/ptr 0x%X]" % (ins.address, ins.mnemonic, t)
        # rip-relative data / string refs
        elif any(op.type == CS_OP_MEM and ins.reg_name(op.mem.base or 0) == "rip"
                 for op in ins.operands) or (
                 ins.mnemonic == "lea" and "rip" in ins.op_str):
            for op in ins.operands:
                if op.type == CS_OP_MEM and ins.reg_name(op.mem.base or 0) == "rip":
                    t = ins.address + ins.size + op.mem.disp
                    s = cstr(t)
                    if s:
                        line = '  0x%X  %-4s "%s"' % (ins.address, ins.mnemonic, s[:50])
                    else:
                        sc = sec_of(t)
                        secn = sc.Name.rstrip(b"\x00").decode() if sc else "?"
                        line = "  0x%X  %-4s %s:0x%X" % (ins.address, ins.mnemonic, secn, t)
        # notable immediates (sound codes / big sizes)
        else:
            for op in ins.operands:
                if op.type == CS_OP_IMM:
                    v = op.imm & 0xFFFFFFFF
                    if (v & 0xFFFF0000) == 0x01FF0000 or (v & 0xFFFF0000) == 0x01000000 \
                            or v in (13, 0xD) or 0x1000 <= v <= 0x8000 and v % 0x800 == 0:
                        line = "  0x%X  %-4s 0x%X   (imm)" % (ins.address, ins.mnemonic, v)
        if line:
            print(line)
    print()
