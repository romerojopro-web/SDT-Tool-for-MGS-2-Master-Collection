#!/usr/bin/env python3
"""Disassemble a function of the unpacked EXE, resolving strings, data and calls.

Uses the .pdata RUNTIME_FUNCTION table (plaintext even before unpacking) for
exact function boundaries, then annotates each RIP-relative operand: a target in
.rdata/.data is shown with the string or bytes it points at, and a call target is
named sub_<va>. This turns raw asm into something readable enough to follow the
audio logic.
"""
import struct
import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = r"C:\Games\Steam\steamapps\common\MGS2\METAL GEAR SOLID2.exe.unpacked.exe"
pe = pefile.PE(EXE, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
data = pe.__data__
sections = pe.sections


def sec_of(va):
    for s in sections:
        a = base + s.VirtualAddress
        if a <= va < a + s.Misc_VirtualSize:
            return s
    return None


def va_to_off(va):
    s = sec_of(va)
    if not s:
        return None
    return s.PointerToRawData + (va - (base + s.VirtualAddress))


def read(va, n):
    off = va_to_off(va)
    return data[off:off + n] if off is not None else b""


def cstr(va, maxlen=64):
    b = read(va, maxlen)
    z = b.split(b"\x00")[0]
    if z and all(9 <= c < 127 for c in z):
        return z.decode("latin1")
    return None


# ---- function table from .pdata (RUNTIME_FUNCTION: begin, end, unwind u32 each)
pdata = next(s for s in sections if s.Name.startswith(b".pdata"))
praw = data[pdata.PointerToRawData:pdata.PointerToRawData + pdata.Misc_VirtualSize]
funcs = []
for i in range(0, len(praw) - 11, 12):
    b, e, u = struct.unpack_from("<III", praw, i)
    if b and e > b:
        funcs.append((base + b, base + e))
funcs.sort()
func_starts = [f[0] for f in funcs]


def func_of(va):
    import bisect
    i = bisect.bisect_right(func_starts, va) - 1
    if 0 <= i < len(funcs) and funcs[i][0] <= va < funcs[i][1]:
        return funcs[i]
    return None


md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def annotate(ins):
    notes = []
    for op in ins.operands:
        if op.type == 3 and op.mem.base == 0x2b:  # x86 RIP register id in capstone
            pass
    # simpler: use op_str RIP handling via ins.disp when rip-relative
    if "rip" in ins.op_str:
        # capstone gives the displacement; compute target
        for op in ins.operands:
            if op.type == 3 and op.mem.base != 0 and md.reg_name(op.mem.base) == "rip":
                target = ins.address + ins.size + op.mem.disp
                s = cstr(target)
                if s is not None:
                    notes.append('"%s"' % s[:48])
                else:
                    bs = read(target, 8)
                    # is it a pointer to code/data?
                    ptr = struct.unpack("<Q", bs)[0] if len(bs) == 8 else 0
                    tag = sec_of(target)
                    notes.append("data 0x%X%s" % (target, " (%s)" % tag.Name.rstrip(b'\x00').decode() if tag else ""))
    if ins.mnemonic == "call" or ins.mnemonic.startswith("j"):
        try:
            tgt = int(ins.op_str, 16)
            f = func_of(tgt)
            notes.append("-> sub_%X" % tgt)
        except ValueError:
            pass
    return "  ; " + " ".join(notes) if notes else ""


def dump(func_start, limit=400):
    f = func_of(func_start)
    if not f:
        print("no function table entry at 0x%X" % func_start)
        # fall back: disasm from the given address
        f = (func_start, func_start + 0x400)
    start, end = f
    print("=" * 78)
    print("sub_%X   (0x%X .. 0x%X, %d bytes)" % (start, start, end, end - start))
    print("=" * 78)
    code = read(start, end - start)
    n = 0
    for ins in md.disasm(code, start):
        print("  0x%X  %-22s %-6s %-26s%s"
              % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str, annotate(ins)))
        n += 1
        if n >= limit:
            print("  ... (truncated)")
            break


print("total functions in .pdata: %d\n" % len(funcs))
for va in [int(x, 16) for x in sys.argv[1:]] or [0x1400692E6]:
    f = func_of(va)
    print(">>> address 0x%X is in %s\n"
          % (va, ("sub_%X" % f[0]) if f else "(no function entry)"))
    dump(f[0] if f else va)
    print()
