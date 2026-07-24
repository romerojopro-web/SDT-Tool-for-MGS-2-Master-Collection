#!/usr/bin/env python3
"""Load the EXE, map file offsets <-> virtual addresses, locate our target strings.

Everything downstream (finding who references a string, disassembling that code)
needs the image base and the section layout, so establish those first and print
the virtual address of the two strings the earlier string-scan located by file
offset.
"""
import pefile

EXE = r"C:\Games\Steam\steamapps\common\MGS2\METAL GEAR SOLID2.exe"
pe = pefile.PE(EXE, fast_load=True)

base = pe.OPTIONAL_HEADER.ImageBase
print("image base : 0x%X" % base)
print("machine    : 0x%X (%s)" % (pe.FILE_HEADER.Machine,
                                  "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"))
print("entry point: 0x%X (VA 0x%X)\n" % (pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                                         base + pe.OPTIONAL_HEADER.AddressOfEntryPoint))

print("sections:")
print("  %-8s %-12s %-12s %-12s %s" % ("name", "VA", "vsize", "rawptr", "rawsize"))
for s in pe.sections:
    name = s.Name.rstrip(b"\x00").decode("latin1")
    print("  %-8s 0x%010X 0x%08X   0x%08X   0x%08X"
          % (name, base + s.VirtualAddress, s.Misc_VirtualSize,
             s.PointerToRawData, s.SizeOfRawData))


def file_off_to_va(off):
    for s in pe.sections:
        start = s.PointerToRawData
        end = start + s.SizeOfRawData
        if start <= off < end:
            return base + s.VirtualAddress + (off - start)
    return None


# The two strings, by the file offsets the earlier EXE string-scan reported.
TARGETS = {
    "pk pattern  (%s/stage/%s/pk%06x.sdx)": 0x0072ECC0,
    "mtrack error (SoundData(voi):mtrack)": 0x0072ED00,
}
print("\ntarget strings:")
data = pe.__data__
for label, off in TARGETS.items():
    va = file_off_to_va(off)
    # read the actual bytes there to confirm
    text = data[off:off + 48].split(b"\x00")[0].decode("latin1", "replace")
    print("  %-40s file 0x%06X -> VA 0x%X" % (label, off, va))
    print("      = %r" % text)
