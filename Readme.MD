# CPython `ctypes.Structure` OOB to Shell

[![Python Version](https://img.shields.io/badge/python-3.12-blue.svg)](https://python.org)
[![Vulnerability](https://img.shields.io/badge/vuln-OOB%20R%2FW-red.svg)]()

This repository contains a proof-of-concept (PoC) exploit for a memory corruption vulnerability in CPython's `ctypes` module (Issue [#145985](https://github.com/python/cpython/issues/145985) / dup of #143005). 

Following up on previous research into CPython internals like the perf trampoline UAF, this exploit demonstrates how a simple `__class__` swap on a `ctypes.Structure` object can be weaponized to achieve arbitrary memory read/write and ultimately a native shell—using a radically minimal attack surface.

## 🧠 The Bug

The core vulnerability lies in how CPython handles dynamic class assignments for `ctypes.Structure` objects. By instantiating a struct with a small memory footprint and then swapping its `__class__` attribute to a heavily padded struct, we trick the interpreter into allowing out-of-bounds (OOB) field access.

Because the underlying C memory allocation isn't resized to match the new class definition, writing to the higher-index fields of the new class corrupts adjacent memory in the Python heap.

## ⚙️ Exploit Architecture

This exploit strictly avoids common crutches like `os`, `sys`, `subprocess`, `/proc/self/maps`, or even `ctypes.addressof`. It relies only on the `ctypes.Structure` bug, the `id()` function for initial heap layout orientation, and standard `getattr`/`setattr` calls.

**The attack chain:**
1. **Heap Feng Shui:** Spray the heap with alternating `Attacker` and `Victim` objects until an exact memory gap (128 bytes) is achieved.
2. **The Primitive:** Perform the `__class__` swap on the `Attacker` object. By writing OOB into the adjacent `Victim` object's `b_ptr` (the pointer to its underlying C data buffer), we establish an arbitrary read/write primitive.
3. **Leak & Bypass:** * Leak the address of the built-in `len()` function's internal structures (`PyCFunctionObject` and `PyMethodDef`).
   * Calculate the `libpython` base address.
   * Read the GOT to find `libc`'s `free`, defeating ASLR to resolve `system()`.
4. **Code Execution:** * Write the payload (`"exec /bin/sh\\0"`) directly into the attacker's buffer.
   * Overwrite `len()`'s `ml_meth` pointer with `system()`.
   * Overwrite `len()`'s `m_self` pointer to pass our payload address as the first argument.
   * Call `len("x")` to pop the shell.

## ⚠️ Version Dependency & The "Dict Offset" Problem

If you're trying to port this exploit to a different CPython version (like 3.10, or the newer 3.13 builds), you are going to hit a wall with the internal object layouts. 

This PoC relies heavily on exact heap geometries to achieve the OOB read/write primitive. Specifically, the stability of this exploit is strictly tied to the **dict offset** and the internal C struct layout of `ctypes.cDataObject`:

* **Object Footprints (`OBJ_GAP`):** CPython 3.11+ introduced massive internal changes to how objects are laid out in memory, specifically regarding inline object dictionaries to speed up attribute access. The exact allocation size of the `ctypes.Structure` instances (128 bytes in this 3.12 target) will shift depending on how `__dict__` and `__weakref__` are structured in that specific Python minor version.
* **Targeting the Buffer (`b_ptr`):** The exploit establishes its primitive by calculating `orig_bptr = id(vic) + 80`. This assumes the pointer to the underlying C memory buffer (`b_ptr`) is exactly 80 bytes deep into the victim object. If the `PyObject_HEAD` size or the dict offset shifts even by a few bytes in a different Python build, your OOB write will overwrite adjacent metadata instead of cleanly hijacking the data buffer pointer.
* **The `F_IDX` Alignment:** The index used for the OOB array access (`(OBJ_GAP + 16 - 80) // 8`) expects perfectly aligned 8-byte boundaries. A shifted dict offset will misalign this math, leading to an immediate `SIGSEGV` when the interpreter tries to dereference garbage memory.

**TL;DR:** To port this to another environment, updating the `libc` offsets isn't enough. You will need to drop into `gdb`, inspect the `ctypes.Structure` allocation, and manually recalculate `OBJ_GAP` and the exact byte offset to `b_ptr`.

## 🚀 Usage

**Note:** Memory offsets are highly environment-dependent. The offsets in this script (`OFF_BUILTIN_LEN`, `OFF_FREE_GOT`, etc.) are tuned for `pyenv` CPython 3.12.12 (x86-64) and its corresponding `libpython3.12.so.1.0`. 

```bash
# Clone the repo
git clone [https://github.com/cyb3rst4n/cpython-ctypes-oob.git](https://github.com/cyb3rst4n/cpython-ctypes-oob.git)
cd cpython-ctypes-oob

# Run the exploit
python3 exploit.py
