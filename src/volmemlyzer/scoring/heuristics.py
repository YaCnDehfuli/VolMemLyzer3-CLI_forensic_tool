"""Low-level detection primitives, self-contained and unit-testable.

These are the hardened replacements for the VolMemLyzer scorers that this engine
ports. In particular they fix the two byte-pattern bugs called out in the port
plan:

* the original hexdump check built regex-shaped byte literals (``b"\\xe8[\\x00-
  \\xff]{4}"``) and matched them with ``in`` — so those "patterns" only matched
  when the file literally contained the bytes ``[`` ``\\`` ``x`` … and never fired
  on real shellcode. Here the raw region bytes are recovered and matched with
  ``re.search(..., re.DOTALL)`` against genuine shellcode byte signatures.
* the original disassembly check matched ``push ebp`` / ``call|jmp .*`` — patterns
  present in essentially all code — producing constant false positives. That
  heuristic is dropped entirely in favour of the byte-signature scan below.

The helpers are pure Python (no NumPy/Volatility) so the whole scoring package
imports cleanly in the API process and the test environment.
"""
from __future__ import annotations

import math
import re
from collections import Counter

# --- path classification -------------------------------------------------

_SYSTEM_ROOTS = (
    r"\windows",
    r"\program files",
    r"\program files (x86)",
    r"\programdata\microsoft",
)
_SUSPICIOUS_TOKENS = (
    r"\temp\\",
    r"\tmp\\",
    r"\downloads\\",
    r"\appdata\\",
    r"\desktop\\",
    r"\users\public\\",
    r"\$recycle.bin\\",
    r"\perflogs\\",
)


def _norm(path: str) -> str:
    return (path or "").replace("/", "\\").strip().strip('"').lower()


def not_system_path(path: str) -> bool:
    """True if ``path`` is a real path that does not live under a system root."""
    p = _norm(path)
    if not p:
        return False
    # Only judge things that look like absolute Windows paths.
    if not re.match(r"^[a-z]:\\", p) and not p.startswith("\\"):
        return False
    return not any(root in p for root in _SYSTEM_ROOTS)


def is_suspicious_path(path: str) -> bool:
    """User-writable / staging locations attackers favour."""
    p = _norm(path)
    if not not_system_path(p):
        return False
    return any(tok.replace("\\\\", "\\") in p for tok in _SUSPICIOUS_TOKENS)


def char_entropy(s: str) -> float:
    if not s:
        return 0.0
    cnt, n = Counter(s), len(s)
    return -sum((c / n) * math.log2(c / n) for c in cnt.values())


def is_non_ascii(s: str) -> bool:
    return any(ord(ch) > 127 for ch in (s or ""))


# --- memory-region byte analysis ----------------------------------------

_ADDR_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|[0-9a-fA-F]{6,})$")
_BYTE_RE = re.compile(r"^[0-9a-fA-F]{2}$")


def hexdump_to_bytes(hexdump: str, max_bytes: int = 4096) -> bytes:
    """Recover the raw bytes from a malfind ``Hexdump`` field.

    Handles both the multi-line Volatility layout ``<addr>  <16 hex bytes>  <ascii>``
    and a plain whitespace-separated hex string. The trailing ASCII gutter is
    ignored by only taking the leading run of two-hex-digit tokens on each line.
    """
    out = bytearray()
    for line in (hexdump or "").splitlines() or [hexdump or ""]:
        toks = line.split()
        if not toks:
            continue
        cap: int | None = None
        if _ADDR_RE.match(toks[0]):
            toks = toks[1:]
            cap = 16  # Volatility renders 16 bytes/line before the ASCII gutter
        n = 0
        for t in toks:
            if _BYTE_RE.match(t) and (cap is None or n < cap):
                out.append(int(t, 16))
                n += 1
            else:
                break
        if len(out) >= max_bytes:
            break
    return bytes(out[:max_bytes])


def has_pe_header(data: bytes) -> bool:
    """Reflective/injected PE: an ``MZ`` DOS header at the start of a region."""
    return len(data) >= 2 and data[0] == 0x4D and data[1] == 0x5A


# Genuine shellcode byte signatures, matched against recovered region bytes.
_SHELLCODE_SIGNATURES: tuple[tuple[str, bytes], ...] = (
    ("NOP sled", rb"\x90{8,}"),
    ("Metasploit block prologue (cld; call)", rb"\xfc\xe8.{2}\x00\x00"),
    ("call $+5 GetPC / pop", rb"\xe8\x00\x00\x00\x00[\x58-\x5f]"),
    ("fnstenv GetPC", rb"\xd9[\xf0-\xff]?\xd9\x74\x24\xf4"),
    ("PEB access via fs:[0x30] (x86)", rb"\x64\xa1\x30\x00\x00\x00"),
    ("PEB access via gs (x64)", rb"\x65\x48\x8b"),
    ("SEH walk fs:[0]", rb"\x64\x8b[\x0d\x1d\x25\x35]\x00\x00\x00\x00"),
)


def shellcode_signals(data: bytes) -> list[str]:
    """Return the names of shellcode signatures present in ``data`` (may be empty)."""
    found: list[str] = []
    for name, pattern in _SHELLCODE_SIGNATURES:
        if re.search(pattern, data, re.DOTALL):
            found.append(name)
    return found


def protection_is_rwx(protection: str) -> bool:
    """PAGE_EXECUTE_READWRITE (or any EXECUTE+WRITE) — the classic injection mark."""
    p = (protection or "").upper()
    return "EXECUTE" in p and ("WRITECOPY" in p or "READWRITE" in p or "WRITE" in p)


# --- loader behaviour ----------------------------------------------------
#
# Ported from VolMemLyzer's OverviewAnalysis, which the catalog had no
# equivalent for. Position-independent code has to locate its own imports at
# runtime; these are the two ways it does that.

# The x86 walk from the PEB to the loader's module lists:
#   mov eax,[eax+0x0c]   PEB->Ldr
#   mov esi,[eax+0x1c]   InInitializationOrderModuleList
#   mov eax,[esi+0x08]   DllBase
#   mov edi,[esi+0x20]   BaseDllName
#   mov esi,[esi]        next entry
_PEB_WALK_OPS: tuple[bytes, ...] = (
    b"\x8b\x40\x0c", b"\x8b\x70\x1c", b"\x8b\x46\x08",
    b"\x8b\x7e\x20", b"\x8b\x36", b"\x8b\x5e\x08", b"\x8b\x4e\x20",
)


def walks_peb_loader_lists(data: bytes) -> bool:
    """Several PEB/Ldr field reads together, not one on its own.

    Compiler output reaches structure fields exactly the same way, and two of
    these — one of which is the two-byte ``8b 36`` — turn up in ordinary code
    often enough that the original threshold of two fired on compiled
    functions. Three independent field offsets is the walk.
    """
    return sum(1 for op in _PEB_WALK_OPS if op in data) >= 3


def api_hash_pushes(data: bytes) -> int:
    """Count ``push imm32`` whose immediate looks like a precomputed API hash.

    Shellcode resolves imports by hashing export names, so the hashes appear
    inline as immediates. Ordinary code pushes addresses, lengths and flags,
    which leave most of the four bytes zero.

    The original scanned unaligned for ``0x68`` and accepted any immediate with
    three distinct mostly-non-zero bytes. ``0x68`` is ASCII ``'h'``, so the
    string ``"http"`` matched (``'h'`` + ``"ttp:"``) and two links in a region
    were enough to flag it — a false positive on any region holding text.
    Immediates that are themselves printable ASCII are therefore rejected.
    """
    hits = 0
    for m in re.finditer(rb"\x68(....)", data, re.DOTALL):
        imm = m.group(1)
        if len(set(imm)) < 3 or imm.count(0) > 1:
            continue
        if all(0x20 <= b < 0x7F for b in imm):
            continue  # "ttp:", "ello" — text, not a hash
        hits += 1
    return hits


# --- kernel dispatch integrity ------------------------------------------

# SSDT entries normally resolve into one of these Windows kernel modules.
TRUSTED_SSDT_MODULES: frozenset[str] = frozenset({
    "ntoskrnl", "win32k", "win32kbase", "win32kfull",
})


def ssdt_foreign_module(module: str) -> bool:
    """True when a resolved SSDT target lands outside the kernel baseline.

    An unresolved or empty module is missing data, not a hook, and must not be
    scored as one.
    """
    name = (module or "").strip().replace("/", "\\").rsplit("\\", 1)[-1].lower()
    stem = name.rsplit(".", 1)[0] if "." in name else name
    if not stem:
        return False
    return stem not in TRUSTED_SSDT_MODULES
