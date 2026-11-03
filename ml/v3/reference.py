"""Reference raw features of EMBER2024 (feature version 3) for one file.

    python3 ml/v3/reference.py <file>...   -> one JSON object per line

The same computations as thrember's features.py (FutureComputing4AI/EMBER2024,
Apache-2.0), written here with pefile, for the groups the agent reproduces in
Go (agent/internal/mlscore/v3.go): general, histogram, byteentropy, strings,
header, section, imports, exports, datadirectories, richheader. Left out:
authenticode (needs a full PKCS#7 parser) and pefilewarnings (pefile's own
warning texts). ml/v3/compare.py checks the Go output against this.
"""
from __future__ import annotations

import json
import math
import re
import sys
from collections import Counter, OrderedDict

import numpy as np
import pefile


def entropy_h(data: bytes) -> float:
    # pefile's entropy_H, used for the file and the overlay
    if not data:
        return 0.0
    occ = Counter(bytearray(data))
    e = 0.0
    for x in occ.values():
        p = float(x) / len(data)
        e -= p * math.log(p, 2)
    return e


def general(b: bytes, pe) -> dict:
    a = bytearray(b)
    return {"size": len(b), "entropy": entropy_h(b), "is_pe": 0 if pe is None else 1,
            "start_bytes": [int(a[0]), int(a[1]) if len(b) >= 2 else 0, int(a[2]) if len(b) >= 3 else 0,
                            int(a[3]) if len(b) >= 4 else 0]}


def histogram(b: bytes) -> list:
    return np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256).tolist()


def _ebin(block, window):
    c = np.bincount(block >> 4, minlength=16)
    p = c.astype(np.float32) / window
    wh = np.where(c)[0]
    H = np.sum(-p[wh] * np.log2(p[wh])) * 2
    hbin = int(H * 2)
    if hbin == 16:
        hbin = 15
    return hbin, c


def byteentropy(b: bytes, step=1024, window=2048) -> list:
    out = np.zeros((16, 16), dtype=np.int32)
    a = np.frombuffer(b, dtype=np.uint8)
    if a.shape[0] < window:
        h, c = _ebin(a, window)
        out[h, :] += c
    else:
        shape = a.shape[:-1] + (a.shape[-1] - window + 1, window)
        strides = a.strides + (a.strides[-1],)
        blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::step, :]
        for block in blocks:
            h, c = _ebin(block, window)
            out[h, :] += c
    return out.flatten().tolist()


STRING_REGEXES = {
    "url": "\\b(?:http|https|ftp):\\/\\/[a-zA-Z0-9-._~:?#[\\]@!$&'()*+,;=]+",
    "ipv4_addr": "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b",
    "ipv6_addr": "\\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\\b|\\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\\b|\\b:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){1,6}\\b",
    "mac_addr": "\\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\\b",
    "email_addr": "\\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\\b",
    "btc_wallet": "[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
    "file_path": "\\bC:/",
    "dos_msg": "!This program ",
    "registry_key": "\\b(?:KHEY_|KHLM|HKCU)",
    "/dev/": "/dev/", "/proc/": "/proc/", "/bin/": "/bin/", "/usr/": "/usr/", "/tmp/": "/tmp/",
    "/URI": "/URI", "/FlateDecode": "/FlateDecode", "/EmbeddedFile": "/EmbeddedFile",
    "html": "(?i)html", "javascript": "(?i)javascript", "<script": "(?i)<script", ".click(": "(?i).click",
    "onlick": "(?i)onclick",
    "powershell": "(?i)powershell", "Invoke-Expression": "Invoke-Expression", "Invoke-Command": "Invoke-Command",
    "Start-process": "Start-process",
    "get": "(?i)GET /", "post": "(?i)POST /", "http": "(?i)HTTP/", "http://": "(?i)http://", "https://": "(?i)https://",
    "ftp": "(?i)ftp:", "useragent": "(?i)User-Agent", "cookie": "(?i)cookie", "internet": "(?i)internet",
    "download": "(?i)download", "connect": "(?i)connect",
    "base64": "(?i)base64", "base64string": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "crypt": "crypt", "encode": "(?i)encode", "decode": "(?i)decode",
}
for _w in ("cache", "certificate", "clipboard", "command", "create", "debug", "delete", "desktop", "directory", "disk",
           "environment", "enum", "exit", "file", "hostname", "install", "hidden", "keyboard", "memory", "module",
           "mutex", "password", "privilege", "process", "remote", "resource", "security", "service", "shell",
           "snapshot", "system", "thread", "token", "wallet", "window"):
    STRING_REGEXES[_w] = "(?i)" + _w
_COMPILED = {k: re.compile(v) for k, v in STRING_REGEXES.items()}
_ALL = re.compile(b"[\x20-\x7f]{5,}")


def strings(b: bytes) -> dict:
    allstrings = _ALL.findall(b)
    if allstrings:
        lengths = [len(s) for s in allstrings]
        av = sum(lengths) / len(lengths)
        shifted = [x - 0x20 for x in b"".join(allstrings)]
        c = np.bincount(shifted, minlength=96)
        csum = c.sum()
        p = c.astype(np.float32) / csum
        wh = np.where(c)[0]
        H = np.sum(-p[wh] * np.log2(p[wh]))
    else:
        av, c, H, csum = 0, np.zeros((96,), dtype=np.float32), 0, 0
    counts = {}
    for s in (x.decode() for x in allstrings):
        for k, r in _COMPILED.items():
            if r.search(s):
                counts[k] = counts.get(k, 0) + 1
    return {"numstrings": len(allstrings), "avlength": av, "printabledist": [int(x) for x in c.tolist()],
            "printables": int(csum), "entropy": float(H), "string_counts": OrderedDict(sorted(counts.items()))}


DOS = ["e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc", "e_ss", "e_sp", "e_csum",
       "e_ip", "e_cs", "e_lfarlc", "e_ovno", "e_oemid", "e_oeminfo", "e_lfanew"]


def header(pe) -> dict:
    if pe is None:
        return {}
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    out = {"coff": {"timestamp": fh.TimeDateStamp,
                    "machine": pefile.MACHINE_TYPE.get(fh.Machine, "IMAGE_FILE_MACHINE_UNKNOWN"),
                    "number_of_sections": fh.NumberOfSections, "number_of_symbols": fh.NumberOfSymbols,
                    "sizeof_optional_header": fh.SizeOfOptionalHeader,
                    "pointer_to_symbol_table": fh.PointerToSymbolTable,
                    "characteristics": [k[11:] for k, v in fh.__dict__.items() if k.startswith("IMAGE_FILE_") and v]}}
    out["optional"] = {
        "magic": oh.Magic,
        "subsystem": pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, "IMAGE_SUBSYSTEM_UNKNOWN"),
        "major_image_version": oh.MajorImageVersion, "minor_image_version": oh.MinorImageVersion,
        "major_linker_version": oh.MajorLinkerVersion, "minor_linker_version": oh.MinorLinkerVersion,
        "major_operating_system_version": oh.MajorOperatingSystemVersion,
        "minor_operating_system_version": oh.MinorOperatingSystemVersion,
        "major_subsystem_version": oh.MajorSubsystemVersion, "minor_subsystem_version": oh.MinorSubsystemVersion,
        "sizeof_code": oh.SizeOfCode, "sizeof_headers": oh.SizeOfHeaders, "sizeof_image": oh.SizeOfImage,
        "sizeof_initialized_data": oh.SizeOfInitializedData,
        "sizeof_uninitialized_data": oh.SizeOfUninitializedData,
        "sizeof_stack_reserve": oh.SizeOfStackReserve, "sizeof_stack_commit": oh.SizeOfStackCommit,
        "sizeof_heap_reserve": oh.SizeOfHeapReserve, "sizeof_heap_commit": oh.SizeOfHeapCommit,
        "address_of_entrypoint": oh.AddressOfEntryPoint, "base_of_code": oh.BaseOfCode,
        "image_base": oh.ImageBase, "section_alignment": oh.SectionAlignment, "checksum": oh.CheckSum,
        "number_of_rvas_and_sizes": oh.NumberOfRvaAndSizes,
        "dll_characteristics": [k[25:] for k, v in oh.__dict__.items()
                                if k.startswith("IMAGE_DLLCHARACTERISTICS_") and v],
    }
    d = pe.DOS_HEADER.dump_dict()
    out["dos"] = {m: (d[m].get("Value") or 0) for m in DOS}
    return out


def section(b: bytes, pe) -> dict:
    if pe is None:
        return {}
    entry = ""
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for s in pe.sections:
        if s.contains_rva(ep):
            entry = s.Name.strip(b"\x00").decode(errors="ignore").lower()
    i = 0
    while entry == "" and i < len(pe.sections):
        if pe.sections[i].Characteristics & 0x20000000 > 0:
            entry = pe.sections[i].Name.strip(b"\x00").decode(errors="ignore").lower()
        i += 1
    out = {"entry": entry, "sections": [{
        "name": s.Name.strip(b"\x00").decode(errors="ignore").lower(),
        "size": s.SizeOfRawData, "entropy": s.get_entropy(), "vsize": s.Misc_VirtualSize,
        "size_ratio": s.SizeOfRawData / len(b), "vsize_ratio": s.SizeOfRawData / max(s.Misc_VirtualSize, 1),
        "props": [sc[10:] for sc, _ in pefile.section_characteristics if s.__dict__[sc]],
    } for s in pe.sections], "overlay": {"size": 0, "size_ratio": 0, "entropy": 0}}
    ov = pe.get_overlay()
    if ov is not None:
        out["overlay"] = {"size": len(ov), "size_ratio": len(ov) / len(b), "entropy": entropy_h(ov)}
    return out


def imports(pe) -> dict:
    out = {}
    if pe is None or "DIRECTORY_ENTRY_IMPORT" not in pe.__dict__:
        return out
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode()
        out[dll] = []
        for lib in entry.imports:
            if lib.name is not None and len(lib.name):
                out[dll].append(lib.name.decode()[:10000])
            elif lib.ordinal is not None:
                out[dll].append(f"{dll}:ordinal{lib.ordinal}")
    return out


def exports(pe) -> list:
    out = []
    if pe is None:
        return out
    if "DIRECTORY_ENTRY_EXPORT" in pe.__dict__:
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if e.name is not None and len(e.name):
                out.append(e.name.decode()[:10000])
            elif e.ordinal is not None:
                out.append(f"ordinal{e.ordinal}")
    return out


def datadirectories(pe) -> list:
    if pe is None:
        return []
    out = [{"has_relocs": int(pe.has_relocs()), "has_dynamic_relocs": int(pe.has_dynamic_relocs())}]
    for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        out.append({"name": str(d.name).replace("IMAGE_DIRECTORY_ENTRY_", ""), "size": d.Size,
                    "virtual_address": d.VirtualAddress})
    return out


def richheader(pe) -> list:
    if pe is not None and pe.RICH_HEADER is not None:
        return list(pe.RICH_HEADER.values)
    return []


def raw(b: bytes) -> dict:
    pe = None
    try:
        pe = pefile.PE(data=b)
    except (pefile.PEFormatError, AttributeError):
        pass
    out = {"general": general(b, pe), "histogram": histogram(b), "byteentropy": byteentropy(b),
           "strings": strings(b), "header": header(pe), "section": section(b, pe)}
    try:
        out["imports"] = imports(pe)
    except UnicodeDecodeError:
        out["imports"] = None  # thrember fails on such files: they are not in the dataset
    try:
        out["exports"] = exports(pe)
    except UnicodeDecodeError:
        out["exports"] = None
    out["datadirectories"] = datadirectories(pe)
    out["richheader"] = richheader(pe)
    return out


if __name__ == "__main__":
    for path in sys.argv[1:]:
        with open(path, "rb") as f:
            data = f.read()
        if not data:
            continue
        print(json.dumps({"file": path, "raw": raw(data)}))
