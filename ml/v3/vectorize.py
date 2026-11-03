"""Feature vector (v3) for the EMBER2024-trained models, from raw v3 features.

The same vector is built by the agent in Go (agent/internal/mlscore/vector_v3.go)
from its own raw features (v3.go); ml/v3/compare_vectors.py checks they agree.
Hashing is FNV-1a 32-bit (ml/vectorize.py), never sklearn's FeatureHasher.

Groups (in order): general 7 | histogram 256 | byteentropy 256 | strings 177 |
header 74 | section 224 | imports 1282 | exports 129 | datadirectories 34 |
richheader 33. EMBER2024's authenticode and pefilewarnings are not used.
"""
from __future__ import annotations


def fnv1a(s: str) -> int:
    """FNV-1a 32-bit of the UTF-8 bytes (as ml/vectorize.py and the Go side)."""
    h = 0x811C9DC5
    for b in s.encode("utf-8", "surrogatepass"):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h

STRING_KEYS = sorted([
    "url", "ipv4_addr", "ipv6_addr", "mac_addr", "email_addr", "btc_wallet", "file_path", "dos_msg", "registry_key",
    "/dev/", "/proc/", "/bin/", "/usr/", "/tmp/", "/URI", "/FlateDecode", "/EmbeddedFile", "html", "javascript",
    "<script", ".click(", "onlick", "powershell", "Invoke-Expression", "Invoke-Command", "Start-process", "get",
    "post", "http", "http://", "https://", "ftp", "useragent", "cookie", "internet", "download", "connect", "base64",
    "base64string", "crypt", "encode", "decode", "cache", "certificate", "clipboard", "command", "create", "debug",
    "delete", "desktop", "directory", "disk", "environment", "enum", "exit", "file", "hostname", "install", "hidden",
    "keyboard", "memory", "module", "mutex", "password", "privilege", "process", "remote", "resource", "security",
    "service", "shell", "snapshot", "system", "thread", "token", "wallet", "window"])

MACHINES = ["IMAGE_FILE_MACHINE_UNKNOWN", "IMAGE_FILE_MACHINE_I386", "IMAGE_FILE_MACHINE_R3000",
            "IMAGE_FILE_MACHINE_R4000", "IMAGE_FILE_MACHINE_R10000", "IMAGE_FILE_MACHINE_WCEMIPSV2",
            "IMAGE_FILE_MACHINE_ALPHA", "IMAGE_FILE_MACHINE_SH3", "IMAGE_FILE_MACHINE_SH3DSP",
            "IMAGE_FILE_MACHINE_SH3E", "IMAGE_FILE_MACHINE_SH4", "IMAGE_FILE_MACHINE_SH5", "IMAGE_FILE_MACHINE_ARM",
            "IMAGE_FILE_MACHINE_THUMB", "IMAGE_FILE_MACHINE_ARMNT", "IMAGE_FILE_MACHINE_AM33",
            "IMAGE_FILE_MACHINE_POWERPC", "IMAGE_FILE_MACHINE_POWERPCFP", "IMAGE_FILE_MACHINE_IA64",
            "IMAGE_FILE_MACHINE_MIPS16", "IMAGE_FILE_MACHINE_ALPHA64", "IMAGE_FILE_MACHINE_AXP64",
            "IMAGE_FILE_MACHINE_MIPSFPU", "IMAGE_FILE_MACHINE_MIPSFPU16", "IMAGE_FILE_MACHINE_TRICORE",
            "IMAGE_FILE_MACHINE_CEF", "IMAGE_FILE_MACHINE_EBC", "IMAGE_FILE_MACHINE_RISCV32",
            "IMAGE_FILE_MACHINE_RISCV64", "IMAGE_FILE_MACHINE_RISCV128", "IMAGE_FILE_MACHINE_LOONGARCH32",
            "IMAGE_FILE_MACHINE_LOONGARCH64", "IMAGE_FILE_MACHINE_AMD64", "IMAGE_FILE_MACHINE_M32R",
            "IMAGE_FILE_MACHINE_ARM64", "IMAGE_FILE_MACHINE_CEE"]
SUBSYSTEMS = ["IMAGE_SUBSYSTEM_UNKNOWN", "IMAGE_SUBSYSTEM_NATIVE", "IMAGE_SUBSYSTEM_WINDOWS_GUI",
              "IMAGE_SUBSYSTEM_WINDOWS_CUI", "IMAGE_SUBSYSTEM_OS2_CUI", "IMAGE_SUBSYSTEM_POSIX_CUI",
              "IMAGE_SUBSYSTEM_NATIVE_WINDOWS", "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI", "IMAGE_SUBSYSTEM_EFI_APPLICATION",
              "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
              "IMAGE_SUBSYSTEM_EFI_ROM", "IMAGE_SUBSYSTEM_XBOX", "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"]
IMAGE_CHARS = ["RELOCS_STRIPPED", "EXECUTABLE_IMAGE", "LINE_NUMS_STRIPPED", "LOCAL_SYMS_STRIPPED",
               "AGGRESIVE_WS_TRIM", "LARGE_ADDRESS_AWARE", "16BIT_MACHINE", "BYTES_REVERSED_LO", "32BIT_MACHINE",
               "DEBUG_STRIPPED", "REMOVABLE_RUN_FROM_SWAP", "NET_RUN_FROM_SWAP", "SYSTEM", "DLL", "UP_SYSTEM_ONLY",
               "BYTES_REVERSED_HI"]
DLL_CHARS = ["HIGH_ENTROPY_VA", "DYNAMIC_BASE", "FORCE_INTEGRITY", "NX_COMPAT", "NO_ISOLATION", "NO_SEH", "NO_BIND",
             "APPCONTAINER", "WDM_DRIVER", "GUARD_CF", "TERMINAL_SERVER_AWARE"]
DOS = ["e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc", "e_ss", "e_sp", "e_csum",
       "e_ip", "e_cs", "e_lfarlc", "e_ovno", "e_oemid", "e_oeminfo", "e_lfanew"]
OPTIONAL = ["major_image_version", "minor_image_version", "major_linker_version", "minor_linker_version",
            "major_operating_system_version", "minor_operating_system_version", "major_subsystem_version",
            "minor_subsystem_version", "sizeof_code", "sizeof_headers", "sizeof_image", "sizeof_initialized_data",
            "sizeof_uninitialized_data", "sizeof_stack_reserve", "sizeof_stack_commit", "sizeof_heap_reserve",
            "sizeof_heap_commit", "address_of_entrypoint", "base_of_code", "image_base", "section_alignment",
            "checksum", "number_of_rvas_and_sizes"]
DIRS = ["EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "COPYRIGHT", "GLOBALPTR",
        "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED"]

GROUPS = [("general", 7), ("histogram", 256), ("byteentropy", 256), ("strings", 177), ("header", 74),
          ("section", 224), ("imports", 1282), ("exports", 129), ("datadirectories", 34), ("richheader", 33)]
DIM = sum(n for _, n in GROUPS)


def hashed(items: list[str], n: int) -> list[float]:
    out = [0.0] * n
    for k in items:
        out[fnv1a(k) % n] += 1.0
    return out


def hashed_pairs(pairs: list[tuple[str, float]], n: int) -> list[float]:
    out = [0.0] * n
    for k, v in pairs:
        out[fnv1a(k) % n] += float(v)
    return out


def _norm(counts) -> list[float]:
    total = float(sum(counts))
    return [c / total for c in counts] if total > 0 else [0.0] * len(counts)


def _general(g):
    sb = list(g.get("start_bytes", [0, 0, 0, 0])) + [0, 0, 0, 0]
    return [float(g.get("size", 0)), float(g.get("entropy", 0)), float(g.get("is_pe", 0))] + [float(x) for x in sb[:4]]


def _strings(s):
    printables = float(s.get("printables", 0))
    div = printables if printables > 0 else 1.0
    dist = list(s.get("printabledist", [])) + [0] * 96
    counts = s.get("string_counts", {}) or {}
    return ([float(s.get("numstrings", 0)), float(s.get("avlength", 0)), printables]
            + [float(x) / div for x in dist[:96]] + [float(s.get("entropy", 0))]
            + [float(counts.get(k, 0)) for k in STRING_KEYS])


def _header(h):
    if not h:
        return [0.0] * 74
    coff, opt, dos = h.get("coff", {}), h.get("optional", {}), h.get("dos", {})
    out = [float(coff.get(k, 0)) for k in ("timestamp", "number_of_sections", "number_of_symbols",
                                           "sizeof_optional_header", "pointer_to_symbol_table")]
    m, sub = coff.get("machine", ""), opt.get("subsystem", "")
    out += [float(MACHINES.index(m)) if m in MACHINES else 0.0, float(SUBSYSTEMS.index(sub)) if sub in SUBSYSTEMS else 0.0]
    out += [float(opt.get(k, 0)) for k in OPTIONAL]
    chars, dll = set(coff.get("characteristics", [])), set(opt.get("dll_characteristics", []))
    out += [1.0 if c in chars else 0.0 for c in IMAGE_CHARS]
    out += [1.0 if c in dll else 0.0 for c in DLL_CHARS]
    out += [float(dos.get(k, 0)) for k in DOS]
    return out


def _section(sec):
    if not sec:
        return [0.0] * 224
    ss = sec.get("sections", [])
    ov = sec.get("overlay", {"size": 0, "size_ratio": 0, "entropy": 0})
    ent = [s["entropy"] for s in ss] + [ov.get("entropy", 0), 0]
    sr = [s["size_ratio"] for s in ss] + [ov.get("size_ratio", 0), 0]
    vr = [s["vsize_ratio"] for s in ss] + [0]
    general = [len(ss), sum(1 for s in ss if s["size"] == 0), sum(1 for s in ss if s["name"] == ""),
               sum(1 for s in ss if "MEM_READ" in s["props"] and "MEM_EXECUTE" in s["props"]),
               sum(1 for s in ss if "MEM_WRITE" in s["props"]),
               max(ent), min(ent), max(sr), min(sr), max(vr), min(vr)]
    return ([float(x) for x in general]
            + hashed_pairs([(s["name"], s["size"]) for s in ss], 50)
            + hashed_pairs([(s["name"], s["vsize"]) for s in ss], 50)
            + hashed_pairs([(s["name"], s["entropy"]) for s in ss], 50)
            + hashed([f"{s['name']}:{p}" for s in ss for p in s["props"]], 50)
            + hashed([sec.get("entry", "")], 10)
            + [float(ov.get("size", 0)), float(ov.get("size_ratio", 0)), float(ov.get("entropy", 0))])


def _imports(imp):
    if not imp:
        return [0.0] * 1282
    libs = sorted(set(k.lower() for k in imp))
    funcs = [lib.lower() + ":" + e for lib, el in imp.items() for e in el]
    return [float(len(funcs)), float(len(libs))] + hashed(libs, 256) + hashed(funcs, 1024)


def _exports(exp):
    if not exp:
        return [0.0] * 129
    return [float(len(exp))] + hashed(exp, 128)


def _datadirs(dd):
    out = [0.0] * 34
    if not dd:
        return out
    for d in dd[1:]:
        if d.get("name") in DIRS:
            i = DIRS.index(d["name"])
            out[2 * i], out[2 * i + 1] = float(d.get("size", 0)), float(d.get("virtual_address", 0))
    out[32], out[33] = float(dd[0].get("has_relocs", 0)), float(dd[0].get("has_dynamic_relocs", 0))
    return out


def _rich(values):
    if not values:
        return [0.0] * 33
    pairs = [(str(values[i]), values[i + 1]) for i in range(0, len(values) - 1, 2)]
    return [float(len(values) // 2)] + hashed_pairs(pairs, 32)


def vector(raw: dict) -> list[float]:
    v = (_general(raw.get("general", {})) + _norm(raw.get("histogram", [0] * 256))
         + _norm(raw.get("byteentropy", [0] * 256)) + _strings(raw.get("strings", {}))
         + _header(raw.get("header")) + _section(raw.get("section")) + _imports(raw.get("imports"))
         + _exports(raw.get("exports")) + _datadirs(raw.get("datadirectories")) + _rich(raw.get("richheader")))
    assert len(v) == DIM, (len(v), DIM)
    return v
