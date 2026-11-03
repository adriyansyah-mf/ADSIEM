"""Write pefile's tables the v3 extractor needs as a Go source file (data)."""
import sys

import pefile
from pefile import ordlookup


def gostr(b):
    if isinstance(b, bytes):
        b = b.decode("latin-1")
    return '"' + b.replace("\\", "\\\\").replace('"', '\\"') + '"'


out = ["// Code generated from pefile " + pefile.__version__ + " (MIT licence) by ml/v3/dump_pefile_consts.py. DO NOT EDIT.",
       "", "package mlscore", ""]
out.append("// pefileAllowedFilename / pefileAllowedFunctionName: pefile's allowed characters.")
out.append("var pefileAllowedFilename = []byte(" + gostr(pefile.allowed_filename) + ")")
out.append("var pefileAllowedFunctionName = []byte(" + gostr(pefile.allowed_function_name) + ")")
out.append("")


def flags(name, items, strip):
    out.append(f"var {name} = []struct {{\n\tname string\n\tbit  uint32\n}}{{")
    for k, v in items:
        out.append(f"\t{{{gostr(k[strip:])}, 0x{v:x}}},")
    out.append("}")
    out.append("")


flags("pefileSectionFlags", pefile.retrieve_flags(pefile.SECTION_CHARACTERISTICS, "IMAGE_SCN_"), 10)
flags("pefileImageFlags", pefile.retrieve_flags(pefile.IMAGE_CHARACTERISTICS, "IMAGE_FILE_"), 11)
flags("pefileDllFlags", pefile.retrieve_flags(pefile.DLL_CHARACTERISTICS, "IMAGE_DLLCHARACTERISTICS_"), 25)

out.append("var pefileMachine = map[uint16]string{")
for k, v in sorted(pefile.MACHINE_TYPE.items(), key=lambda kv: str(kv[0])):
    if isinstance(k, int):
        out.append(f"\t0x{k:x}: {gostr(v)},")
out.append("}")
out.append("")
out.append("var pefileSubsystem = map[uint16]string{")
for k, v in sorted(pefile.SUBSYSTEM_TYPE.items(), key=lambda kv: str(kv[0])):
    if isinstance(k, int):
        out.append(f"\t{k}: {gostr(v)},")
out.append("}")
out.append("")
out.append("// pefileOrdNames: names of functions imported by ordinal (pefile's ordlookup).")
out.append("var pefileOrdNames = map[string]map[uint16]string{")
for dll, table in sorted(ordlookup.ords.items()):
    out.append(f"\t{gostr(dll)}: {{")
    for o, n in sorted(table.items()):
        out.append(f"\t\t{o}: {gostr(n)},")
    out.append("\t},")
out.append("}")
open(sys.argv[1], "w").write("\n".join(out) + "\n")
print("wrote", sys.argv[1])
