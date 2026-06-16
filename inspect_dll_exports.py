#!/usr/bin/env python3
"""
inspect_dll_exports.py

Inspects all exported functions of a DLL using the pefile library,
prints them in a formatted table, and saves them to exported_functions.txt
in the #pragma comment(linker, ...) format.

Usage:
    python inspect_dll_exports.py <path_to_dll> [--dll-name <name>]

    --dll-name  Override the DLL name on the RIGHT-HAND side of the pragma
                directive (i.e. the target DLL being forwarded to).
                If omitted, the name embedded in the DLL's export directory
                is used.

                Example output without flag:
                  /export:GetFileVersionInfoA=VERSION.GetFileVersionInfoA
                Example output with --dll-name myVersion:
                  /export:GetFileVersionInfoA=myVersion.GetFileVersionInfoA

Examples:
    # Use the DLL's own embedded name (default)
    python inspect_dll_exports.py version.dll

    # Override the RHS dll name (e.g. your proxy DLL will load "myVersion.dll")
    python inspect_dll_exports.py version.dll --dll-name myVersion

Requirements:
    pip install pefile
"""

import sys
import os
import argparse
import pefile


def get_dll_exports(dll_path: str) -> tuple[list[dict], str]:
    """Parse the DLL and return (exports, embedded_dll_stem)."""
    pe = pefile.PE(dll_path)

    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        pe.close()
        return [], ""

    dll_name_raw = pe.DIRECTORY_ENTRY_EXPORT.name
    dll_base_name = (
        dll_name_raw.decode("utf-8", errors="replace")
        if isinstance(dll_name_raw, bytes)
        else str(dll_name_raw)
    )
    embedded_stem = os.path.splitext(dll_base_name)[0]

    exports = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = exp.name.decode("utf-8", errors="replace") if exp.name else None
        forwarded = (
            exp.forwarder.decode("utf-8", errors="replace")
            if exp.forwarder
            else None
        )
        exports.append(
            {
                "ordinal":   exp.ordinal,
                "address":   exp.address,
                "name":      name,
                "forwarded": forwarded,
            }
        )

    pe.close()
    return exports, embedded_stem


def print_table(exports: list[dict], dll_path: str, rhs_dll: str) -> None:
    """Pretty-print the exports as a table."""
    H = ["Ordinal", "Address", "Name", "Forwarded"]

    w_ord  = max(len(H[0]), max((len(str(e["ordinal"])) for e in exports), default=0))
    w_addr = max(len(H[1]), 10)
    w_name = max(len(H[2]), max((len(e["name"] or "(no name)") for e in exports), default=0))
    w_fwd  = max(len(H[3]), max((len(e["forwarded"] or "") for e in exports), default=0))

    sep = f"+-{'-'*w_ord}-+-{'-'*w_addr}-+-{'-'*w_name}-+-{'-'*w_fwd}-+"
    hdr = (f"| {H[0]:<{w_ord}} | {H[1]:<{w_addr}} |"
           f" {H[2]:<{w_name}} | {H[3]:<{w_fwd}} |")

    print(f"\nDLL : {os.path.abspath(dll_path)}")
    print(f"RHS : {rhs_dll}.<FunctionName>")
    print(f"Total exports: {len(exports)}\n")
    print(sep)
    print(hdr)
    print(sep)

    for e in exports:
        ordinal = str(e["ordinal"])
        address = f"0x{e['address']:08X}" if e["address"] else "N/A"
        name    = e["name"] or "(no name)"
        fwd     = e["forwarded"] or ""
        print(f"| {ordinal:<{w_ord}} | {address:<{w_addr}} |"
              f" {name:<{w_name}} | {fwd:<{w_fwd}} |")

    print(sep)


def save_pragmas(
    exports: list[dict],
    rhs_dll: str,
    out_path: str = "exported_functions.txt",
) -> None:
    """Write one #pragma comment line per export to the output file."""
    lines = []
    for e in exports:
        # Both sides always use the real function name; only the DLL stem on
        # the right-hand side can be overridden via --dll-name.
        func = e["name"] if e["name"] else f"#{e['ordinal']}"
        lines.append(f'#pragma comment(linker, "/export:{func}={rhs_dll}.{func}")')

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"\n[+] Saved {len(lines)} pragma(s) to '{out_path}'")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect DLL exports and generate #pragma comment(linker, ...) directives.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s version.dll\n"
            "  %(prog)s version.dll --dll-name myVersion\n"
        ),
    )
    parser.add_argument("dll", metavar="<dll>", help="Path to the DLL file to inspect")
    parser.add_argument(
        "--dll-name",
        metavar="<name>",
        default=None,
        help=(
            "Override the DLL name on the RIGHT-HAND side of the pragma directive "
            "(the target being forwarded to). Defaults to the name embedded in the "
            "DLL's own export directory."
        ),
    )

    args = parser.parse_args()

    if not os.path.isfile(args.dll):
        print(f"[!] File not found: '{args.dll}'")
        sys.exit(1)

    print(f"[*] Parsing '{args.dll}' ...")

    try:
        exports, embedded_stem = get_dll_exports(args.dll)
    except pefile.PEFormatError as exc:
        print(f"[!] pefile error: {exc}")
        sys.exit(1)

    if not exports:
        print("[!] No exports found.")
        sys.exit(0)

    exports.sort(key=lambda e: e["ordinal"])

    # Use the override if supplied, otherwise fall back to the embedded name
    rhs_dll = args.dll_name if args.dll_name else embedded_stem

    if args.dll_name:
        print(f"[*] RHS dll name overridden: '{embedded_stem}' -> '{rhs_dll}'")

    print_table(exports, args.dll, rhs_dll)
    save_pragmas(exports, rhs_dll)


if __name__ == "__main__":
    main()
