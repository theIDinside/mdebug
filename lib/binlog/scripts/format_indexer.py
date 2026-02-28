#!/usr/bin/env python3
"""
Binary Logging Format String Indexer

Scans provided source files for log macro calls (DBGLOG, DBGBUFLOG, BINLOG),
extracts format strings, assigns unique IDs, and generates:
1. log_formats.def - Format string definitions for the decoder
2. log_format_map.h - Compile-time hash→ID lookup table

Usage:
    python format_indexer.py --sources file1.cpp file2.h ... --output-dir path/to/output

Or with a file list:
    python format_indexer.py --sources-file sources.txt --output-dir path/to/output
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Regex patterns to match log macro calls
# Matches: DBGLOG(channel, "format string", ...)
# Matches: BINLOG(channel, "format string", ...)
LOG_MACRO_PATTERN = re.compile(
    r'\b(?:DBGLOG|DBGBUFLOG|BINLOG)\s*\([^,]+,\s*"([^"]*)"',
    re.MULTILINE
)


def fnv1a_hash(text: str) -> int:
    """
    Compute FNV-1a hash for a string (32-bit version).
    This must match the C++ implementation in log_format_map.h.
    """
    hash_value = 0x811c9dc5  # FNV offset basis (32-bit)
    fnv_prime = 0x01000193  # FNV prime (32-bit)

    for char in text:
        hash_value ^= ord(char)
        hash_value = (hash_value * fnv_prime) & 0xFFFFFFFF  # Keep 32-bit

    return hash_value


def scan_source_file(file_path: Path) -> List[Tuple[str, str, int]]:
    """
    Scan a single source file for log format strings.
    Returns list of (format_string, file_path, line_number) tuples.
    """
    format_strings = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Find all matches with line numbers
        for line_num, line in enumerate(content.splitlines(), start=1):
            for match in LOG_MACRO_PATTERN.finditer(line):
                format_str = match.group(1)
                format_strings.append((format_str, str(file_path), line_num))
    except Exception as e:
        print(f"Warning: Failed to read {file_path}: {e}", file=sys.stderr)

    return format_strings


def scan_source_files(file_paths: List[Path]) -> List[Tuple[str, str, int]]:
    """
    Scan multiple source files for log format strings.
    Returns list of (format_string, file_path, line_number) tuples.
    """
    all_format_strings = []

    for file_path in file_paths:
        if file_path.suffix in ['.cpp', '.cc', '.cxx', '.c', '.h', '.hpp', '.hxx']:
            all_format_strings.extend(scan_source_file(file_path))

    return all_format_strings


def deduplicate_formats(format_list: List[Tuple[str, str, int]]) -> Dict[str, int]:
    """
    Deduplicate format strings and assign sequential IDs.
    Returns dict mapping format_string → ID.
    """
    # Use dict to preserve insertion order (Python 3.7+) and deduplicate
    unique_formats = {}
    next_id = 1

    for format_str, file_path, line_num in format_list:
        if format_str not in unique_formats:
            unique_formats[format_str] = next_id
            next_id += 1

    return unique_formats


def escape_string(s: str) -> str:
    """Escape special characters for C++ string literals."""
    return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')


def generate_def_file(format_map: Dict[str, int], output_path: Path):
    """
    Generate log_formats.def file.
    Format: LOG_FORMAT(id, "format string")
    """
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("/* GENERATED FILE - DO NOT ALTER */\n")
        f.write("/* This file contains all log format strings indexed by ID */\n")
        f.write("/* Usage: #define LOG_FORMAT(id, str) ... */\n\n")

        for format_str, format_id in sorted(format_map.items(), key=lambda x: x[1]):
            escaped = escape_string(format_str)
            f.write(f'LOG_FORMAT({format_id}, "{escaped}")\n')


def generate_hash_map_header(format_map: Dict[str, int], output_path: Path, namespace: str, typedef_include: str):
    """
    Generate log_format_map.h with compile-time hash→ID lookup.
    """
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("/** GENERATED FILE - DO NOT ALTER */\n")
        f.write("#pragma once\n")

        if typedef_include:
            f.write(f"#include <{typedef_include}>\n")
        else:
            f.write("#include <cstdint>\n")

        f.write(f"\nnamespace {namespace} {{\n\n")

        # Use explicit types if no typedef include
        u32_type = "u32" if typedef_include else "std::uint32_t"

        f.write(f"""/**
 * FNV-1a hash function for compile-time format string hashing.
 * Must match the Python implementation in format_indexer.py.
 */
constexpr {u32_type}
HashFormatString(const char *str) noexcept
{{
  {u32_type} hash = 0x811c9dc5u;  // FNV offset basis
  for (const char *p = str; *p != '\\0'; ++p) {{
    hash ^= static_cast<{u32_type}>(*p);
    hash *= 0x01000193u;  // FNV prime
  }}
  return hash;
}}

/**
 * Compile-time lookup from format string hash to format ID.
 * Returns 0 if the format string is not found (unknown format).
 */
constexpr {u32_type}
GetFormatId({u32_type} hash) noexcept
{{
  switch (hash) {{
""")

        # Generate switch cases for each format string
        for format_str, format_id in sorted(format_map.items(), key=lambda x: x[1]):
            hash_value = fnv1a_hash(format_str)
            escaped = escape_string(format_str)
            f.write(f'    case 0x{hash_value:08x}u: return {format_id};  // "{escaped}"\n')

        f.write(f"""    default: return 0;  // Unknown format
  }}
}}

}} // namespace {namespace}
""")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Index log format strings from source files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan specific files
  python format_indexer.py --sources src/main.cpp src/util.cpp --output-dir build/generated

  # Scan files from a list
  python format_indexer.py --sources-file sources.txt --output-dir build/generated

  # Customize namespace
  python format_indexer.py --sources file.cpp --output-dir out --namespace myapp::logging
        """
    )

    parser.add_argument('--sources', nargs='*', help='Source files to scan')
    parser.add_argument('--sources-file', help='File containing list of source files (one per line)')
    parser.add_argument('--output-dir', help='Output directory for generated files (used if --def-file and --map-file not specified)')
    parser.add_argument('--def-file', help='Output path for log_formats.def file')
    parser.add_argument('--map-file', help='Output path for log_format_map.h file')
    parser.add_argument('--namespace', default='binlog::detail', help='C++ namespace for generated code (default: binlog::detail)')
    parser.add_argument('--typedef-include', default='', help='Header file for type definitions (e.g., common/typedefs.h)')

    args = parser.parse_args()

    # Collect source files
    source_files = []

    if args.sources:
        source_files.extend([Path(f) for f in args.sources])

    if args.sources_file:
        sources_file = Path(args.sources_file)
        if not sources_file.exists():
            print(f"Error: Sources file not found: {sources_file}", file=sys.stderr)
            return 1

        with open(sources_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    source_files.append(Path(line))

    if not source_files:
        print("Error: No source files specified. Use --sources or --sources-file", file=sys.stderr)
        parser.print_help()
        return 1

    # Scan files
    print(f"Scanning {len(source_files)} source files for log format strings...")
    format_list = scan_source_files(source_files)
    print(f"Found {len(format_list)} log macro calls")

    format_map = deduplicate_formats(format_list)
    print(f"Identified {len(format_map)} unique format strings")

    if not format_map:
        print("Warning: No log format strings found!", file=sys.stderr)

    # Determine output file paths
    if args.def_file and args.map_file:
        def_file = Path(args.def_file)
        hash_map_file = Path(args.map_file)
    elif args.output_dir:
        output_dir = Path(args.output_dir)
        def_file = output_dir / 'log_formats.def'
        hash_map_file = output_dir / 'log_format_map.h'
    else:
        print("Error: Must specify either --output-dir or both --def-file and --map-file", file=sys.stderr)
        return 1

    # Ensure directories exist
    def_file.parent.mkdir(parents=True, exist_ok=True)
    hash_map_file.parent.mkdir(parents=True, exist_ok=True)

    generate_def_file(format_map, def_file)
    print(f"Generated {def_file}")

    generate_hash_map_header(format_map, hash_map_file, args.namespace, args.typedef_include)
    print(f"Generated {hash_map_file}")

    print(f"Success! Indexed {len(format_map)} format strings")
    return 0


if __name__ == '__main__':
    sys.exit(main())
