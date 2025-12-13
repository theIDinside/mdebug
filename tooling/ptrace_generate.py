import re


def parse_enums_from_file(filename, target_enums):
    with open(filename, "r", encoding="utf-8") as f:
        content = f.read()

    # Regex to capture entire enum blocks
    enum_pattern = re.compile(r"enum\s+(\w+)\s*\{([^}]*)\};", re.MULTILINE | re.DOTALL)

    results = {}

    for match in enum_pattern.finditer(content):
        enum_name, body = match.groups()
        if enum_name not in target_enums:
            continue

        entries = []
        # Split enum body by commas, strip whitespace
        for line in body.split(","):
            line = line.strip()
            if not line or line.startswith("/*"):  # skip comments/empty
                continue

            # Match NAME = VALUE
            m = re.match(r"([A-Za-z0-9_]+)\s*=\s*([^/\s]+)", line)
            if m:
                name, value = m.groups()
                entries.append((name, value))
            else:
                # Handle case: NAME without explicit value
                m = re.match(r"([A-Za-z0-9_]+)", line)
                if m:
                    name = m.group(1)
                    entries.append((name, None))

        results[enum_name] = entries

    return results


def snakeToPascal(s: str) -> str:
    return "".join(word.capitalize() for word in s.split("_"))


if __name__ == "__main__":
    filename = "/usr/include/bits/ptrace-shared.h"  # change to your actual filename
    target_enums = {"__ptrace_eventcodes", "__ptrace_setoptions"}

    parsed = parse_enums_from_file(filename, target_enums)

    source = [
        """
#pragma once

// Constructs the scaffolding for a modern enum type.
#include <common/macros.h>

// Enum value "compile time constructor" macro, passed to ENUM_TYPE_METADATA as third arg
#define ENUM_VALUE(Name, Value) Name = Value,
"""
    ]
    macros = []

    for enumName, values in parsed.items():
        macros.append(f"// Generation for {enumName}")
        typeName = snakeToPascal(enumName[2:])
        macroName = f"FOR_EACH_PTRACE_{enumName[2:].upper()}"
        macroDefinition = f"#define {macroName}(ITEM)"
        macros.append(f"{macroDefinition} \\")
        lines = [f"  ITEM({name}, {value})" for name, value in values]
        for line in lines[:-1]:
            macros.append(f"{line} \\")
        macros.append(lines[-1])
        macros.append("")
        macros.append(f"ENUM_TYPE_METADATA({typeName}, {macroName}, ENUM_VALUE, int)")
        macros.append("")

    for line in macros:
        source.append(line)

    print(f"// macro: \n{"\n".join(source)}")
