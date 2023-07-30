#pragma once
#include "../common.h"

struct TraceeController;
struct ElfSection;
class CompilationUnitFile;
struct LineTableEntry;

namespace sym {
struct Disassembly
{
  AddrPtr address;
  std::string opcode;
  std::string instruction;
  std::string_view source_name;
  std::string_view source_path;
  u32 line;
  u32 column;
};

void zydis_disasm_backwards(TraceeController *target, AddrPtr addr, i32 ins_offset,
                            std::vector<sym::Disassembly> &output) noexcept;

void zydis_disasm(TraceeController *target, AddrPtr addr, u32 ins_offset, u32 total,
                  std::vector<sym::Disassembly> &output) noexcept;
} // namespace sym

namespace fmt {
template <> struct formatter<sym::Disassembly>
{

  template <typename ParseContext>
  constexpr auto
  parse(ParseContext &ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto
  format(sym::Disassembly const &disasm, FormatContext &ctx) const
  {
    return fmt::format_to(
        ctx.out(),
        R"({{ "address": "{}", "instructionBytes": "{}", "instruction": "{}", "location": {{ "name": "{}", "path": "{}/{}" }}, "line": {}, "column": {} }})",
        disasm.address, disasm.opcode, disasm.instruction, disasm.source_name, disasm.source_path,
        disasm.source_name, disasm.line, disasm.column);
  }
};
}; // namespace fmt