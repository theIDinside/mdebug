/** LICENSE TEMPLATE */
#pragma once

// mdb
#include <common.h>
#include <common/formatter.h>
#include <common/typedefs.h>
#include <tracee_pointer.h>

namespace mdb {
namespace tc {
class SupervisorState;
}

struct ElfSection;
struct LineTableEntry;
} // namespace mdb

namespace mdb::sym {
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

void DisassembleBackwards(
  tc::SupervisorState *target, AddrPtr addr, i32 ins_offset, std::vector<sym::Disassembly> &output) noexcept;

void Disassemble(tc::SupervisorState *target,
  AddrPtr addr,
  u32 ins_offset,
  u32 total,
  std::vector<sym::Disassembly> &output) noexcept;
} // namespace mdb::sym

namespace sym = mdb::sym;
template <> struct std::formatter<sym::Disassembly>
{
  BASIC_PARSE
  template <typename FormatContext>
  auto
  format(sym::Disassembly const &disasm, FormatContext &ctx) const
  {
    return std::format_to(ctx.out(),
      R"({{ "address": "{}", "instructionBytes": "{}", "instruction": "{}", "location": {{ "name": "{}", "path": "{}/{}" }}, "line": {}, "column": {} }})",
      disasm.address,
      disasm.opcode,
      disasm.instruction,
      disasm.source_name,
      disasm.source_path,
      disasm.source_name,
      disasm.line,
      disasm.column);
  }
};