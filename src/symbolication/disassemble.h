#pragma once
#include "../common.h"

namespace sym {
struct Disassembly
{
  TPtr<void> address;
  std::string opcode;
  std::string instruction;
  std::string_view source;
  u32 line;
  u32 column;
};

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
        R"({{ "address": "{}", "instructionBytes": "{}", "instruction": "{}", "location": {{ "name": "{}", "path": "{}" }}, "line": {}, "column": {} }})",
        disasm.address, disasm.opcode, disasm.instruction, disasm.source, disasm.source, disasm.line,
        disasm.column);
  }
};
}; // namespace fmt