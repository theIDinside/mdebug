#include "disassemble.h"
#include "../target.h"
#include "distorm/include/distorm.h"
#include "elf.h"

namespace sym {
void
disassemble_backwards(Target *target, AddrPtr addr, u32 ins_offset, u32 total,
                      std::vector<sym::Disassembly> &result)
{
  result.reserve(total);
  ElfSection *text = target->get_text_section(addr);
  ASSERT(text != nullptr, "Could not find .text section containing {}", addr);
  auto total_disassembled = 0u;
  auto file_index_res = target->cu_file_from_pc(addr);
  ASSERT(file_index_res.has_value(), "Could not find CU with address {}", addr);
  auto file_index = *file_index_res;
  auto f = &target->cu_files()[file_index];
  auto current_addr = addr;
  auto lt = f->line_table();
  auto entry_it = std::lower_bound(lt.cbegin(), lt.cend(), current_addr,
                                   [](const auto &lte, auto addr) { return lte.pc >= addr; });
  _DInst decomposed[std::min(ins_offset, total)];
  // simple path, we *for sure* got more instructions than requested, because 1 "logical breakpoint location"
  // generally involves quite a few instructions, sometimes, quite a lot.
  auto it = std::make_reverse_iterator(entry_it);
  auto end = std::crend(lt);
  auto end_addr = addr;

  while (total_disassembled < ins_offset && total_disassembled < total) {
    --it;
    if (it == end) {
      if (file_index > 0) {
        f = &target->cu_files()[--file_index];
        it = std::crbegin(f->line_table());
        end = std::crend(f->line_table());
      } else {
        const auto remaining_invalid = total - total_disassembled;
        total_disassembled += (total - total_disassembled);
        for (auto i = 0u; i < remaining_invalid; ++i) {
          result.insert(result.begin(), sym::Disassembly{nullptr, "", "<unknown>", "<unknown>", 0, 0});
        }
        return;
      }
    }
    _CodeInfo info{};
    info.dt = Decode64Bits;
    info.codeOffset = it->pc;
    info.code = text->into(it->pc);
    info.codeLen = static_cast<int>(addr - it->pc);
    addr = it->pc;
    u32 result_count = 0;
    const auto res =
        distorm_decompose(&info, (decomposed + total_disassembled), total - total_disassembled, &result_count);
    int idx = result_count;
    ASSERT(res == DECRES_SUCCESS, "Failed to decompose instructions between {} .. {}", it->pc, end_addr);
    total_disassembled += result_count;
    for (auto i = idx - 1; i >= 0; --i) {
      _DecodedInst decode;
      distorm_format(&info, &decomposed[i], &decode);
      std::string opcode;
      opcode.reserve(decode.instructionHex.length);
      std::string mnemonic;
      mnemonic.reserve(decode.mnemonic.length);
      std::copy(decode.instructionHex.p, decode.instructionHex.p + decode.instructionHex.length,
                std::back_inserter(opcode));
      std::copy(decode.mnemonic.p, decode.mnemonic.p + decode.mnemonic.length, std::back_inserter(mnemonic));
      result.insert(result.begin(),
                    sym::Disassembly{decode.offset, opcode, mnemonic, f->file(it->file), it->line, it->column});
    }
  }
}
} // namespace sym