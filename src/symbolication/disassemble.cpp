#include "disassemble.h"
#include "../supervisor.h"
#include "elf.h"
#include "fmt/core.h"
#include "objfile.h"
#include "symbolication/dwarf/lnp.h"
#include "symbolication/fnsymbol.h"
#include "zydis/Zydis.h"
#include <algorithm>
#include <optional>
#include <set>

namespace sym {

std::optional<std::tuple<dw::RelocatedLteIterator, dw::RelocatedLteIterator, dw::LineTable>>
get_lte_range(SymbolFile *obj, std::vector<sym::CompilationUnit *> symtabs, AddrPtr addr)
{
  for (auto st : symtabs) {
    if (auto lt_opt = st->get_linetable(obj); lt_opt) {
      auto lt = lt_opt.value();
      auto lte_it = lt.find_by_pc(addr);
      if (lte_it != std::end(lt)) {
        if (lte_it.get().pc > addr && (lte_it - 1).get().pc <= addr) {
          return std::optional{std::tuple{lte_it - 1, lte_it, lt}};
        } else if (lte_it.get().pc <= addr && (lte_it + 1).get().pc > addr) {
          return std::optional{std::tuple{lte_it, lte_it + 1, lt}};
        }
      }
    }
  }
  return std::nullopt;
}

static sym::Disassembly
create_disasm_entry(TraceeController *target, AddrPtr vm_address, const ZydisDisassembledInstruction &ins,
                    const u8 *exec_data_ptr) noexcept
{
  std::string machine_code{};
  machine_code.resize(ins.info.length * 2 + ins.info.length - 1, ' ');
  auto mc_b = machine_code.begin();
  for (auto i = 0; i < ins.info.length; i++) {
    fmt::format_to(mc_b, "{:02x}", *(exec_data_ptr + i));
    mc_b += 3;
  }
  auto obj = target->find_obj_by_pc(vm_address);
  auto cus = obj->getSourceInfos(vm_address);
  if (!cus.empty()) {
    auto lte_range_opt = get_lte_range(obj, cus, vm_address);
    if (lte_range_opt) {
      const auto [begin_rel, end_rel, lt] = lte_range_opt.value();
      const auto begin = begin_rel.get();
      ASSERT(vm_address >= begin.pc && vm_address <= end_rel.get().pc,
             "Address {} does not land inside LTE range {} .. {}", vm_address, begin.pc, end_rel.get().pc);
      return sym::Disassembly{.address = vm_address,
                              .opcode = std::move(machine_code),
                              .instruction = ins.text,
                              .source_name = lt.file(begin.file)->file_name,
                              .source_path = lt.file(begin.file)->file_name,
                              .line = begin.line,
                              .column = begin.column};
    } else {
      return sym::Disassembly{.address = vm_address,
                              .opcode = std::move(machine_code),
                              .instruction = ins.text,
                              .source_name = "",
                              .source_path = "",
                              .line = 0,
                              .column = 0};
    }
  } else {
    return sym::Disassembly{.address = vm_address,
                            .opcode = std::move(machine_code),
                            .instruction = ins.text,
                            .source_name = "",
                            .source_path = "",
                            .line = 0,
                            .column = 0};
  }
}

void
zydis_disasm_backwards(TraceeController *target, AddrPtr addr, i32 ins_offset,
                       std::vector<sym::Disassembly> &output) noexcept
{
  const auto objfile = target->find_obj_by_pc(addr);
  const auto text = objfile->objectFile()->elf->get_section(".text");
  ZydisDisassembledInstruction instruction;

  // This hurts my soul and is so hacky.
  std::set<AddrPtr> disassembled_addresses{};
  auto srcs = objfile->getSourceInfos(addr);

  std::sort(srcs.begin(), srcs.end(), [](auto a, auto b) { return a->start_pc() >= b->start_pc(); });

  for (auto src : srcs) {
    if (static_cast<int>(output.size()) <= ins_offset) {
      auto add = src->start_pc();
      auto exec_data_ptr = text->into(add);
      std::vector<sym::Disassembly> result;
      while (ZYAN_SUCCESS(ZydisDisassembleATT(ZYDIS_MACHINE_MODE_LONG_64, add, exec_data_ptr,
                                              text->remaining_bytes(exec_data_ptr), &instruction)) &&
             add <= addr) {
        if (!disassembled_addresses.contains(add)) {
          result.push_back(create_disasm_entry(target, add, instruction, exec_data_ptr));
        }
        disassembled_addresses.insert(add);
        add = offset(add, instruction.info.length);
        exec_data_ptr += instruction.info.length;
      }
      addr = src->start_pc();
      for (auto i = result.rbegin(); i != result.rend(); i++) {
        output.insert(output.begin(), *i);
      }
    }
  }

  // Disassemble instructions that aren't referenced by DWARF debug info
  if (static_cast<int>(output.size()) <= ins_offset) {
    auto add = text->address;
    auto exec_data_ptr = text->into(text->address);
    std::vector<sym::Disassembly> result;
    DBGLOG(core, "Disassembling non-DWARF referenced instructions");
    while (ZYAN_SUCCESS(ZydisDisassembleATT(ZYDIS_MACHINE_MODE_LONG_64, add, exec_data_ptr,
                                            text->remaining_bytes(exec_data_ptr), &instruction)) &&
           add <= addr) {
      if (!disassembled_addresses.contains(add)) {
        result.push_back(create_disasm_entry(target, add, instruction, exec_data_ptr));
      }
      disassembled_addresses.insert(add);
      add = offset(add, instruction.info.length);
      exec_data_ptr += instruction.info.length;
    }
    for (auto i = result.rbegin(); i != result.rend(); i++) {
      if (output.begin()->address != i->address) {
        output.insert(output.begin(), *i);
      }
    }
  }
  // Fill remaining with "invalid values"
  if (static_cast<int>(output.size()) <= ins_offset) {
    while (static_cast<int>(output.size()) < ins_offset) {
      output.insert(output.begin(), sym::Disassembly{nullptr, "", "", "", "", 0, 0});
    }
  }
}

void
zydis_disasm(TraceeController *target, AddrPtr addr, u32 ins_offset, u32 total,
             std::vector<sym::Disassembly> &output) noexcept
{
  const ElfSection *text = target->get_text_section(addr);
  const auto start_exec_data = text->into(addr);
  auto exec_data_ptr = start_exec_data;
  ZydisDisassembledInstruction instruction;
  auto vm_address = addr;

  if (ins_offset > 0) {
    while (ZYAN_SUCCESS(ZydisDisassembleATT(ZYDIS_MACHINE_MODE_LONG_64, vm_address, exec_data_ptr,
                                            text->remaining_bytes(exec_data_ptr), &instruction)) &&
           ins_offset != 0) {
      vm_address = offset(vm_address, instruction.info.length);
      exec_data_ptr += instruction.info.length;
      --ins_offset;
    }
  }

  while (ZYAN_SUCCESS(ZydisDisassembleATT(ZYDIS_MACHINE_MODE_LONG_64, vm_address, exec_data_ptr,
                                          text->remaining_bytes(exec_data_ptr), &instruction)) &&
         total != 0) {
    output.push_back(create_disasm_entry(target, vm_address, instruction, exec_data_ptr));
    vm_address = offset(vm_address, instruction.info.length);
    exec_data_ptr += instruction.info.length;
    --total;
  }
}
} // namespace sym