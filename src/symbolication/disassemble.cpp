#include "disassemble.h"
#include "../tracee_controller.h"
#include "elf.h"
#include "fmt/core.h"
#include "lnp.h"
#include "type.h"
#include "zydis/Zydis.h"
#include <algorithm>
#include <charconv>
#include <set>

namespace sym {

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
  auto f = target->cu_file_from_pc(vm_address);
  if (f) {
    const CompilationUnitFile &file = target->cu_files()[*f];
    const auto [begin, end] = file.get_range(vm_address);
    if (begin && end) {
      ASSERT(begin != nullptr && end != nullptr, "Expected to be able to find LT Entries; but didn't");
      ASSERT(vm_address >= begin->pc && vm_address <= end->pc,
             "Address {} does not land inside LTE range {} .. {}", vm_address, begin->pc, end->pc);
      return sym::Disassembly{.address = vm_address,
                              .opcode = std::move(machine_code),
                              .instruction = ins.text,
                              .source_name = file.file(begin->file),
                              .source_path = file.path_of_file(begin->file),
                              .line = begin->line,
                              .column = begin->column};
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
  ElfSection *text = target->get_text_section(addr);
  ZydisDisassembledInstruction instruction;

  // This hurts my soul and is so hacky.
  std::set<AddrPtr> disassembled_addresses{};
  if (auto idx = target->cu_file_from_pc(addr); idx.has_value()) {
    int index = *idx;
    while (index >= 0 && static_cast<int>(output.size()) <= ins_offset) {
      auto add = target->cu_files()[index].low_pc();
      auto exec_data_ptr = text->into(add);
      std::vector<sym::Disassembly> result;
      while (ZYAN_SUCCESS(ZydisDisassembleATT(ZYDIS_MACHINE_MODE_LONG_64, add, exec_data_ptr,
                                              text->remaining_bytes(exec_data_ptr), &instruction)) &&
             add <= addr) {
        if (!disassembled_addresses.contains(add))
          result.push_back(create_disasm_entry(target, add, instruction, exec_data_ptr));
        disassembled_addresses.insert(add);
        add = offset(add, instruction.info.length);
        exec_data_ptr += instruction.info.length;
      }
      addr = target->cu_files()[index].low_pc();
      for (auto i = result.rbegin(); i != result.rend(); i++) {
        output.insert(output.begin(), *i);
      }
      index--;
    }
  }

  // Disassemble instructions that aren't referenced by DWARF debug info
  if (static_cast<int>(output.size()) <= ins_offset) {
    auto add = text->address;
    auto exec_data_ptr = text->into(text->address);
    std::vector<sym::Disassembly> result;
    logging::get_logging()->log("mdb", fmt::format("Disassembling non-DWARF referenced instructions"));
    while (ZYAN_SUCCESS(ZydisDisassembleATT(ZYDIS_MACHINE_MODE_LONG_64, add, exec_data_ptr,
                                            text->remaining_bytes(exec_data_ptr), &instruction)) &&
           add <= addr) {
      if (!disassembled_addresses.contains(add))
        result.push_back(create_disasm_entry(target, add, instruction, exec_data_ptr));
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
  ElfSection *text = target->get_text_section(addr);
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