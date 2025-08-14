/** LICENSE TEMPLATE */
#include "disassemble.h"
#include "../supervisor.h"
#include "elf.h"
#include "objfile.h"
#include "symbolication/dwarf/lnp.h"
#include "symbolication/fnsymbol.h"
#include "zydis/Zydis.h"
#include <algorithm>
#include <set>

namespace mdb::sym {

struct SourceInfo
{
  dw::SourceCodeFile *mSource;
  const dw::LineTableEntry *mEntry;

  explicit constexpr
  operator bool() const noexcept
  {
    return mSource && mEntry;
  }
};

SourceInfo
GetSourceInfo(SymbolFile *obj, const std::vector<sym::CompilationUnit *> &compilationUnits, AddrPtr addr)
{
  for (auto cu : compilationUnits) {
    const auto res = cu->GetLineTableEntry(addr);
    if (res.first) {
      return { res.first, res.second };
    }
  }
  return { nullptr, nullptr };
}

static sym::Disassembly
create_disasm_entry(TraceeController *target,
  AddrPtr vm_address,
  const ZydisDisassembledInstruction &ins,
  const u8 *exec_data_ptr) noexcept
{
  std::string machine_code{};
  machine_code.resize(ins.info.length * 2 + ins.info.length - 1, ' ');
  auto mc_b = machine_code.begin();
  for (auto i = 0; i < ins.info.length; i++) {
    std::format_to(mc_b, "{:02x}", *(exec_data_ptr + i));
    mc_b += 3;
  }
  auto obj = target->FindObjectByPc(vm_address);
  auto cus = obj->GetCompilationUnits(vm_address);
  if (!cus.empty()) {
    SourceInfo sourceInfo = GetSourceInfo(obj, cus, vm_address);
    if (sourceInfo) {
      return sym::Disassembly{ .address = vm_address,
        .opcode = std::move(machine_code),
        .instruction = ins.text,
        .source_name = sourceInfo.mSource->mFullPath.StringView(),
        .source_path = sourceInfo.mSource->mFullPath.StringView(),
        .line = sourceInfo.mEntry->line,
        .column = sourceInfo.mEntry->column };
    } else {
      return sym::Disassembly{ .address = vm_address,
        .opcode = std::move(machine_code),
        .instruction = ins.text,
        .source_name = "",
        .source_path = "",
        .line = 0,
        .column = 0 };
    }
  } else {
    return sym::Disassembly{ .address = vm_address,
      .opcode = std::move(machine_code),
      .instruction = ins.text,
      .source_name = "",
      .source_path = "",
      .line = 0,
      .column = 0 };
  }
}

void
zydis_disasm_backwards(
  TraceeController *target, AddrPtr addr, i32 ins_offset, std::vector<sym::Disassembly> &output) noexcept
{
  const auto objfile = target->FindObjectByPc(addr);
  const auto text = objfile->GetObjectFile()->GetElf()->GetSection(".text");
  ZydisDisassembledInstruction instruction;

  // This hurts my soul and is so hacky.
  std::set<AddrPtr> disassembled_addresses{};
  auto srcs = objfile->GetCompilationUnits(addr);

  std::sort(srcs.begin(), srcs.end(), [](auto a, auto b) { return a->StartPc() >= b->StartPc(); });

  for (auto src : srcs) {
    if (static_cast<int>(output.size()) <= ins_offset) {
      auto add = src->StartPc();
      auto exec_data_ptr = text->Into(add);
      std::vector<sym::Disassembly> result;
      while (
        ZYAN_SUCCESS(ZydisDisassembleATT(
          ZYDIS_MACHINE_MODE_LONG_64, add, exec_data_ptr, text->RemainingBytes(exec_data_ptr), &instruction)) &&
        add <= addr) {
        if (!disassembled_addresses.contains(add)) {
          result.push_back(create_disasm_entry(target, add, instruction, exec_data_ptr));
        }
        disassembled_addresses.insert(add);
        add = offset(add, instruction.info.length);
        exec_data_ptr += instruction.info.length;
      }
      addr = src->StartPc();
      for (auto i = result.rbegin(); i != result.rend(); i++) {
        output.insert(output.begin(), *i);
      }
    }
  }

  // Disassemble instructions that aren't referenced by DWARF debug info
  if (static_cast<int>(output.size()) <= ins_offset) {
    auto add = *text->address;
    auto exec_data_ptr = text->Into(text->address);
    std::vector<sym::Disassembly> result;
    DBGLOG(core, "Disassembling non-DWARF referenced instructions");
    while (ZYAN_SUCCESS(ZydisDisassembleATT(
             ZYDIS_MACHINE_MODE_LONG_64, add, exec_data_ptr, text->RemainingBytes(exec_data_ptr), &instruction)) &&
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
      output.insert(output.begin(), sym::Disassembly{ nullptr, "", "", "", "", 0, 0 });
    }
  }
}

void
zydis_disasm(TraceeController *target,
  AddrPtr addr,
  u32 ins_offset,
  u32 total,
  std::vector<sym::Disassembly> &output) noexcept
{
  auto obj = target->FindObjectByPc(addr);
  const ElfSection *text = obj->GetTextSection();
  const auto start_exec_data = text->Into(addr);
  auto exec_data_ptr = start_exec_data;
  ZydisDisassembledInstruction instruction;
  auto vm_address = addr;

  if (ins_offset > 0) {
    while (ZYAN_SUCCESS(ZydisDisassembleATT(ZYDIS_MACHINE_MODE_LONG_64,
             vm_address,
             exec_data_ptr,
             text->RemainingBytes(exec_data_ptr),
             &instruction)) &&
           ins_offset != 0) {
      vm_address = offset(vm_address, instruction.info.length);
      exec_data_ptr += instruction.info.length;
      --ins_offset;
    }
  }

  while (
    ZYAN_SUCCESS(ZydisDisassembleATT(
      ZYDIS_MACHINE_MODE_LONG_64, vm_address, exec_data_ptr, text->RemainingBytes(exec_data_ptr), &instruction)) &&
    total != 0) {
    output.push_back(create_disasm_entry(target, vm_address, instruction, exec_data_ptr));
    vm_address = offset(vm_address, instruction.info.length);
    exec_data_ptr += instruction.info.length;
    --total;
  }
}
} // namespace mdb::sym