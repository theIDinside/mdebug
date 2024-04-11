#include "dwarf_frameunwinder.h"
#include "../supervisor.h"
#include "../task.h"
#include "block.h"
#include "dwarf_binary_reader.h"
#include "dwarf_defs.h"
#include "dwarf_expressions.h"
#include "elf.h"
#include "objfile.h"
#include <array>
#include <cstdint>
#include <memory_resource>
#include <span>

namespace sym {

void
Reg::set_expression(std::span<const u8> expression) noexcept
{
  expr = expression;
  rule = RegisterRule::Expression;
}

void
Reg::set_val_expression(std::span<const u8> expression) noexcept
{
  expr = expression;
  rule = RegisterRule::ValueExpression;
}

void
Reg::set_offset(i64 offs) noexcept
{
  rule = RegisterRule::Offset;
  offset = offs;
}

void
Reg::set_value_offset(i64 val_offset) noexcept
{
  rule = RegisterRule::ValueOffset;
  offset = val_offset;
}

void
Reg::set_register(u64 reg) noexcept
{
  rule = RegisterRule::Register;
  value = reg;
}

Reg::Reg() noexcept : value(0), rule(RegisterRule::Undefined) {}

CFAStateMachine::CFAStateMachine(TraceeController &tc, TaskInfo &task, UnwindInfoSymbolFilePair cfi,
                                 AddrPtr pc) noexcept
    : tc(tc), task(task), fde_pc(cfi.start()), end_pc(pc), cfa({.is_expr = false, .reg = {0, 0}}), rule_table()
{
  rule_table.fill(Reg{});
}

CFAStateMachine::CFAStateMachine(TraceeController &tc, TaskInfo &task, const RegisterValues &frame_below,
                                 UnwindInfoSymbolFilePair cfi, AddrPtr pc) noexcept
    : tc(tc), task(task), fde_pc(cfi.start()), end_pc(pc), cfa({.is_expr = false, .reg = {0, 0}})
{
  for (auto i = 0u; i < rule_table.size(); ++i) {
    rule_table[i].rule = RegisterRule::Undefined;
    rule_table[i].value = frame_below[i];
  }
}

void
CFAStateMachine::reset(UnwindInfoSymbolFilePair cfi, const RegisterValues &frame_below, AddrPtr pc) noexcept
{
  fde_pc = cfi.start();
  end_pc = pc;
  cfa = {.is_expr = false, .reg = {0, 0}};
  auto i = 0;
  for (auto &r : rule_table) {
    r.rule = RegisterRule::Undefined;
    r.value = frame_below[i];
    i++;
  }
}

// todo(simon): this factory fn might seem dumb, but at some point we will want to optimize
// and only produce Rule-cells for registers actually in use - determining/initializing that will be done here
// then.
/* static */
CFAStateMachine
CFAStateMachine::Init(TraceeController &tc, TaskInfo &task, UnwindInfoSymbolFilePair cfi, AddrPtr pc) noexcept
{
  auto cfa_sm = CFAStateMachine{tc, task, cfi, pc};
  for (auto i = 0; i <= 16; i++) {
    cfa_sm.rule_table[i].rule = RegisterRule::Undefined;
    cfa_sm.rule_table[i].value = task.get_register(i);
  }
  return cfa_sm;
}

u64
CFAStateMachine::compute_expression(std::span<const u8> bytes) noexcept
{
  DLOG("eh", "compute_expression of dwarf expression of {} bytes", bytes.size());
  auto intepreter = ExprByteCodeInterpreter{-1, tc, task, bytes};
  return intepreter.run();
}

RegisterValues
CFAStateMachine::resolve_frame_regs(const RegisterValues &frame_live_registers) noexcept
{
  RegisterValues nxt_frame_regs{};

  if (cfa.is_expr) {
    cfa_value = compute_expression(cfa.expr);
  } else {
    const auto res = static_cast<i64>(frame_live_registers[cfa.reg.number]) + cfa.reg.offset;
    cfa_value = static_cast<u64>(res);
    DLOG("eh", "CFA=0x{:x} set from reg {} with value 0x{:x}", cfa_value, cfa.reg.number,
         frame_live_registers[cfa.reg.number]);
  }

  for (auto i = 0u; i < nxt_frame_regs.size(); ++i) {
    nxt_frame_regs[i] = resolve_reg_contents(i, frame_live_registers);
  }

  nxt_frame_regs[7] = cfa_value;
  return nxt_frame_regs;
}

u64
CFAStateMachine::resolve_reg_contents(u64 reg_number, const RegisterValues &regs) noexcept
{
  auto &reg = rule_table[reg_number];
  switch (reg.rule) {
  case sym::RegisterRule::Undefined:
  case sym::RegisterRule::SameValue:
    return reg.value;
  case sym::RegisterRule::Offset: {
    const AddrPtr cfa_record = cfa_value + reg.offset;
    const auto res = tc.read_type(cfa_record.as<u64>());
    return res;
  }
  case sym::RegisterRule::ValueOffset: {
    const auto cfa = cfa_value;
    const auto res = cfa + reg.offset;
    return res;
  }
  case sym::RegisterRule::Register: {
    return regs[reg.value];
  }
  case sym::RegisterRule::Expression: {
    const auto saved_at_addr = TPtr<u64>(compute_expression(reg.expr));
    const auto res = tc.read_type(saved_at_addr);
    return res;
  }
  case sym::RegisterRule::ValueExpression: {
    const auto value = compute_expression(reg.expr);
    return value;
  }
  case sym::RegisterRule::ArchSpecific:
    break;
  }
  PANIC("resolve_reg_contents fell off");
}

const CFA &
CFAStateMachine::get_cfa() const noexcept
{
  return cfa;
}

const Registers &
CFAStateMachine::get_regs() const noexcept
{
  return rule_table;
}

const Reg &
CFAStateMachine::ret_reg() const noexcept
{
  return rule_table[16];
}

void
CFA::set_register(u64 number, i64 offset) noexcept
{
  reg.number = number;
  reg.offset = offset;
  is_expr = false;
}

void
CFA::set_register(u64 number) noexcept
{
  reg.number = number;
}

void
CFA::set_offset(i64 offset) noexcept
{
  reg.offset = offset;
}

void
CFA::set_expression(std::span<const u8> expression) noexcept
{
  is_expr = true;
  expr = expression;
}

int
decode(DwarfBinaryReader &reader, CFAStateMachine &state, const UnwindInfo *cfi)
{
  auto count = 0;
  while (reader.has_more() && state.fde_pc <= state.end_pc) {
    auto op = reader.read_value<u8>();
    ++count;
    switch (op & 0b1100'0000) {
    case 0b0100'0000: { // DW_CFA_advance_loc
      state.fde_pc += (BOTTOM6_BITS & op) * cfi->cie->code_alignment_factor;
      break;
    }
    case 0b1000'0000: { // I::DW_CFA_offset
      const auto reg_num = (op & BOTTOM6_BITS);
      const auto offset = reader.read_uleb128<u64>();
      const auto n = static_cast<i64>(offset) * cfi->cie->data_alignment_factor;
      state.rule_table[reg_num].set_offset(static_cast<i64>(n));
      break;
    }
    case 0b1100'0000:
      TODO("I::DW_CFA_restore restore not implemented");
      break;
    default:
      switch (op) {
      case 0: // I::DW_CFA_nop
        break;
      case 0x01: { // I::DW_CFA_set_loc
        state.fde_pc = reader.read_value<u64>();
      } break;
      case 0x02: { // I::DW_CFA_advance_loc1
        const auto delta = reader.read_value<u8>();
        state.fde_pc += delta * cfi->cie->code_alignment_factor;
      } break;
      case 0x03: { // I::DW_CFA_advance_loc2
        const auto delta = reader.read_value<u16>();
        state.fde_pc += delta * cfi->cie->code_alignment_factor;
      } break;
      case 0x04: { // I::DW_CFA_advance_loc4
        const auto delta = reader.read_value<u16>();
        state.fde_pc += delta * cfi->cie->code_alignment_factor;
      } break;
      case 0x05: { // I::DW_CFA_offset_extended
        const auto reg = reader.read_uleb128<u64>();
        const auto offset = reader.read_uleb128<u64>();
        const auto n = offset * cfi->cie->data_alignment_factor;
        state.rule_table[reg].set_offset(n);
      } break;
      case 0x06: { // I::DW_CFA_restore_extended
        const auto reg = reader.read_uleb128<u64>();
        TODO_FMT("I::DW_CFA_restore_extended not implemented, reg={}", reg);
      } break;
      case 0x07: { // I::DW_CFA_undefined
        const auto reg = reader.read_uleb128<u64>();
        state.rule_table[reg].rule = RegisterRule::Undefined;
      } break;
      case 0x08: { // I::DW_CFA_same_value
        const auto reg = reader.read_uleb128<u64>();
        state.rule_table[reg].rule = RegisterRule::SameValue;
      } break;
      case 0x09: { // I::DW_CFA_register
        const auto reg1 = reader.read_uleb128<u64>();
        const auto reg2 = reader.read_uleb128<u64>();
        state.rule_table[reg1].set_register(reg2);
      } break;
      case 0x0a: { // I::DW_CFA_remember_state
        TODO("I::DW_CFA_remember_state")
      } break;
      case 0x0b: { // I::DW_CFA_restore_state
        TODO("I::DW_CFA_restore_state");
      } break;
      case 0x0c: { // I::DW_CFA_def_cfa
        const auto reg = reader.read_uleb128<u64>();
        const auto offset = reader.read_uleb128<u64>();
        state.cfa.set_register(reg, offset);
      } break;
      case 0x0d: { // I::DW_CFA_def_cfa_register
        const auto reg = reader.read_uleb128<u64>();
        state.cfa.set_register(reg);
      } break;
      case 0x0e: { // I::DW_CFA_def_cfa_offset
        const auto offset = reader.read_uleb128<u64>();
        state.cfa.set_offset(static_cast<i64>(offset));
      } break;
      case 0x0f: { // I::DW_CFA_def_cfa_expression
        const auto length = reader.read_uleb128<u64>();
        const auto block = reader.read_block(length);
        state.cfa.set_expression(std::span{block.ptr, block.size});
      } break;
      case 0x10: { // I::DW_CFA_expression
        TODO("I::DW_CFA_expression");
        const auto reg = reader.read_uleb128<u64>();
        const auto length = reader.read_uleb128<u64>();
        const auto block = reader.read_block(length);
        state.rule_table[reg].set_expression(std::span<const u8>{block.ptr, block.size});
      } break;
      case 0x11: { // I::DW_CFA_offset_extended_sf
        const auto reg = reader.read_uleb128<u64>();
        const auto offset = reader.read_leb128<i64>();
        const auto n = offset * cfi->cie->data_alignment_factor;
        state.rule_table[reg].set_offset(n);
      } break;
      case 0x12: { // I::DW_CFA_def_cfa_sf
        const auto reg = reader.read_uleb128<u64>();
        const auto offset = reader.read_leb128<i64>();
        const auto n = offset * cfi->cie->data_alignment_factor;
        state.cfa.set_register(reg, n);
      } break;
      case 0x13: { // I::DW_CFA_def_cfa_offset_sf
        const auto offset = reader.read_leb128<i64>();
        const auto n = offset * cfi->cie->data_alignment_factor;
        state.cfa.set_offset(n);
      } break;
      case 0x14: { // I::DW_CFA_val_offset
        const auto reg = reader.read_uleb128<u64>();
        const auto offset = reader.read_uleb128<u64>();
        const auto n = offset * cfi->cie->data_alignment_factor;
        state.rule_table[reg].set_value_offset(n);
      } break;
      case 0x15: { // I::DW_CFA_val_offset_sf
        const auto reg = reader.read_uleb128<u64>();
        const auto offset = reader.read_leb128<i64>();
        const auto n = offset * cfi->cie->data_alignment_factor;
        state.rule_table[reg].set_value_offset(n);
      } break;
      case 0x16: { // I::DW_CFA_val_expression
        const auto reg = reader.read_uleb128<u64>();
        const auto length = reader.read_uleb128<u64>();
        const auto block = reader.read_block(length);
        state.rule_table[reg].set_val_expression({block.ptr, block.size});
      } break;
      case 0x1c:
        TODO("DW_CFA_lo_user not supported");
      case 0x3f:
        TODO("DW_CFA_hi_user not supported");
      default: {
        PANIC(fmt::format("Could not decode byte code: {:x} == {:b} at position {}, cie offset: 0x{:x}", op, op,
                          reader.bytes_read() - 1, cfi->cie->offset));
      }
      }
    }
  }
  return count;
}

ByteCodeInterpreter::ByteCodeInterpreter(std::span<const u8> stream) noexcept : byte_stream(stream) {}

constexpr auto
parse_encoding(u8 value)
{
  return Enc{.loc_fmt = (DwarfExceptionHeaderApplication)(0b0111'0000 & value),
             .value_fmt = (DwarfExceptionHeaderEncoding)(0b0000'1111 & value)};
}

using ExprOperation = AddrPtr (*)(ElfSection *, DwarfBinaryReader &);

std::pair<u64, u64>
elf_eh_calculate_entries_count(DwarfBinaryReader reader) noexcept
{
  auto cie_count = 0;
  auto fde_count = 0;
  while (reader.has_more()) {
    auto len = reader.read_value<u32>();
    // stupid .debug_frame uses u32.max as CIE identifier when 0 is to clearly be used.
    if (len == 0)
      return {cie_count, fde_count};
    auto id = reader.read_value<u32>();
    if (id == 0)
      ++cie_count;
    else
      ++fde_count;
    reader.skip(len - 4);
  }
  return {cie_count, fde_count};
}

std::pair<u64, u64>
dwarf_eh_calculate_entries_count(DwarfBinaryReader reader) noexcept
{
  auto cie_count = 0;
  auto fde_count = 0;
  while (reader.has_more()) {
    auto len = reader.read_value<u32>();
    // apparently .debug_frame does *not* have a 0-length entry as a terminator. Great. Amazing.
    if (len == 0)
      return {cie_count, fde_count};
    auto id = reader.read_value<u32>();
    // stupid .debug_frame uses u32.max as CIE identifier when 0 is to clearly be used.
    if (id == 0xff'ff'ff'ff)
      ++cie_count;
    else
      ++fde_count;
    reader.skip(len - 4);
  }
  return {cie_count, fde_count};
}

AddrPtr
read_lsda(CIE *cie, AddrPtr pc, DwarfBinaryReader &reader)
{
  using enum DwarfExceptionHeaderEncoding;
  if (cie->lsda_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_pcrel) {
    switch (cie->lsda_encoding.value_fmt) {
      // clang-format off
    case DW_EH_PE_omit: case DW_EH_PE_uleb128: case DW_EH_PE_udata2:
    case DW_EH_PE_sleb128: case DW_EH_PE_sdata2:
      TODO("unsupported value format for LSDA pointer: {}");
      break;
    // clang-format on
    case DW_EH_PE_udata4:
      return pc + reader.read_value<u32>();
      break;
    case DW_EH_PE_udata8:
      return pc + reader.read_value<u64>();
      break;
    case DW_EH_PE_sdata4:
      return pc + reader.read_value<i32>();
      break;
    case DW_EH_PE_sdata8:
      return pc + reader.read_value<i64>();
      break;
    }
  } else if (cie->lsda_encoding.loc_fmt == DwarfExceptionHeaderApplication::DW_EH_PE_absptr) {
    switch (cie->lsda_encoding.value_fmt) {
      // clang-format off
    case DW_EH_PE_omit: case DW_EH_PE_uleb128: case DW_EH_PE_udata2:
    case DW_EH_PE_sleb128: case DW_EH_PE_sdata2:
      TODO("unsupported value format for LSDA pointer: {}");
      break;
    // clang-format on
    case DW_EH_PE_udata4:
      return reader.read_value<u32>();
      break;
    case DW_EH_PE_udata8:
      return reader.read_value<u64>();
      break;
    case DW_EH_PE_sdata4:
      return reader.read_value<i32>();
      break;
    case DW_EH_PE_sdata8:
      return reader.read_value<i64>();
      break;
    }
  } else {
    DLOG("eh", "Unsupported LSDA application encoding: 0x{:x}", std::to_underlying(cie->lsda_encoding.loc_fmt));
  }
  PANIC("reading lsda failed");
}

std::unique_ptr<Unwinder>
parse_eh(ObjectFile *objfile, const ElfSection *eh_frame) noexcept
{
  ASSERT(eh_frame != nullptr, "Expected a .eh_frame section!");
  DwarfBinaryReader reader{objfile->elf, eh_frame->m_section_ptr, eh_frame->size()};
  DLOG("eh", "reading .eh_frame section [{}] of {} bytes. Offset {:x}", objfile->path->c_str(),
       reader.remaining_size(), eh_frame->file_offset);
  auto unwinder_db = std::make_unique<Unwinder>(objfile);

  using CieId = u64;
  using CieIdx = u64;
  std::unordered_map<CieId, CieIdx> cies{};

  const auto [cie_count, fdes_count] = elf_eh_calculate_entries_count(DwarfBinaryReader{reader});
  unwinder_db->elf_eh_cies.reserve(cie_count);
  unwinder_db->elf_eh_unwind_infos.reserve(fdes_count);
  AddrPtr low{std::uintptr_t{UINTMAX_MAX}};
  AddrPtr high{nullptr};
  const auto total = cie_count + fdes_count;
  for (auto i = 0u; i < total; ++i) {
    constexpr auto len_field_len = 4;
    const auto eh_offset = reader.bytes_read();
    const auto entry_length = reader.read_value<u32>();
    ASSERT(entry_length != 0xff'ff'ff'ff, "GCC and clang do not support 64-bit .eh_frame; so why should we?");
    const auto current_offset = reader.bytes_read();
    if (entry_length == 0) {
      ASSERT(unwinder_db->elf_eh_cies.capacity() == cie_count,
             "We reserved memory to *exactly* hold {} count. std::vector re allocated under our feet", cie_count);
      unwinder_db->set_high(high);
      unwinder_db->set_low(low);
      return unwinder_db;
    }

    reader.bookmark();
    auto cie_ptr = reader.read_value<u32>();
    if (cie_ptr == 0) { // this is a CIE
      unwinder_db->elf_eh_cies.push_back(read_cie(entry_length, eh_offset, reader));
      cies[current_offset - len_field_len] = unwinder_db->elf_eh_cies.size() - 1;
    } else {
      auto cie_idx = cies[current_offset - cie_ptr];
      auto &cie = unwinder_db->elf_eh_cies[cie_idx];
      auto initial_loc = reader.read_value<i32>();
      if (initial_loc > 0) {
        DLOG("mdb", "[eh]: expected initial loc to be < 0, but was 0x{:x}", initial_loc);
      }
      AddrPtr begin = (eh_frame->address + reader.bytes_read() - len_field_len) + initial_loc;
      AddrPtr end = begin + reader.read_value<u32>();
      u8 aug_data_length = 0u;
      AddrPtr lsda{nullptr};
      if (cie.augmentation_string->contains("z")) {
        // it's *going* to be less than 255 bytes. So we cast it here
        aug_data_length = static_cast<u8>(reader.read_uleb128<u64>());
      }
      if (cie.augmentation_string->contains("L")) {
        lsda = read_lsda(&cie, begin, reader);
      }
      const auto bytes_remaining = entry_length - reader.pop_bookmark();
      const auto ins = reader.get_span(bytes_remaining);
      ASSERT(reader.bytes_read() - current_offset == entry_length, "Unexpected difference in length: {} != {}",
             reader.bytes_read() - current_offset, entry_length);
      low = std::min(low, begin);
      high = std::max(high, end);
      unwinder_db->elf_eh_unwind_infos.push_back(UnwindInfo{
          .start = begin,
          .end = end,
          .code_align = static_cast<u8>(cie.code_alignment_factor),
          .data_align = static_cast<i8>(cie.data_alignment_factor),
          .aug_data_len = aug_data_length,
          .lsda = lsda,
          .cie = &cie,
          .fde_insts = ins,
      });
    }
  }
  ASSERT(unwinder_db->elf_eh_cies.capacity() == cie_count,
         "We reserved memory to *exactly* hold {} count. std::vector re allocated under our feet", cie_count);
  unwinder_db->set_high(high);
  unwinder_db->set_low(low);
  return unwinder_db;
}

void
parse_dwarf_eh(const Elf *elf, Unwinder *unwinder_db, const ElfSection *debug_frame, int fde_count) noexcept
{
  DwarfBinaryReader reader{elf, debug_frame->m_section_ptr, debug_frame->size()};

  using CieId = u64;
  using CieIdx = u64;
  std::unordered_map<CieId, CieIdx> cies{};

  const auto [cie_count, fdes_count] = dwarf_eh_calculate_entries_count(DwarfBinaryReader{reader});
  unwinder_db->dwarf_debug_cies.reserve(unwinder_db->elf_eh_cies.size() + cie_count);
  unwinder_db->dwarf_unwind_infos.reserve(unwinder_db->elf_eh_unwind_infos.size() + fdes_count);
  AddrPtr low{std::uintptr_t{UINTMAX_MAX}};
  AddrPtr high{nullptr};
  for (; fde_count != 0; --fde_count) {
    constexpr auto len_field_len = 4;
    const auto eh_offset = reader.bytes_read();
    const auto entry_length = reader.read_value<u32>();
    ASSERT(entry_length != 0xff'ff'ff'ff, "GCC and clang do not support 64-bit .eh_frame; so why should we?");
    const auto current_offset = reader.bytes_read();
    if (entry_length == 0) {
      unwinder_db->set_high(high);
      unwinder_db->set_low(low);
      return;
    }

    reader.bookmark();
    auto cie_ptr = reader.read_value<u32>();
    if (cie_ptr == 0xff'ff'ff'ff) { // this is a CIE
      unwinder_db->dwarf_debug_cies.push_back(read_cie(entry_length, eh_offset, reader));
      cies[current_offset - len_field_len] = unwinder_db->dwarf_debug_cies.size() - 1;
    } else {
      auto cie_idx = cies[current_offset - cie_ptr];
      auto &cie = unwinder_db->dwarf_debug_cies[cie_idx];
      auto initial_loc = reader.read_value<i32>();
      ASSERT(initial_loc < 0, "Expected initial loc to be negative offset");
      AddrPtr begin = (debug_frame->address + reader.bytes_read() - len_field_len) + initial_loc;
      AddrPtr end = begin + reader.read_value<u32>();
      u8 aug_data_length = 0u;
      const auto augstr = cie.augmentation_string.value_or("");
      if (augstr.contains("z")) {
        aug_data_length = static_cast<u8>(reader.read_uleb128<u64>());
      }
      AddrPtr lsda{nullptr};
      if (cie.augmentation_string->contains("L")) {
        lsda = read_lsda(&cie, begin, reader);
      }
      const auto bytes_remaining = entry_length - reader.pop_bookmark();
      auto ins = reader.get_span(bytes_remaining);
      ASSERT(reader.bytes_read() - current_offset == entry_length, "Unexpected difference in length: {} != {}",
             reader.bytes_read() - current_offset, entry_length);
      DLOG("mdb", "Unwind Info for {} .. {}; CIE instruction count {}; FDE instruction count: {}", begin, end,
           cie.instructions.size(), ins.size());
      low = std::min(low, begin);
      high = std::max(high, end);
      unwinder_db->dwarf_unwind_infos.push_back(UnwindInfo{
          .start = begin,
          .end = end,
          .code_align = static_cast<u8>(cie.code_alignment_factor),
          .data_align = static_cast<i8>(cie.data_alignment_factor),
          .aug_data_len = aug_data_length,
          .lsda = lsda,
          .cie = &cie,
          .fde_insts = ins,
      });
    }
  }
  unwinder_db->set_high(high);
  unwinder_db->set_low(low);
}

CommonInformationEntry
read_cie(u64 cie_len, u64 cie_offset, DwarfBinaryReader &entry_reader) noexcept
{
  CIE cie;
  cie.offset = cie_offset;
  cie.length = cie_len;
  cie.version = entry_reader.read_value<u8>();
  const auto has_augment = entry_reader.peek_value<i8>();
  if ((bool)has_augment) {
    cie.augmentation_string = entry_reader.read_string();
    // this is a UTF-8 string, but, I'm going out on a limb and say that's moronic. It's always zR, zPLR, so
    // seemingly ASCII-characters, this should be safe.
  } else {
    entry_reader.read_value<u8>();
  }

  if (cie.version >= 4) {
    cie.addr_size = entry_reader.read_value<u8>();
    cie.segment_size = entry_reader.read_value<u8>();
  }

  cie.code_alignment_factor = entry_reader.read_uleb128<u64>();
  cie.data_alignment_factor = entry_reader.read_leb128<i64>();
  cie.retaddr_register = entry_reader.read_uleb128<u64>();
  for (auto c : cie.augmentation_string.value_or("")) {
    if (c == 'z') {
      // we don't care about auglength.
      entry_reader.read_uleb128<u64>();
    }
    if (c == 'R') {
      auto fde_encoding = parse_encoding(entry_reader.read_value<u8>());
      cie.fde_encoding = fde_encoding;
    }
    if (c == 'P') {
      auto [fmt, val] = parse_encoding(entry_reader.read_value<u8>());
      cie.p_application = fmt;
      using enum DwarfExceptionHeaderEncoding;
      switch (val) {
      case DW_EH_PE_udata4:
        cie.personality_address = entry_reader.read_value<u32>();
        break;
      case DW_EH_PE_sdata4:
        cie.personality_address = entry_reader.read_value<i32>();
        break;
        // clang-format off
      case DW_EH_PE_sdata8: case DW_EH_PE_udata8: case DW_EH_PE_sleb128:
      case DW_EH_PE_sdata2: case DW_EH_PE_omit:   case DW_EH_PE_uleb128:
      case DW_EH_PE_udata2:
        // clang-format on
        TODO("support personality address data format than sdata4 and udata4 not implemented");
      }
    }
    if (c == 'L') {
      auto lsda = parse_encoding(entry_reader.read_value<u8>());
      cie.lsda_encoding = lsda;
    }
  }
  const auto bytes_remaining = cie_len - entry_reader.pop_bookmark();
  cie.instructions = entry_reader.get_span(bytes_remaining);

  return cie;
}

u64
Unwinder::total_cies() const noexcept
{
  return dwarf_debug_cies.size() + elf_eh_cies.size();
}
u64
Unwinder::total_fdes() const noexcept
{
  return dwarf_unwind_infos.size() + elf_eh_unwind_infos.size();
}

void
Unwinder::set_low(AddrPtr ptr) noexcept
{
  addr_range.low = std::min(addr_range.low, ptr);
}
void
Unwinder::set_high(AddrPtr ptr) noexcept
{
  addr_range.high = std::max(addr_range.high, ptr);
}

const UnwindInfo *
Unwinder::get_unwind_info(AddrPtr pc) const noexcept
{
  // todo(simon): once again, better searching can be done here, particularly binary search, if the elements are
  // ordered
  for (const auto &u : elf_eh_unwind_infos) {
    if (pc >= u.start && pc < u.end)
      return &u;
  }

  for (const auto &u : dwarf_unwind_infos) {
    if (pc >= u.start && pc < u.end)
      return &u;
  }
  return nullptr;
}

Unwinder::Unwinder(ObjectFile *objfile) noexcept : objfile(objfile), addr_range(AddressRange::MaxMin()) {}

UnwindIterator::UnwindIterator(TraceeController *tc, AddrPtr first_pc) noexcept
    : tc(tc), current(tc->get_unwinder_from_pc(first_pc))
{
}

std::optional<UnwindInfoSymbolFilePair>
UnwinderSymbolFilePair::get_unwinder_info(AddrPtr pc) noexcept
{
  if (sf && !sf->pc_bounds->contains(pc)) {
    return std::nullopt;
  }

  const auto info = unwinder->get_unwind_info(sf != nullptr ? sf->unrelocate(pc) : pc);
  if (!info) {
    return std::nullopt;
  }
  return UnwindInfoSymbolFilePair{.info = info, .sf = sf};
}

std::optional<UnwindInfoSymbolFilePair>
UnwindIterator::get_info(AddrPtr pc) noexcept
{
  auto inf = current.get_unwinder_info(pc);
  if (inf) {
    return inf;
  } else {
    current = tc->get_unwinder_from_pc(pc);
    return current.get_unwinder_info(pc);
  }
}

bool
UnwindIterator::is_null() const noexcept
{
  return tc->is_null_unwinder(current.unwinder);
}

AddrPtr
UnwindInfoSymbolFilePair::start() const noexcept
{
  return info->start + sf->baseAddress;
}

AddrPtr
UnwindInfoSymbolFilePair::end() const noexcept
{
  return info->end + sf->baseAddress;
}

} // namespace sym