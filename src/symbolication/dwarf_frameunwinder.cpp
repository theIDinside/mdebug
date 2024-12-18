#include "dwarf_frameunwinder.h"
#include "../supervisor.h"
#include "../task.h"
#include "dwarf_binary_reader.h"
#include "dwarf_expressions.h"
#include "elf.h"
#include "objfile.h"
#include <array>
#include <cstdint>
#include <span>

namespace sym {

void
Reg::SetExpression(std::span<const u8> expression) noexcept
{
  uExpression = expression;
  mRule = RegisterRule::Expression;
}

void
Reg::SetValueExpression(std::span<const u8> expression) noexcept
{
  uExpression = expression;
  mRule = RegisterRule::ValueExpression;
}

void
Reg::SetOffset(i64 offs) noexcept
{
  mRule = RegisterRule::Offset;
  uOffset = offs;
}

void
Reg::SetValueOffset(i64 val_offset) noexcept
{
  mRule = RegisterRule::ValueOffset;
  uOffset = val_offset;
}

void
Reg::SetRegister(u64 reg) noexcept
{
  mRule = RegisterRule::Register;
  uValue = reg;
}

Reg::Reg() noexcept : uValue(0), mRule(RegisterRule::Undefined) {}

CFAStateMachine::CFAStateMachine(TraceeController &tc, TaskInfo &task, UnwindInfoSymbolFilePair cfi,
                                 AddrPtr pc) noexcept
    : mTraceeController(tc), mTask(task), mFrameDescriptionEntryPc(cfi.start()), mEndPc(pc),
      mCanonicalFrameAddressData({.mIsExpression = false, .reg = {0, 0}}), mRuleTable()
{
  mRuleTable.fill(Reg{});
}

CFAStateMachine::CFAStateMachine(TraceeController &tc, TaskInfo &task, const RegisterValues &frameBelow,
                                 UnwindInfoSymbolFilePair cfi, AddrPtr pc) noexcept
    : mTraceeController(tc), mTask(task), mFrameDescriptionEntryPc(cfi.start()), mEndPc(pc),
      mCanonicalFrameAddressData({.mIsExpression = false, .reg = {0, 0}})
{
  for (auto i = 0u; i < mRuleTable.size(); ++i) {
    mRuleTable[i].mRule = RegisterRule::Undefined;
    mRuleTable[i].uValue = frameBelow[i];
  }
}

void
CFAStateMachine::Reset(UnwindInfoSymbolFilePair cfi, const FrameUnwindState &belowFrameRegisters,
                       AddrPtr pc) noexcept
{
  mFrameDescriptionEntryPc = cfi.start();
  mEndPc = pc;
  mCanonicalFrameAddressData = {.mIsExpression = false, .reg = {0, 0}};
  auto i = 0;
  for (auto &r : mRuleTable) {
    r.mRule = RegisterRule::Undefined;
    r.uValue = belowFrameRegisters.GetRegister(i);
    i++;
  }
  // TODO: Perhaps in the future, we may want to support systems where RSP is not register 7
  static constexpr auto CFA_REGISTER = 7;
  mRuleTable[CFA_REGISTER].mRule = RegisterRule::IsCFARegister;
}

void
CFAStateMachine::SetNoKnownResumeAddress() noexcept
{
  mResumeAddressUndefined = true;
}

void
CFAStateMachine::Reset(UnwindInfoSymbolFilePair cfi, const RegisterValues &frameBelow, AddrPtr pc) noexcept
{
  mFrameDescriptionEntryPc = cfi.start();
  mEndPc = pc;
  mCanonicalFrameAddressData = {.mIsExpression = false, .reg = {0, 0}};
  auto i = 0;
  for (auto &r : mRuleTable) {
    r.mRule = RegisterRule::Undefined;
    r.uValue = frameBelow[i];
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
  const auto &cache = task.GetRegisterCache();
  for (auto i = 0; i <= 16; i++) {
    cfa_sm.mRuleTable[i].mRule = RegisterRule::Undefined;
    cfa_sm.mRuleTable[i].uValue = cache.GetRegister(i);
  }
  return cfa_sm;
}

u64
CFAStateMachine::ComputeExpression(std::span<const u8> bytes) noexcept
{
  DBGLOG(eh, "compute_expression of dwarf expression of {} bytes", bytes.size());
  auto intepreter = ExprByteCodeInterpreter{-1, mTraceeController, mTask, bytes};
  return intepreter.Run();
}

void
CFAStateMachine::SetCanonicalFrameAddress(u64 canonicalFrameAddress) noexcept
{
  mCanonicalFrameAddressValue = canonicalFrameAddress;
}

void
CFAStateMachine::RememberState() noexcept
{
  mRememberedState.push_back(mRuleTable);
  mRememberedCFA.push_back({});
  std::memcpy(&mRememberedCFA.back(), &mCanonicalFrameAddressData, sizeof(mCanonicalFrameAddressData));
}

void
CFAStateMachine::RestoreState() noexcept
{
  mRuleTable = mRememberedState.back();
  mRememberedState.pop_back();
  std::memcpy(&mCanonicalFrameAddressData, &mRememberedCFA.back(), sizeof(mCanonicalFrameAddressData));
  mRememberedCFA.pop_back();
}

u64
CFAStateMachine::ResolveRegisterContents(u64 registerNumber, const FrameUnwindState &belowFrame) noexcept
{
  auto &reg = mRuleTable[registerNumber];
  switch (reg.mRule) {
  case sym::RegisterRule::Undefined:
  case sym::RegisterRule::SameValue:
    return reg.uValue;
  case sym::RegisterRule::Offset: {
    const AddrPtr cfa_record = mCanonicalFrameAddressValue + reg.uOffset;
    const auto res = mTraceeController.ReadType(cfa_record.as<u64>());
    return res;
  }
  case sym::RegisterRule::ValueOffset: {
    const auto cfa = mCanonicalFrameAddressValue;
    const auto res = cfa + reg.uOffset;
    return res;
  }
  case sym::RegisterRule::Register: {
    return belowFrame.GetRegister(reg.uValue);
  }
  case sym::RegisterRule::Expression: {
    const auto saved_at_addr = TPtr<u64>(ComputeExpression(reg.uExpression));
    const auto res = mTraceeController.ReadType(saved_at_addr);
    return res;
  }
  case sym::RegisterRule::ValueExpression: {
    const auto value = ComputeExpression(reg.uExpression);
    return value;
  }
  case sym::RegisterRule::IsCFARegister: {
    return mCanonicalFrameAddressValue;
  }
  }
  PANIC("resolve_reg_contents fell off");
}

const CFA &
CFAStateMachine::GetCanonicalFrameAddressData() const noexcept
{
  return mCanonicalFrameAddressData;
}

const Registers &
CFAStateMachine::GetRegisters() const noexcept
{
  return mRuleTable;
}

const Reg &
CFAStateMachine::GetProgramCounterRegister() const noexcept
{
  return mRuleTable[16];
}

void
CFA::SetRegister(u64 number, i64 offset) noexcept
{
  reg.uNumber = number;
  reg.uOffset = offset;
  mIsExpression = false;
}

void
CFA::SetRegister(u64 number) noexcept
{
  reg.uNumber = number;
}

void
CFA::SetOffset(i64 offset) noexcept
{
  reg.uOffset = offset;
}

void
CFA::SetExpression(std::span<const u8> expression) noexcept
{
  mIsExpression = true;
  uExpression = expression;
}

int
decode(DwarfBinaryReader &reader, CFAStateMachine &state, const UnwindInfo *cfi)
{
  auto count = 0;
  while (reader.has_more() && state.mFrameDescriptionEntryPc <= state.mEndPc) {
    auto op = reader.read_value<u8>();
    ++count;
    switch (op & 0b1100'0000) {
    case 0b0100'0000: { // DW_CFA_advance_loc
      state.mFrameDescriptionEntryPc += (BOTTOM6_BITS & op) * cfi->mPointerToCommonInfoEntry->mCodeAlignFactor;
      break;
    }
    case 0b1000'0000: { // I::DW_CFA_offset
      const auto reg_num = (op & BOTTOM6_BITS);
      const auto offset = reader.read_uleb128<u64>();
      const auto n = static_cast<i64>(offset) * cfi->mPointerToCommonInfoEntry->mDataAlignFactor;
      state.mRuleTable[reg_num].SetOffset(static_cast<i64>(n));
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
        state.mFrameDescriptionEntryPc = reader.read_value<u64>();
      } break;
      case 0x02: { // I::DW_CFA_advance_loc1
        const auto delta = reader.read_value<u8>();
        state.mFrameDescriptionEntryPc += delta * cfi->mPointerToCommonInfoEntry->mCodeAlignFactor;
      } break;
      case 0x03: { // I::DW_CFA_advance_loc2
        const auto delta = reader.read_value<u16>();
        state.mFrameDescriptionEntryPc += delta * cfi->mPointerToCommonInfoEntry->mCodeAlignFactor;
      } break;
      case 0x04: { // I::DW_CFA_advance_loc4
        const auto delta = reader.read_value<u16>();
        state.mFrameDescriptionEntryPc += delta * cfi->mPointerToCommonInfoEntry->mCodeAlignFactor;
      } break;
      case 0x05: { // I::DW_CFA_offset_extended
        const auto reg = reader.read_uleb128<u64>();
        const auto offset = reader.read_uleb128<u64>();
        const auto n = offset * cfi->mPointerToCommonInfoEntry->mDataAlignFactor;
        state.mRuleTable[reg].SetOffset(n);
      } break;
      case 0x06: { // I::DW_CFA_restore_extended
        const auto reg = reader.read_uleb128<u64>();
        TODO_FMT("I::DW_CFA_restore_extended not implemented, reg={}", reg);
      } break;
      case 0x07: { // I::DW_CFA_undefined
        const auto reg = reader.read_uleb128<u64>();
        state.mRuleTable[reg].mRule = RegisterRule::Undefined;
        if (reg == 16) {
          state.SetNoKnownResumeAddress();
        }
      } break;
      case 0x08: { // I::DW_CFA_same_value
        const auto reg = reader.read_uleb128<u64>();
        state.mRuleTable[reg].mRule = RegisterRule::SameValue;
      } break;
      case 0x09: { // I::DW_CFA_register
        const auto reg1 = reader.read_uleb128<u64>();
        const auto reg2 = reader.read_uleb128<u64>();
        state.mRuleTable[reg1].SetRegister(reg2);
      } break;
      case 0x0a: { // I::DW_CFA_remember_state
        state.RememberState();
      } break;
      case 0x0b: { // I::DW_CFA_restore_state
        state.RestoreState();
      } break;
      case 0x0c: { // I::DW_CFA_def_cfa
        const auto reg = reader.read_uleb128<u64>();
        const auto offset = reader.read_uleb128<u64>();
        state.mCanonicalFrameAddressData.SetRegister(reg, offset);
      } break;
      case 0x0d: { // I::DW_CFA_def_cfa_register
        const auto reg = reader.read_uleb128<u64>();
        state.mCanonicalFrameAddressData.SetRegister(reg);
      } break;
      case 0x0e: { // I::DW_CFA_def_cfa_offset
        const auto offset = reader.read_uleb128<u64>();
        state.mCanonicalFrameAddressData.SetOffset(static_cast<i64>(offset));
      } break;
      case 0x0f: { // I::DW_CFA_def_cfa_expression
        const auto length = reader.read_uleb128<u64>();
        const auto block = reader.read_block(length);
        state.mCanonicalFrameAddressData.SetExpression(std::span{block.ptr, block.size});
      } break;
      case 0x10: { // I::DW_CFA_expression
        TODO("I::DW_CFA_expression");
        const auto reg = reader.read_uleb128<u64>();
        const auto length = reader.read_uleb128<u64>();
        const auto block = reader.read_block(length);
        state.mRuleTable[reg].SetExpression(std::span<const u8>{block.ptr, block.size});
      } break;
      case 0x11: { // I::DW_CFA_offset_extended_sf
        const auto reg = reader.read_uleb128<u64>();
        const auto offset = reader.read_leb128<i64>();
        const auto n = offset * cfi->mPointerToCommonInfoEntry->mDataAlignFactor;
        state.mRuleTable[reg].SetOffset(n);
      } break;
      case 0x12: { // I::DW_CFA_def_cfa_sf
        const auto reg = reader.read_uleb128<u64>();
        const auto offset = reader.read_leb128<i64>();
        const auto n = offset * cfi->mPointerToCommonInfoEntry->mDataAlignFactor;
        state.mCanonicalFrameAddressData.SetRegister(reg, n);
      } break;
      case 0x13: { // I::DW_CFA_def_cfa_offset_sf
        const auto offset = reader.read_leb128<i64>();
        const auto n = offset * cfi->mPointerToCommonInfoEntry->mDataAlignFactor;
        state.mCanonicalFrameAddressData.SetOffset(n);
      } break;
      case 0x14: { // I::DW_CFA_val_offset
        const auto reg = reader.read_uleb128<u64>();
        const auto offset = reader.read_uleb128<u64>();
        const auto n = offset * cfi->mPointerToCommonInfoEntry->mDataAlignFactor;
        state.mRuleTable[reg].SetValueOffset(n);
      } break;
      case 0x15: { // I::DW_CFA_val_offset_sf
        const auto reg = reader.read_uleb128<u64>();
        const auto offset = reader.read_leb128<i64>();
        const auto n = offset * cfi->mPointerToCommonInfoEntry->mDataAlignFactor;
        state.mRuleTable[reg].SetValueOffset(n);
      } break;
      case 0x16: { // I::DW_CFA_val_expression
        const auto reg = reader.read_uleb128<u64>();
        const auto length = reader.read_uleb128<u64>();
        const auto block = reader.read_block(length);
        state.mRuleTable[reg].SetValueExpression({block.ptr, block.size});
      } break;
      case 0x1c:
        TODO("DW_CFA_lo_user not supported");
      case 0x3f:
        TODO("DW_CFA_hi_user not supported");
      default: {
        PANIC(fmt::format("Could not decode byte code: {:x} == {:b} at position {}, cie offset: 0x{:x}", op, op,
                          reader.bytes_read() - 1, cfi->mPointerToCommonInfoEntry->mSectionOffset));
      }
      }
    }
  }
  return count;
}

constexpr auto
parse_encoding(u8 value)
{
  return Enc{.mLocationFormat = (DwarfExceptionHeaderApplication)(0b0111'0000 & value),
             .mValueFormat = (DwarfExceptionHeaderEncoding)(0b0000'1111 & value)};
}

using ExprOperation = AddrPtr (*)(ElfSection *, DwarfBinaryReader &);

std::pair<CommonInfoEntryCount, FrameDescriptionEntryCount>
CountTotalEntriesInElfSection(DwarfBinaryReader reader) noexcept
{
  auto cie_count = 0;
  auto fde_count = 0;
  while (reader.has_more()) {
    auto len = reader.read_value<u32>();
    // stupid .debug_frame uses u32.max as CIE identifier when 0 is to clearly be used.
    if (len == 0) {
      return {cie_count, fde_count};
    }
    auto id = reader.read_value<u32>();
    if (id == 0) {
      ++cie_count;
    } else {
      ++fde_count;
    }
    reader.skip(len - 4);
  }
  return {cie_count, fde_count};
}

std::pair<CommonInfoEntryCount, FrameDescriptionEntryCount>
CountTotalEntriesInDwarfSection(DwarfBinaryReader reader) noexcept
{
  auto cie_count = 0;
  auto fde_count = 0;
  while (reader.has_more()) {
    auto len = reader.read_value<u32>();
    // apparently .debug_frame does *not* have a 0-length entry as a terminator. Great. Amazing.
    if (len == 0) {
      return {cie_count, fde_count};
    }
    auto id = reader.read_value<u32>();
    // stupid .debug_frame uses u32.max as CIE identifier when 0 is to clearly be used.
    if (id == 0xff'ff'ff'ff) {
      ++cie_count;
    } else {
      ++fde_count;
    }
    reader.skip(len - 4);
  }
  return {cie_count, fde_count};
}

AddrPtr
read_lsda(CIE *cie, AddrPtr pc, DwarfBinaryReader &reader)
{
  using enum DwarfExceptionHeaderEncoding;
  if (cie->mLanguageSpecificDataAreaEncoding.mLocationFormat == DwarfExceptionHeaderApplication::DW_EH_PE_pcrel) {
    switch (cie->mLanguageSpecificDataAreaEncoding.mValueFormat) {
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
  } else if (cie->mLanguageSpecificDataAreaEncoding.mLocationFormat ==
             DwarfExceptionHeaderApplication::DW_EH_PE_absptr) {
    switch (cie->mLanguageSpecificDataAreaEncoding.mValueFormat) {
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
    DBGLOG(eh, "Unsupported LSDA application encoding: 0x{:x}",
           std::to_underlying(cie->mLanguageSpecificDataAreaEncoding.mLocationFormat));
  }
  PANIC("reading lsda failed");
}

template <u32 CIEMask> struct FrameUnwindEntryIdentifier
{
  u32 mId;
  constexpr bool
  IsCommonInfoEntry() const noexcept
  {
    return mId == CIEMask;
  }
};

using EHIdentifier = FrameUnwindEntryIdentifier<0x00'00'00'00>;
using DebugFrameIdentifier = FrameUnwindEntryIdentifier<0xFF'FF'FF'FF>;

std::unique_ptr<Unwinder>
ParseExceptionHeaderSection(ObjectFile *objfile, const ElfSection *ehFrameSection) noexcept
{
  ASSERT(ehFrameSection != nullptr, "Expected a .eh_frame section!");
  ASSERT(ehFrameSection->mName == ".eh_frame", "expected only .eh_frame section");
  DwarfBinaryReader reader{objfile->GetElf(), ehFrameSection->mSectionData};
  DBGLOG(eh, "reading .eh_frame section [{}] of {} bytes. Offset {:x}", objfile->GetPathString(),
         reader.remaining_size(), ehFrameSection->file_offset.as_t());
  auto unwinder_db = std::make_unique<Unwinder>(objfile);

  using CieId = u64;
  using CieIdx = u64;
  std::unordered_map<CieId, CieIdx> cies{};

  const auto [cie_count, fdes_count] = CountTotalEntriesInElfSection(DwarfBinaryReader{reader});
  unwinder_db->mElfEhCies.reserve(cie_count);
  unwinder_db->mElfEhUnwindInfos.reserve(fdes_count);
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
      ASSERT(unwinder_db->mElfEhCies.capacity() == cie_count,
             "We reserved memory to *exactly* hold {} count. std::vector re allocated under our feet", cie_count);
      unwinder_db->SetHighAddress(high);
      unwinder_db->SetLowAddress(low);
      return unwinder_db;
    }

    reader.bookmark();
    const auto cieId = reader.read_value<EHIdentifier>();
    if (cieId.IsCommonInfoEntry()) { // this is a CIE
      unwinder_db->mElfEhCies.push_back(ReadCommonInformationEntry(entry_length, eh_offset, reader));
      cies[current_offset - len_field_len] = unwinder_db->mElfEhCies.size() - 1;
    } else {
      auto cie_idx = cies[current_offset - cieId.mId];
      auto &cie = unwinder_db->mElfEhCies[cie_idx];
      auto initial_loc = reader.read_value<i32>();
      if (initial_loc > 0) {
        DBGLOG(core, "[eh]: expected initial loc to be < 0, but was 0x{:x}", initial_loc);
      }
      AddrPtr begin = (ehFrameSection->address + reader.bytes_read() - len_field_len) + initial_loc;
      AddrPtr end = begin + reader.read_value<u32>();
      u8 aug_data_length = 0u;
      AddrPtr lsda{nullptr};
      auto augment = cie.GetAugmentation();
      if (augment.HasAugmentDataField) {
        // it's *going* to be less than 255 bytes. So we cast it here
        aug_data_length = static_cast<u8>(reader.read_uleb128<u64>());
      }
      if (augment.HasLanguageSpecificDataArea) {
        lsda = read_lsda(&cie, begin, reader);
      }
      const auto bytes_remaining = entry_length - reader.pop_bookmark();
      const auto ins = reader.get_span(bytes_remaining);
      ASSERT(reader.bytes_read() - current_offset == entry_length, "Unexpected difference in length: {} != {}",
             reader.bytes_read() - current_offset, entry_length);
      low = std::min(low, begin);
      high = std::max(high, end);
      unwinder_db->mElfEhUnwindInfos.push_back(UnwindInfo{
        .mStart = begin,
        .mEnd = end,
        .mCodeAlignFactor = static_cast<u8>(cie.mCodeAlignFactor),
        .mDataAlignFactor = static_cast<i8>(cie.mDataAlignFactor),
        .mAugmentationDataLength = aug_data_length,
        .mLanguageSpecificDataAreaAddress = lsda,
        .mPointerToCommonInfoEntry = &cie,
        .mInstructionByteStreamFde = ins,
      });
    }
  }
  ASSERT(unwinder_db->mElfEhCies.capacity() == cie_count,
         "We reserved memory to *exactly* hold {} count. std::vector re allocated under our feet", cie_count);
  unwinder_db->SetHighAddress(high);
  unwinder_db->SetLowAddress(low);
  return unwinder_db;
}

void
ParseDwarfDebugFrame(const Elf *elf, Unwinder *unwinderDb, const ElfSection *debugFrame) noexcept
{
  DwarfBinaryReader reader{elf, debugFrame->mSectionData};

  using CieId = u64;
  using CieIdx = u64;
  std::unordered_map<CieId, CieIdx> cies{};

  const auto [cie_count, fdes_count] = CountTotalEntriesInDwarfSection(DwarfBinaryReader{reader});
  unwinderDb->mDwarfDebugCies.reserve(unwinderDb->mElfEhCies.size() + cie_count);
  unwinderDb->mDwarfUnwindInfos.reserve(unwinderDb->mElfEhUnwindInfos.size() + fdes_count);
  AddrPtr low{std::uintptr_t{UINTMAX_MAX}};
  AddrPtr high{nullptr};
  while (reader.has_more()) {
    constexpr auto len_field_len = 4;
    const auto eh_offset = reader.bytes_read();
    const auto entry_length = reader.read_value<u32>();
    ASSERT(entry_length != 0xff'ff'ff'ff, "GCC and clang do not support 64-bit .eh_frame; so why should we?");
    const auto current_offset = reader.bytes_read();
    if (entry_length == 0) {
      unwinderDb->SetHighAddress(high);
      unwinderDb->SetLowAddress(low);
      return;
    }

    reader.bookmark();
    auto cieId = reader.read_value<DebugFrameIdentifier>();
    if (cieId.IsCommonInfoEntry()) { // this is a CIE
      unwinderDb->mDwarfDebugCies.push_back(ReadCommonInformationEntry(entry_length, eh_offset, reader));
      cies[current_offset - len_field_len] = unwinderDb->mDwarfDebugCies.size() - 1;
    } else {
      auto cie_idx = cies[current_offset - cieId.mId];
      auto &cie = unwinderDb->mDwarfDebugCies[cie_idx];
      auto initial_loc = reader.read_value<i32>();
      AddrPtr begin = (debugFrame->address + reader.bytes_read() - len_field_len) + initial_loc;
      AddrPtr end = begin + reader.read_value<u32>();
      u8 aug_data_length = 0u;
      const auto augstr = cie.mAugmentationString.value_or("");
      if (augstr.contains("z")) {
        aug_data_length = static_cast<u8>(reader.read_uleb128<u64>());
      }
      AddrPtr lsda{nullptr};
      auto augment = cie.GetAugmentation();
      if (augment.HasLanguageSpecificDataArea) {
        lsda = read_lsda(&cie, begin, reader);
      }
      const auto bytes_remaining = entry_length - reader.pop_bookmark();
      auto ins = reader.get_span(bytes_remaining);
      ASSERT(reader.bytes_read() - current_offset == entry_length, "Unexpected difference in length: {} != {}",
             reader.bytes_read() - current_offset, entry_length);
      DBGLOG(core, "Unwind Info for {} .. {}; CIE instruction count {}; FDE instruction count: {}", begin, end,
             cie.mInstructionByteStream.size(), ins.size());
      low = std::min(low, begin);
      high = std::max(high, end);
      unwinderDb->mDwarfUnwindInfos.push_back(UnwindInfo{
        .mStart = begin,
        .mEnd = end,
        .mCodeAlignFactor = static_cast<u8>(cie.mCodeAlignFactor),
        .mDataAlignFactor = static_cast<i8>(cie.mDataAlignFactor),
        .mAugmentationDataLength = aug_data_length,
        .mLanguageSpecificDataAreaAddress = lsda,
        .mPointerToCommonInfoEntry = &cie,
        .mInstructionByteStreamFde = ins,
      });
    }
  }
  unwinderDb->SetHighAddress(high);
  unwinderDb->SetLowAddress(low);
}

CommonInformationEntry
ReadCommonInformationEntry(u64 commonInfoEntryLength, u64 commonInfoEntryOffset, DwarfBinaryReader &entryReader) noexcept
{
  CIE cie;
  cie.mSectionOffset = commonInfoEntryOffset;
  cie.mLength = commonInfoEntryLength;
  cie.mVersion = entryReader.read_value<u8>();
  const auto has_augment = entryReader.peek_value<i8>();
  if ((bool)has_augment) {
    cie.mAugmentationString = entryReader.read_string();
    // this is a UTF-8 string, but, I'm going out on a limb and say that's moronic. It's always zR, zPLR, so
    // seemingly ASCII-characters, this should be safe.
  } else {
    entryReader.read_value<u8>();
  }

  if (cie.mVersion >= 4) {
    cie.mAddrSize = entryReader.read_value<u8>();
    cie.mSegmentSize = entryReader.read_value<u8>();
  }

  cie.mCodeAlignFactor = entryReader.read_uleb128<u64>();
  cie.mDataAlignFactor = entryReader.read_leb128<i64>();
  cie.mReturnAddressRegister = entryReader.read_uleb128<u64>();
  for (auto c : cie.mAugmentationString.value_or("")) {
    if (c == 'z') {
      // we don't care about auglength.
      entryReader.read_uleb128<u64>();
    }
    if (c == 'R') {
      auto fde_encoding = parse_encoding(entryReader.read_value<u8>());
      cie.mFrameDescriptionEntryEncoding = fde_encoding;
    }
    if (c == 'P') {
      auto [fmt, val] = parse_encoding(entryReader.read_value<u8>());
      cie.mExceptionHeaderApplication = fmt;
      using enum DwarfExceptionHeaderEncoding;
      switch (val) {
      case DW_EH_PE_udata4:
        cie.mPersonalityAddress = entryReader.read_value<u32>();
        break;
      case DW_EH_PE_sdata4:
        cie.mPersonalityAddress = entryReader.read_value<i32>();
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
      auto lsda = parse_encoding(entryReader.read_value<u8>());
      cie.mLanguageSpecificDataAreaEncoding = lsda;
    }
  }
  const auto bytes_remaining = commonInfoEntryLength - entryReader.pop_bookmark();
  cie.mInstructionByteStream = entryReader.get_span(bytes_remaining);

  return cie;
}

u64
Unwinder::CommonInfoEntryCount() const noexcept
{
  return mDwarfDebugCies.size() + mElfEhCies.size();
}
u64
Unwinder::FrameDescriptionEntryCount() const noexcept
{
  return mDwarfUnwindInfos.size() + mElfEhUnwindInfos.size();
}

void
Unwinder::SetLowAddress(AddrPtr ptr) noexcept
{
  mAddressRange.low = std::min(mAddressRange.low, ptr);
}
void
Unwinder::SetHighAddress(AddrPtr ptr) noexcept
{
  mAddressRange.high = std::max(mAddressRange.high, ptr);
}

const UnwindInfo *
Unwinder::GetUnwindInformation(AddrPtr pc) const noexcept
{
  // todo(simon): once again, better searching can be done here, particularly binary search, if the elements are
  // ordered
  for (const auto &u : mElfEhUnwindInfos) {
    if (pc >= u.mStart && pc < u.mEnd) {
      return &u;
    }
  }

  for (const auto &u : mDwarfUnwindInfos) {
    if (pc >= u.mStart && pc < u.mEnd) {
      return &u;
    }
  }
  return nullptr;
}

Unwinder::Unwinder(ObjectFile *objfile) noexcept : mObjectFile(objfile), mAddressRange(AddressRange::MaxMin()) {}

UnwindIterator::UnwindIterator(TraceeController *tc, AddrPtr firstPc) noexcept
    : mTraceeController(tc), mCurrent(tc->GetUnwinderUsingPc(firstPc))
{
}

std::optional<UnwindInfoSymbolFilePair>
UnwinderSymbolFilePair::GetUnwinderInfo(AddrPtr pc) noexcept
{
  if (mSymbolFile && !mSymbolFile->mPcBounds->Contains(pc)) {
    return std::nullopt;
  }

  const auto info =
    mUnwinder->GetUnwindInformation(mSymbolFile != nullptr ? mSymbolFile->UnrelocateAddress(pc) : pc);
  if (!info) {
    return std::nullopt;
  }
  return UnwindInfoSymbolFilePair{.mInfo = info, .mSymbolFile = mSymbolFile};
}

std::optional<UnwindInfoSymbolFilePair>
UnwindIterator::GetInfo(AddrPtr pc) noexcept
{
  auto inf = mCurrent.GetUnwinderInfo(pc);
  if (inf) {
    return inf;
  } else {
    mCurrent = mTraceeController->GetUnwinderUsingPc(pc);
    return mCurrent.GetUnwinderInfo(pc);
  }
}

bool
UnwindIterator::IsNull() const noexcept
{
  return mTraceeController->IsNullUnwinder(mCurrent.mUnwinder);
}

AddrPtr
UnwindInfoSymbolFilePair::start() const noexcept
{
  return mInfo->mStart + mSymbolFile->mBaseAddress;
}

AddrPtr
UnwindInfoSymbolFilePair::end() const noexcept
{
  return mInfo->mEnd + mSymbolFile->mBaseAddress;
}

std::span<const u8>
UnwindInfoSymbolFilePair::GetCommonInformationEntryData() const
{
  if (!mInfo || !mInfo->mPointerToCommonInfoEntry) {
    return {};
  }
  return mInfo->mPointerToCommonInfoEntry->mInstructionByteStream;
}
std::span<const u8>
UnwindInfoSymbolFilePair::GetFrameDescriptionEntryData() const
{
  if (!mInfo) {
    return {};
  }
  return mInfo->mInstructionByteStreamFde;
}

} // namespace sym