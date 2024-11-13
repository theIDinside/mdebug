#include "callstack.h"
#include "common.h"
#include "symbolication/dwarf_binary_reader.h"
#include "symbolication/dwarf_frameunwinder.h"
#include "tracer.h"
#include "utils/debug_value.h"
#include "utils/macros.h"
#include <symbolication/cu_symbol_info.h>
#include <symbolication/objfile.h>
#include <task.h>

namespace sym {

InsideRange
Frame::inside(TPtr<void> addr) const noexcept
{
  switch (type) {
  case FrameType::Full:
    return addr >= symbol.full_symbol->start_pc() && addr <= symbol.full_symbol->end_pc() ? InsideRange::Yes
                                                                                          : InsideRange::No;
  case FrameType::ElfSymbol:
    return addr >= symbol.min_symbol->start_pc() && addr <= symbol.full_symbol->end_pc() ? InsideRange::Yes
                                                                                         : InsideRange::No;
  case FrameType::Unknown:
    return InsideRange::Unknown;
  }
  MIDAS_UNREACHABLE
}

bool
Frame::has_symbol_info() const noexcept
{
  switch (type) {
  case FrameType::Full:
    return symbol.full_symbol != nullptr;
  case FrameType::ElfSymbol:
    return symbol.min_symbol != nullptr;
  case FrameType::Unknown:
    return false;
  }
  MIDAS_UNREACHABLE
}

FrameType
Frame::frame_type() const noexcept
{
  return type;
}

int
Frame::id() const noexcept
{
  return frame_id;
}

int
Frame::level() const noexcept
{
  return lvl;
}

AddrPtr
Frame::pc() const noexcept
{
  return rip;
}

SymbolFile *
Frame::get_symbol_file() noexcept
{
  return symbol_file;
}

const sym::FunctionSymbol &
Frame::full_symbol_info() const noexcept
{
  auto ptr = maybe_get_full_symbols();
  if (ptr == nullptr) {
    PANIC("No symbol information for frame, but expected there to be one");
  }
  return *ptr;
}

std::optional<dw::LineTable>
Frame::cu_line_table() const noexcept
{
  if (type != FrameType::Full) {
    return std::nullopt;
  }
  const auto symbol_info = symbol.full_symbol->symbol_info();
  ASSERT(symbol_info != nullptr, "Expected symbol info for this frame to not be null");

  return symbol_info->get_linetable(symbol_file);
}

std::optional<ui::dap::Scope>
Frame::scope(u32 var_ref) noexcept
{
  for (const auto scope : cached_scopes) {
    if (scope.variables_reference == var_ref) {
      return scope;
    }
  }
  return {};
}

std::array<ui::dap::Scope, 3>
Frame::scopes() noexcept
{
  // Variable reference can't be 0, so a zero here, means we haven't created the scopes yet
  if (cached_scopes[0].variables_reference == 0) {
    for (auto i = 0u; i < 3; ++i) {
      cached_scopes[i].type = static_cast<ui::dap::ScopeType>(i);
      const auto key = Tracer::Instance->new_key();
      Tracer::Instance->set_var_context({symbol_file->supervisor(), task->ptr, symbol_file, static_cast<u32>(id()),
                                         static_cast<u16>(key), ContextType::Scope});
      cached_scopes[i].variables_reference = key;
    }
  }
  return cached_scopes;
}

sym::FunctionSymbol *
Frame::maybe_get_full_symbols() const noexcept
{
  ASSERT(type == FrameType::Full, "Frame has no full symbol info");
  return symbol.full_symbol;
}

const MinSymbol *
Frame::maybe_get_min_symbols() const noexcept
{
  ASSERT(type == FrameType::ElfSymbol, "Frame has no ELF symbol info");
  return symbol.min_symbol;
}

IterateFrameSymbols
Frame::block_symbol_iterator(FrameVariableKind variables_kind) noexcept
{
  return IterateFrameSymbols{*this, variables_kind};
}

u32
Frame::frame_locals_count() const noexcept
{
  return full_symbol_info().local_variable_count();
}

u32
Frame::frame_args_count() const noexcept
{
  return full_symbol_info().get_args().symbols.size();
}

std::optional<std::string_view>
Frame::name() const noexcept
{
  return function_name();
}

std::optional<std::string_view>
Frame::function_name() const noexcept
{
  switch (type) {
  case FrameType::Full:
    return symbol.full_symbol->name;
  case FrameType::ElfSymbol:
    return symbol.min_symbol->name;
  case FrameType::Unknown:
    return std::nullopt;
  }
  MIDAS_UNREACHABLE
}

void
FrameUnwindState::SetCanonicalFrameAddress(u64 addr) noexcept
{
  mCanonicalFrameAddress = addr;
}

u64
FrameUnwindState::CanonicalFrameAddress() const noexcept
{
  return mCanonicalFrameAddress;
}

u64
FrameUnwindState::RegisterCount() const noexcept
{
  return mFrameRegisters.size();
}

void
FrameUnwindState::Reserve(u32 count) noexcept
{
  mFrameRegisters.reserve(count);
  std::fill_n(std::back_inserter(mFrameRegisters), count, 0u);
}

void
FrameUnwindState::Set(u32 number, u64 value) noexcept
{
  mFrameRegisters[number] = value;
}

void
FrameUnwindState::Reset() noexcept
{
  mCanonicalFrameAddress = 0;
  mFrameRegisters.clear();
}

AddrPtr
FrameUnwindState::GetPc() const noexcept
{
  return mFrameRegisters[X86_64_RIP_REGISTER];
}

AddrPtr
FrameUnwindState::GetRegister(u64 registerNumber) const noexcept
{
  return mFrameRegisters[registerNumber];
}

CallStack::CallStack(TraceeController *supervisor, TaskInfo *task) noexcept
    : mTask(task), mSupervisor(supervisor), dirty(true)
{
}

Frame *
CallStack::get_frame(int frame_id) noexcept
{
  for (auto &f : frames) {
    if (f.id() == frame_id) {
      return &f;
    }
  }
  return nullptr;
}

Frame *
CallStack::GetFrameAtLevel(u32 level) noexcept
{
  if (level >= frames.size()) {
    return nullptr;
  }
  return &frames[0];
}

u64
CallStack::unwind_buffer_register(u8 level, u16 register_number) noexcept
{
  ASSERT(level < mUnwoundRegister.size(), "out of bounds");
  return mUnwoundRegister[level].GetRegister(register_number);
}

bool
CallStack::IsDirty() const noexcept
{
  return dirty;
}

void
CallStack::SetDirty() noexcept
{
  dirty = true;
}

void
CallStack::Initialize() noexcept
{
  Reset();
  mUnwoundRegister.push_back({});
  mUnwoundRegister[0].Reset();
  mUnwoundRegister[0].Reserve(17);

  const auto &cache = mTask->GetRegisterCache();
  for (auto i = 0u; i <= 16; ++i) {
    mUnwoundRegister[0].Set(i, cache.GetRegister(i));
  }
}

void
CallStack::Reset() noexcept
{
  ClearFrames();
  ClearProgramCounters();
  ClearUnwoundRegisters();
}

void
CallStack::ClearFrames() noexcept
{
  frames.clear();
}

void
CallStack::ClearProgramCounters() noexcept
{
  mFrameProgramCounters.clear();
}

void
CallStack::ClearUnwoundRegisters() noexcept
{
  mUnwoundRegister.clear();
}

void
CallStack::Reserve(u32 count) noexcept
{
  frames.reserve(count);
  mFrameProgramCounters.reserve(count);
  mUnwoundRegister.reserve(count);
}

u32
CallStack::FramesCount() const noexcept
{
  return frames.size();
}

std::span<Frame>
CallStack::GetFrames() noexcept
{
  return frames;
}

std::optional<Frame>
CallStack::FindFrame(const Frame &frame) const noexcept
{
  for (const auto &f : frames) {
    if (f.has_symbol_info() && f.name() == frame.name()) {
      return f;
    }
    if (same_symbol(f, frame)) {
      return f;
    }
  }
  return std::nullopt;
}

AddrPtr
CallStack::GetTopMostPc() const noexcept
{
  ASSERT(!mUnwoundRegister.empty(), "No unwound registers!");
  return mUnwoundRegister.back().GetPc();
}

bool
CallStack::ResolveNewFrameRegisters(sym::CFAStateMachine &stateMachine) noexcept
{
  auto &cfa = stateMachine.get_cfa();

  const u64 canonicalFrameAddr =
    stateMachine.get_cfa().is_expr
      ? stateMachine.compute_expression(cfa.expr)
      : static_cast<u64>(static_cast<i64>(mUnwoundRegister.back().GetRegister(cfa.reg.number)) + cfa.reg.offset);
  DBGLOG(core, "[eh]: canonical frame address computed: 0x{:x}", canonicalFrameAddr);
  stateMachine.SetCanonicalFrameAddress(canonicalFrameAddr);

  mUnwoundRegister.push_back({});
  auto &newAboveFrame = mUnwoundRegister.back();
  auto &baseFrame = mUnwoundRegister[mUnwoundRegister.size() - 2];
  newAboveFrame.Reserve(baseFrame.RegisterCount());
  baseFrame.SetCanonicalFrameAddress(canonicalFrameAddr);

  for (auto i = 0u; i < mUnwoundRegister[mUnwoundRegister.size() - 2].RegisterCount(); ++i) {
    newAboveFrame.Set(i, stateMachine.ResolveRegisterContents(i, baseFrame));
  }

  // When a frame description entry for instance has a DWARF expression that computes to RIP being undefined
  // we don't want to continue, because we have no known resume address
  return stateMachine.KnowsResumeAddress();
}

static void
decode_eh_insts(sym::UnwindInfoSymbolFilePair info, sym::CFAStateMachine &state) noexcept
{
  // TODO(simon): Refactor DwarfBinaryReader, splitting it into 2 components, a BinaryReader and a
  // DwarfBinaryReader which inherits from that. in this instance, a BinaryReader suffices, we don't need to
  // actually know how to read DWARF binary data here.
  DwarfBinaryReader reader{info.GetCommonInformationEntryData()};
  const utils::DebugValue<int> decodedInstructions = sym::decode(reader, state, info.info);
  DBGLOG(eh, "[unwinder] decoded {} CIE instructions", decodedInstructions);
  DwarfBinaryReader fde{info.GetFrameDescriptionEntryData()};
  sym::decode(fde, state, info.info);
}

FrameUnwindState *
CallStack::GetUnwindState(u32 level) noexcept
{
  if (level >= mUnwoundRegister.size()) {
    return nullptr;
  }
  return &mUnwoundRegister[level];
}

void
CallStack::Unwind(const CallStackRequest &req)
{
  const auto pc = mUnwoundRegister.back().GetPc();
  sym::UnwindIterator it{mSupervisor, pc};
  auto uninfo = it.get_info(pc);

  if (!uninfo) {
    return;
  }

  sym::CFAStateMachine cfa_state = sym::CFAStateMachine::Init(*mSupervisor, *mTask, uninfo.value(), pc);
  mFrameProgramCounters.push_back(GetTopMostPc());

  auto [request, count, _] = req;

  switch (request) {
  case CallStackRequest::Type::Full: {
    for (auto uinf = uninfo; uinf.has_value(); uinf = it.get_info(GetTopMostPc())) {
      const auto pc = GetTopMostPc();
      cfa_state.Reset(uinf.value(), mUnwoundRegister.back(), pc);
      decode_eh_insts(uinf.value(), cfa_state);
      const auto keepUnwinding = ResolveNewFrameRegisters(cfa_state);
      if (!keepUnwinding) {
        break;
      }
      mFrameProgramCounters.push_back(GetTopMostPc());
    }
    break;
  }
  case CallStackRequest::Type::Partial: {
    for (auto uinf = uninfo; uinf.has_value() && count != 0; uinf = it.get_info(GetTopMostPc())) {
      const auto pc = GetTopMostPc();
      cfa_state.Reset(uinf.value(), mUnwoundRegister.back(), pc);
      decode_eh_insts(uinf.value(), cfa_state);
      const auto keepUnwinding = ResolveNewFrameRegisters(cfa_state);
      --count;
      if (!keepUnwinding) {
        break;
      }
      mFrameProgramCounters.push_back(GetTopMostPc());
    }
    break;
  }
  }

  dirty = false;
}

} // namespace sym