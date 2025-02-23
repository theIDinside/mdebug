/** LICENSE TEMPLATE */
#include "callstack.h"
#include "common.h"
#include "supervisor.h"
#include "symbolication/dwarf/lnp.h"
#include "symbolication/dwarf_binary_reader.h"
#include "symbolication/dwarf_frameunwinder.h"
#include "symbolication/value.h"
#include "tracer.h"
#include "utils/debug_value.h"
#include "utils/immutable.h"
#include "utils/macros.h"
#include <algorithm>
#include <iterator>
#include <symbolication/cu_symbol_info.h>
#include <symbolication/objfile.h>
#include <task.h>

namespace mdb::sym {

static constexpr auto X86_64_RIP_REGISTER = 16;

InsideRange
Frame::IsInside(TPtr<void> addr) const noexcept
{
  switch (mFrameType) {
  case FrameType::Full:
    return addr >= mSymbolUnion.uFullSymbol->StartPc() && addr <= mSymbolUnion.uFullSymbol->EndPc()
             ? InsideRange::Yes
             : InsideRange::No;
  case FrameType::ElfSymbol:
    return addr >= mSymbolUnion.uMinSymbol->StartPc() && addr <= mSymbolUnion.uFullSymbol->EndPc()
             ? InsideRange::Yes
             : InsideRange::No;
  case FrameType::Unknown:
    return InsideRange::Unknown;
  }
  MIDAS_UNREACHABLE
}

bool
Frame::HasSymbolInfo() const noexcept
{
  switch (mFrameType) {
  case FrameType::Full:
    return mSymbolUnion.uFullSymbol != nullptr;
  case FrameType::ElfSymbol:
    return mSymbolUnion.uMinSymbol != nullptr;
  case FrameType::Unknown:
    return false;
  }
  MIDAS_UNREACHABLE
}

FrameType
Frame::GetFrameType() const noexcept
{
  return mFrameType;
}

VariableReferenceId
Frame::FrameId() const noexcept
{
  return mFrameId;
}

int
Frame::FrameLevel() const noexcept
{
  return mFrameLevel;
}

AddrPtr
Frame::FramePc() const noexcept
{
  return mFramePc;
}

SymbolFile *
Frame::GetSymbolFile() const noexcept
{
  return mOwningSymbolFile;
}

TaskInfo *
Frame::Task() const noexcept
{
  return mTask->ptr;
}

sym::FunctionSymbol &
Frame::FullSymbolInfo() noexcept
{
  auto ptr = MaybeGetFullSymbolInfo();
  if (ptr == nullptr) {
    PANIC("No symbol information for frame, but expected there to be one");
  }
  return *ptr;
}

std::pair<dw::SourceCodeFile *, const dw::LineTableEntry *>
Frame::GetLineTableEntry() noexcept
{
  CompilationUnit *cu = FullSymbolInfo().GetCompilationUnit();
  return cu->GetLineTableEntry(FramePc() - mOwningSymbolFile->mBaseAddress);
}

std::optional<ui::dap::Scope>
Frame::Scope(u32 var_ref) noexcept
{
  for (const auto scope : mFrameScopes) {
    if (scope.variables_reference == var_ref) {
      return scope;
    }
  }
  return {};
}

std::array<ui::dap::Scope, 3>
Frame::Scopes() noexcept
{
  // Variable reference can't be 0, so a zero here, means we haven't created the scopes yet
  if (mFrameScopes[0].variables_reference == 0) {
    for (auto i = 0u; i < 3; ++i) {
      mFrameScopes[i].type = static_cast<ui::dap::ScopeType>(i);
      const auto key = Tracer::Get().NewVariablesReference();
      Tracer::Get().SetVariableContext(
        std::make_shared<VariableContext>(mTask->ptr, mOwningSymbolFile, FrameId(), key, ContextType::Scope));
      mFrameScopes[i].variables_reference = key;
    }
  }
  return mFrameScopes;
}

sym::FunctionSymbol *
Frame::MaybeGetFullSymbolInfo() const noexcept
{
  if (mFrameType == FrameType::Full) {
    return mSymbolUnion.uFullSymbol;
  }
  return nullptr;
}

const MinSymbol *
Frame::MaybeGetMinimalSymbol() const noexcept
{
  ASSERT(mFrameType == FrameType::ElfSymbol, "Frame has no ELF symbol info");
  return mSymbolUnion.uMinSymbol;
}

IterateFrameSymbols
Frame::BlockSymbolIterator(FrameVariableKind variables_kind) noexcept
{
  return IterateFrameSymbols{*this, variables_kind};
}

u32
Frame::GetInitializedVariables(FrameVariableKind variableSet,
                               std::vector<NonNullPtr<const sym::Symbol>> &outVector) noexcept
{
  switch (variableSet) {
  case FrameVariableKind::Arguments: {
    // TODO: implement this also for arguments; because the args may not be initialized even if we're in the
    // function this is what's done inside a function prologue; therefore we should add functionality that check if
    // we've actually performed the prologue.
    const auto &args = FullSymbolInfo().GetFunctionArguments().mSymbols;
    for (const auto &s : args) {
      outVector.push_back(NonNull(s));
    }
    return args.size();
  }
  case FrameVariableKind::Locals: {
    for (const auto &block : FullSymbolInfo().GetFrameLocalVariableBlocks()) {
      if (block.ContainsPc(mOwningSymbolFile->UnrelocateAddress(mFramePc))) {
        for (const auto &sym : block.mSymbols) {
          outVector.push_back(NonNull(sym));
        }
      }
    }
    return outVector.size();
  }
  }
}

u32
Frame::FrameLocalVariablesCount() noexcept
{
  return FullSymbolInfo().FrameVariablesCount();
}

u32
Frame::FrameParameterCounts() noexcept
{
  return FullSymbolInfo().GetFunctionArguments().mSymbols.size();
}

std::optional<std::string_view>
Frame::Name() const noexcept
{
  return GetFunctionName();
}

std::optional<const char *>
Frame::CStringName() const noexcept
{
  return Name().transform([](auto view) { return view.data(); });
}

std::optional<std::string_view>
Frame::GetFunctionName() const noexcept
{
  switch (mFrameType) {
  case FrameType::Full:
    return mSymbolUnion.uFullSymbol->name;
  case FrameType::ElfSymbol:
    return mSymbolUnion.uMinSymbol->name;
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

CallStack::CallStack(TraceeController *supervisor, TaskInfo *task) noexcept : mTask(task), mSupervisor(supervisor)
{
}

Frame *
CallStack::GetFrame(u64 frameId) noexcept
{
  for (auto &f : mStackFrames) {
    if (f.FrameId() == frameId) {
      return &f;
    }
  }
  return nullptr;
}

Frame *
CallStack::GetFrameAtLevel(u32 level) noexcept
{
  if (level >= mStackFrames.size()) {
    return nullptr;
  }
  return &mStackFrames[0];
}

u64
CallStack::UnwindRegister(u8 level, u16 register_number) noexcept
{
  ASSERT(level < mUnwoundRegister.size(), "out of bounds");
  return mUnwoundRegister[level].GetRegister(register_number);
}

bool
CallStack::IsDirty() const noexcept
{
  return mCallstackState == CallStackState::Invalidated;
}

void
CallStack::SetDirty() noexcept
{
  mCallstackState = CallStackState::Invalidated;
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
  mStackFrames.clear();
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
  mStackFrames.reserve(count);
  mFrameProgramCounters.reserve(count);
  mUnwoundRegister.reserve(count);
}

u32
CallStack::FramesCount() const noexcept
{
  return mStackFrames.size();
}

std::span<Frame>
CallStack::GetFrames() noexcept
{
  return mStackFrames;
}

std::optional<Frame>
CallStack::FindFrame(const Frame &frame) const noexcept
{
  for (const auto &f : mStackFrames) {
    if (f.HasSymbolInfo() && f.Name() == frame.Name()) {
      return f;
    }
    if (SameSymbol(f, frame)) {
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

std::pair<FrameUnwindState *, FrameUnwindState *>
CallStack::GetCurrent() noexcept
{
  if (mUnwoundRegister.size() < 2) {
    return {nullptr, nullptr};
  }
  auto span = std::span{mUnwoundRegister}.subspan(mUnwoundRegister.size() - 2, 2);
  return {&span[0], &span[1]};
}

bool
CallStack::ResolveNewFrameRegisters(sym::CFAStateMachine &stateMachine) noexcept
{
  auto &cfa = stateMachine.GetCanonicalFrameAddressData();
  int frameLevel = mUnwoundRegister.size() - 1;
  const u64 canonicalFrameAddr =
    stateMachine.GetCanonicalFrameAddressData().mIsExpression
      ? stateMachine.ComputeExpression(cfa.uExpression, frameLevel)
      : static_cast<u64>(static_cast<i64>(mUnwoundRegister.back().GetRegister(cfa.reg.uNumber)) + cfa.reg.uOffset);
  DBGLOG(core, "[eh]: canonical frame address computed: 0x{:x}", canonicalFrameAddr);
  stateMachine.SetCanonicalFrameAddress(canonicalFrameAddr);

  mUnwoundRegister.push_back({});
  auto &newAboveFrame = mUnwoundRegister.back();
  auto &baseFrame = mUnwoundRegister[mUnwoundRegister.size() - 2];
  newAboveFrame.Reserve(baseFrame.RegisterCount());
  baseFrame.SetCanonicalFrameAddress(canonicalFrameAddr);

  for (auto i = 0u; i < mUnwoundRegister[mUnwoundRegister.size() - 2].RegisterCount(); ++i) {
    newAboveFrame.Set(i, stateMachine.ResolveRegisterContents(i, baseFrame, frameLevel));
  }

  newAboveFrame.Set(7, canonicalFrameAddr);

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
  const int decodedInstructions = sym::decode(reader, state, info.mInfo);
  DBGLOG(eh, "[unwinder] decoded {} CIE instructions", decodedInstructions);
  DwarfBinaryReader fde{info.GetFrameDescriptionEntryData()};
  sym::decode(fde, state, info.mInfo);
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
  // TODO: Implement frame unwind caching.
  if (mCallstackState == CallStackState::Full) {
    return;
  }
  const auto pc = mTask->GetRegisterCache().GetPc();
  sym::UnwindIterator it{mSupervisor, pc};
  auto uninfo = it.GetInfo(pc);
  bool initialized = false;
  if (!uninfo) {
    constexpr auto STACK_POINTER_NUMBER = 7;
    // we may be in a plt entry. Try sniffing out this frame before throwing away the entire call stack
    // a call instruction automatically pushes rip onto the stack at $rsp
    const auto resumeAddress = mSupervisor->ReadType(TPtr<u64>{mTask->GetRegister(STACK_POINTER_NUMBER)});
    uninfo = it.GetInfo(resumeAddress);
    if (uninfo) {
      Initialize();
      mFrameProgramCounters.push_back(GetTopMostPc());
      initialized = true;
      mUnwoundRegister.push_back({});
      auto [newest, older] = GetCurrent();
      const auto regs = newest->RegisterCount();
      mUnwoundRegister.back().Reserve(regs);
      const auto &cloneFrom = *(mUnwoundRegister.rbegin() + 1);
      for (auto i = 0u; i < regs; ++i) {
        mUnwoundRegister.back().Set(i, cloneFrom.GetRegister(i));
      }
      mUnwoundRegister.back().Set(X86_64_RIP_REGISTER, resumeAddress);
    } else {
      return;
    }
  }

  if (!initialized) {
    Initialize();
  }

  sym::CFAStateMachine cfa_state = sym::CFAStateMachine::Init(*mSupervisor, *mTask, uninfo.value(), pc);
  mFrameProgramCounters.push_back(GetTopMostPc());

  auto [request, count, _] = req;

  switch (request) {
  case CallStackRequest::Type::Full: {
    for (auto uinf = uninfo; uinf.has_value(); uinf = it.GetInfo(GetTopMostPc())) {
      const auto pc = GetTopMostPc();
      cfa_state.Reset(uinf.value(), mUnwoundRegister.back(), pc);
      decode_eh_insts(uinf.value(), cfa_state);
      const auto keepUnwinding = ResolveNewFrameRegisters(cfa_state);
      if (!keepUnwinding) {
        break;
      }
      mFrameProgramCounters.push_back(GetTopMostPc());
    }
    mCallstackState = CallStackState::Full;
    break;
  }
  case CallStackRequest::Type::Partial: {
    for (auto uinf = uninfo; uinf.has_value() && count > 0; uinf = it.GetInfo(GetTopMostPc())) {
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
    mCallstackState = CallStackState::Partial;
    break;
  }
  }
}

} // namespace mdb::sym