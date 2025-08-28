/** LICENSE TEMPLATE */
// mdb
#include "supervisor.h"
#include "event_queue.h"
#include <common.h>
#include <common/macros.h>
#include <interface/dap/events.h>
#include <interface/dap/interface.h>
#include <interface/dap/types.h>
#include <interface/tracee_command/tracee_command_interface.h>
#include <jobs/dwarf_unit_data.h>
#include <jobs/index_die_names.h>
#include <mdbsys/ptrace.h>
#include <supervisor.h>
#include <symbolication/dwarf/name_index.h>
#include <symbolication/dwarf_binary_reader.h>
#include <symbolication/dwarf_expressions.h>
#include <symbolication/dwarf_frameunwinder.h>
#include <symbolication/elf_symbols.h>
#include <symbolication/objfile.h>
#include <tracer.h>
#include <utils/byte_buffer.h>
#include <utils/enumerator.h>
#include <utils/expected.h>
#include <utils/immutable.h>
#include <utils/logger.h>
// stdlib
#include <algorithm>
#include <filesystem>
#include <ranges>
#include <set>
#include <span>
#include <string_view>
#include <utility>
// system
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>

namespace mdb {

using sym::dw::SourceCodeFile;

template <typename TaskPointerType>
constexpr auto
FindByTid(std::vector<TaskPointerType> &container, Tid tid) noexcept
{
  return std::find_if(container.begin(), container.end(), [tid](const auto &task) { return task.mTid == tid; });
}

// FORK constructor
TraceeController::TraceeController(
  u32 sessionId, TraceeController &parent, tc::Interface &&interface, bool isVFork) noexcept
    : mSessionId(sessionId), mParentPid(parent.mTaskLeader), mTaskLeader{ interface->TaskLeaderTid() },
      mSymbolFiles(parent.mSymbolFiles), mMainExecutable{ parent.mMainExecutable }, mThreads{}, mThreadInfos{},
      mUserBreakpoints{ *this }, mInterfaceType{ parent.mInterfaceType }, mSessionKind{ parent.mSessionKind },
      mScheduler{ std::make_unique<TaskScheduler>(this) }, mNullUnwinder{ parent.mNullUnwinder },
      mTraceeInterface{ std::move(interface) }, mAllStopSession{ mTraceeInterface->IsAllStopSession() }
{
  mIsVForking = isVFork;
  // Must be set first.
  mTraceeInterface->SetTarget(this);
  mThreads.reserve(64);

  // Out of order events may have already created the task.
  if (auto t = Tracer::Get().TakeUninitializedTask(mTraceeInterface->TaskLeaderTid()); t) {
    MDB_ASSERT(t->mSupervisor == nullptr, "This task {} already has a supervisor.", t->mTid);
    t->InitializeThread(*mTraceeInterface, false);
    AddTask(std::move(t));
  } else {
    auto task = TaskInfo::CreateTask(*mTraceeInterface, mTraceeInterface->TaskLeaderTid(), false);
    Tracer::Get().RegisterTracedTask(task);
    AddTask(std::move(task));
  }

  mNewObjectFilePublisher.Subscribe(SubscriberIdentity::Of(this), [this](const SymbolFile *sf) {
    mDebugAdapterClient->PostDapEvent(new ui::dap::ModuleEvent{ mTaskLeader, "new", *sf });
  });
  mBreakpointBehavior = parent.mBreakpointBehavior;
}

TraceeController::TraceeController(SessionId sessionId) noexcept
    : mSessionId(sessionId), mParentPid(0), mTaskLeader{ 0 }, mMainExecutable{ nullptr }, mThreads{},
      mThreadInfos{}, mUserBreakpoints{ *this }, mInterfaceType(InterfaceType::GdbRemote),
      mSessionKind{ TargetSession::Attached }, mScheduler{ std::make_unique<TaskScheduler>(this) },
      mNullUnwinder{ new sym::Unwinder{ nullptr } }, mTraceeInterface(nullptr)
{
}

/* static*/
std::unique_ptr<TraceeController>
TraceeController::CreateDetached(SessionId sessionId) noexcept
{
  return std::unique_ptr<TraceeController>(new TraceeController{ sessionId });
}

void
TraceeController::InitializeSupervisor(
  TargetSession session, tc::Interface &&interface, InterfaceType type) noexcept
{
  DBGLOG(core, "Initializing supervisor {}", mSessionId);
  mThreads.reserve(64);
  mSessionKind = session;
  mInterfaceType = type;
  mTaskLeader = interface != nullptr ? interface->TaskLeaderTid() : 0;
  mTraceeInterface = std::move(interface);
  mTraceeInterface->SetTarget(this);
  mAllStopSession = mTraceeInterface->IsAllStopSession();

  auto task = TaskInfo::CreateTask(*mTraceeInterface, mTraceeInterface->TaskLeaderTid(), true);
  Tracer::Get().RegisterTracedTask(task);
  AddTask(std::move(task));

  mNewObjectFilePublisher.Subscribe(SubscriberIdentity::Of(this), [this](const SymbolFile *sf) {
    mDebugAdapterClient->PostDapEvent(new ui::dap::ModuleEvent{ mTaskLeader, "new", *sf });
  });
}

TraceeController::TraceeController(
  u32 sessionId, TargetSession targetSession, tc::Interface &&interface, InterfaceType type) noexcept
    : mSessionId(sessionId), mParentPid(0), mTaskLeader{ interface != nullptr ? interface->TaskLeaderTid() : 0 },
      mMainExecutable{ nullptr }, mThreads{}, mThreadInfos{}, mUserBreakpoints{ *this }, mInterfaceType(type),
      mSessionKind{ targetSession }, mScheduler{ std::make_unique<TaskScheduler>(this) },
      mNullUnwinder{ new sym::Unwinder{ nullptr } }, mTraceeInterface(std::move(interface)),
      mAllStopSession(mTraceeInterface->IsAllStopSession())
{
  // Must be set first.
  mTraceeInterface->SetTarget(this);
  mThreads.reserve(64);
  auto task = TaskInfo::CreateTask(*mTraceeInterface, mTraceeInterface->TaskLeaderTid(), true);
  Tracer::Get().RegisterTracedTask(task);
  AddTask(std::move(task));

  mNewObjectFilePublisher.Subscribe(SubscriberIdentity::Of(this), [this](const SymbolFile *sf) {
    mDebugAdapterClient->PostDapEvent(new ui::dap::ModuleEvent{ mTaskLeader, "new", *sf });
  });
}

/*static*/
std::unique_ptr<TraceeController>
TraceeController::create(u32 sessionId, TargetSession session, tc::Interface &&interface, InterfaceType type)
{
  return std::unique_ptr<TraceeController>(new TraceeController{ sessionId, session, std::move(interface), type });
}

void
TraceeController::ConfigureBreakpointBehavior(BreakpointBehavior behavior) noexcept
{
  mBreakpointBehavior = behavior;
}

void
TraceeController::TearDown(bool killProcess) noexcept
{
  DBGLOG(core,
    "Tear down traced process space {} - unclear if this method is needed. Kill={}",
    mTaskLeader,
    killProcess);
  mIsExited = true;
  mUserBreakpoints.OnProcessExit();
}

bool
TraceeController::IsExited() const noexcept
{
  return mIsExited;
}

void
TraceeController::ConfigureDapClient(ui::dap::DebugAdapterClient *client) noexcept
{
  mDebugAdapterClient = client;
}

void
TraceeController::Disconnect() noexcept
{
  StopAllTasks();
  const auto ok = GetInterface().DoDisconnect(false);
  VERIFY(ok.is_ok(), "Failed to disconnect: {}", strerror(ok.sys_errno));
}

std::unique_ptr<TraceeController>
TraceeController::Fork(tc::Interface &&interface, bool isVFork) noexcept
{
  auto child = std::unique_ptr<TraceeController>(
    new TraceeController{ Tracer::Get().NewSupervisorId(), *this, std::move(interface), isVFork });
  return child;
}

TraceeController::~TraceeController() noexcept
{
  /// TODO(simon): Introduce arena allocator per supervisor - this way, when a supervisor dies, it blinks out all
  /// the memory it's consuming without running MANY destructors. We won't be able to just use canonical std::pmr,
  /// we will need to write our own stuff on top of it, for instance
  // some data is shared between supervisors (if their symbolfiles are the same, for instance). But, I'm thinking
  // this won't be that difficult just add some form of reference counting to the actual `SupervisorAllocator`
  // (e.g.) and when it goes to 0 => blink the memory.
  DBGLOG(core, "Destroying supervisor state for {}", mTaskLeader);
}

AddrPtr
TraceeController::EntryAddress() const noexcept
{
  return mParsedAuxiliaryVector.mEntry;
}

std::span<std::shared_ptr<SymbolFile>>
TraceeController::GetSymbolFiles() noexcept
{
  return mSymbolFiles;
}

std::shared_ptr<SymbolFile>
TraceeController::LookupSymbolFile(const Path &path) noexcept
{
  for (const auto &s : mSymbolFiles) {
    if (s->GetObjectFile()->IsFile(path)) {
      return s;
    }
  }
  return nullptr;
}

auto
createSymbolFile(auto &tc, auto path, AddrPtr addr) noexcept -> std::shared_ptr<SymbolFile>
{
  auto existing_obj = Tracer::Get().LookupSymbolfile(path);
  if (existing_obj) {
    // This process already registered this symbol object.
    if (existing_obj->GetSupervisor() == &tc) {
      return nullptr;
    }
    // if baseAddr == addr; unique = false, return null, because we've already registered it
    return existing_obj->Copy(tc, addr);
  } else {
    auto obj = ObjectFile::CreateObjectFile(&tc, path);
    if (obj != nullptr) {
      return SymbolFile::Create(&tc, std::move(obj), addr);
    }
  }
  return nullptr;
}

static TPtr<r_debug_extended>
Get_rdebug_state(ObjectFile *objectFile)
{
  const auto rdebug_state = objectFile->FindMinimalObjectSymbol(LOADER_STATE);
  MDB_ASSERT(rdebug_state.has_value(), "Could not find _r_debug!");
  return rdebug_state->address.As<r_debug_extended>();
}

static Path
interpreter_path(const Elf *elf, const ElfSection *interp) noexcept
{
  MDB_ASSERT(interp->mName == ".interp", "Section is not .interp: {}", interp->mName);
  DwarfBinaryReader reader{ elf, interp->mSectionData };
  const auto path = reader.ReadString();
  DBGLOG(core, "Path to system interpreter: {}", path);
  return path;
}

static constexpr std::array<std::string_view, 6> LOADER_SYMBOL_NAMES = {
  "r_debug_state",
  "_r_debug_state",
  "_dl_debug_state",
  "rtld_db_dlactivity",
  "__dl_rtld_db_dlactivity",
  "_rtld_debug_state",
};

TPtr<r_debug_extended>
TraceeController::InstallDynamicLoaderBreakpoints() noexcept
{
  MDB_ASSERT(mMainExecutable != nullptr, "No main executable for this target");
  const auto mainExecutableElf = mMainExecutable->GetObjectFile()->GetElf();
  auto interpreterPath = interpreter_path(mainExecutableElf, mainExecutableElf->GetSection(".interp"));
  auto tempObjectFile = ObjectFile::CreateObjectFile(this, interpreterPath);
  MDB_ASSERT(tempObjectFile != nullptr, "Failed to mmap the loader binary");

  const auto interpreterBase = mParsedAuxiliaryVector.mInterpreterBaseAddress;

  mTraceeInterface->tracee_r_debug = interpreterBase + Get_rdebug_state(tempObjectFile.get());
  DBGLOG(core, "_r_debug found at {}", mTraceeInterface->tracee_r_debug);
  for (const auto symbolName : LOADER_SYMBOL_NAMES) {
    if (auto symbol = tempObjectFile->FindMinimalFunctionSymbol(symbolName); symbol) {
      const auto addr = interpreterBase + symbol->address;
      DBGLOG(core, "Setting ld breakpoint at 0x{:x}", addr);
      mUserBreakpoints.CreateBreakpointLocationUser<SOLoadingBreakpoint>(
        *this, GetOrCreateBreakpointLocation(addr), mTaskLeader);
    }
  }

  return mTraceeInterface->tracee_r_debug;
}

void
TraceeController::OnSharedObjectEvent() noexcept
{
  DBGLOG(core, "[{}:so] shared object event triggered", mTaskLeader);
  if (const auto readLibrariesResult = mTraceeInterface->ReadLibraries(); readLibrariesResult) {
    std::vector<std::shared_ptr<SymbolFile>> objectFiles{};
    const auto &libraries = readLibrariesResult.value();
    DBGLOG(core, "Object File Descriptors read: {}", libraries.size());
    for (const auto &[path, l_addr] : libraries) {
      auto symbolFile = createSymbolFile(*this, path, l_addr);
      if (symbolFile) {
        objectFiles.push_back(symbolFile);
        RegisterSymbolFile(symbolFile, false);
      }
    }
    DoBreakpointsUpdate(std::move(objectFiles));
  } else {
    DBGLOG(core, "No library info was returned");
  }
}

bool
TraceeController::IsNullUnwinder(sym::Unwinder *unwinder) const noexcept
{
  return unwinder == mNullUnwinder;
}

bool
TraceeController::IsIndividualTaskControlConfigured() noexcept
{
  return false;
}

void
TraceeController::AddTask(Ref<TaskInfo> &&task) noexcept
{
  Tid t = task->mTid;
  mThreads.push_back({ .mTid = t, .mTask = std::move(task) });
}

u32
TraceeController::RemoveTasksNotInSet(std::span<const gdb::GdbThread> set) noexcept
{
  std::vector<u32> removeTask;
  removeTask.reserve(mThreads.size());
  for (const auto &[idx, task] : mThreads | std::views::enumerate) {
    if (std::ranges::none_of(set, [tid = task.mTid](auto t) { return t.tid == tid; })) {
      removeTask.push_back(idx - removeTask.size());
    }
  }

  for (const auto index : removeTask) {
    mExitedThreads.push_back(std::move(mThreads[index]));
    mThreads.erase(mThreads.begin() + index);
  }
  return removeTask.size();
}

std::span<TaskInfo::InlinedTid>
TraceeController::GetThreads() noexcept
{
  return mThreads;
}

std::span<TaskInfo::InlinedTid>
TraceeController::GetExitedThreads() noexcept
{
  return mExitedThreads;
}

void
TraceeController::SetExitSeen() noexcept
{
  mIsExited = true;
}

Tid
TraceeController::TaskLeaderTid() const noexcept
{
  return mTaskLeader;
}

SessionId
TraceeController::GetSessionId() const noexcept
{
  return mSessionId;
}

TaskInfo *
TraceeController::GetTaskByTid(pid_t tid) noexcept
{
  for (auto &entry : mThreads) {
    if (entry.mTid == tid) {
      return entry.mTask.Get();
    }
  }
  return nullptr;
}

UserBreakpoints &
TraceeController::GetUserBreakpoints() noexcept
{
  return mUserBreakpoints;
}

TaskInfo *
TraceeController::GetOrCreateNewTask(Tid tid, bool running) noexcept
{
  if (auto *task = GetTaskByTid(tid); task) {
    return task;
  }

  CreateNewTask(tid, running);
  // TODO: Have CreateNewTask return the task directly instead, and annotate fn with [[maybe_unused]]
  return GetTaskByTid(tid);
}

void
TraceeController::CreateNewTask(Tid tid, bool running) noexcept
{
  MDB_ASSERT(tid != 0 && !HasTask(tid), "Task {} has already been created!", tid);
  auto task = TaskInfo::CreateTask(*mTraceeInterface, tid, running);
  Tracer::Get().RegisterTracedTask(task);
  AddTask(std::move(task));
}

bool
TraceeController::HasTask(Tid tid) noexcept
{
  for (const auto &taskEntry : mThreads) {
    if (taskEntry.mTid == tid) {
      return true;
    }
  }
  return false;
}

bool
TraceeController::ReverseResumeTarget(tc::ResumeAction type) noexcept
{
  // This is *probably* not necessary during Reverse Execution sessions, because we will be "noSingleThreadControl"
  // and I don't see how we could do anything but normal scheduling. But to keep with `ResumeTarget` we'll set it
  // here anyway, if in the future, this changes.
  mScheduler->SetNormalScheduling();
  mTraceeInterface->ReverseContinue(type.mResumeType == tc::RunType::Step);
  return true;
}

bool
TraceeController::ResumeTarget(tc::ResumeAction action, std::vector<Tid> *resumedThreads) noexcept
{
  DBGLOG(core, "[supervisor]: resume tracee {}", to_str(action.mResumeType));
  mScheduler->SetNormalScheduling();
  bool resumedAtLeastOne = false;
  for (auto &entry : mThreads) {
    resumedAtLeastOne |= entry.mTask->mUserVisibleStop;
  }
  return mTraceeInterface->ResumeTarget(this, action, resumedThreads).is_ok() && resumedAtLeastOne;
}

void
TraceeController::ResumeTask(TaskInfo &task, tc::ResumeAction type) noexcept
{
  mScheduler->SetNormalScheduling();

  if (task.mBreakpointLocationStatus.IsValid()) {
    task.StepOverBreakpoint(this, type.mResumeType);
  } else {
    const auto res = mTraceeInterface->ResumeTask(task, type);
    if (!res.is_ok()) {
      DBGLOG(core, "Unable to resume task {}: {}", task.mTid, strerror(res.sys_errno));
    }
  }
  task.mLastWaitStatus = WaitStatus{ WaitStatusKind::NotKnown, {} };
  task.SetCurrentResumeAction(type);
}

void
TraceeController::StopAllTasks(std::function<void()> &&callback) noexcept
{
  mAllStopPublisher.Once(std::move(callback));
  StopAllTasks();
}

void
TraceeController::StopAllTasks() noexcept
{
  DBGLOG(core, "Stopping all threads")
  // If all threads were at a signal-delivery stop, then we will not receive new wait status events
  // and we will never report to the user that everyone has stopped. We need to track that, and possibly emit a
  // stopped event immediately.
  mScheduler->SetStopAllScheduling();
  for (auto &entry : mThreads) {
    auto &t = *entry.mTask;
    if (!t.mUserVisibleStop && !t.mTracerVisibleStop) {
      DBGLOG(core, "Halting {}", t.mTid);
      const auto response = mTraceeInterface->StopTask(t);
      MDB_ASSERT(response.is_ok(), "Failed to stop {}: {}", t.mTid, strerror(response.sys_errno));
      t.SetUserVisibleStop();
    } else if (t.mTracerVisibleStop) {
      // we're in a tracer-stop, not in a user-stop, so we need no stopping, we only need to inform ourselves that
      // we upgraded our tracer-stop to a user-stop
      t.SetUserVisibleStop();
    }
  }

  if (IsAllStopped()) {
    mAllStopPublisher.Emit();
  }
}

TaskInfo *
TraceeController::RegisterTaskWaited(WaitPidResult wait) noexcept
{
  MDB_ASSERT(HasTask(wait.tid), "Target did not contain task {}", wait.tid);
  auto task = GetTaskByTid(wait.tid);
  task->SetTaskWait(wait);
  task->mTracerVisibleStop = true;
  return task;
}

AddrPtr
TraceeController::CacheAndGetPcFor(TaskInfo &t) noexcept
{
  if (t.mInstructionPointerDirty) {
    CacheRegistersFor(t);
  }
  return t.regs.GetPc();
}

void
TraceeController::SetProgramCounterFor(TaskInfo &task, AddrPtr addr) noexcept
{
  auto res = mTraceeInterface->SetProgramCounter(task, addr);
  MDB_ASSERT(res.is_ok(), "Failed to set PC for {}; {}", task.mTid, strerror(res.sys_errno));
  task.mInstructionPointerDirty = false;
}

void
TraceeController::SetTaskVmInfo(Tid tid, TaskVMInfo vmInfo) noexcept
{
  MDB_ASSERT(HasTask(tid), "Unknown task {}", tid);
  mThreadInfos[tid] = vmInfo;
}

void
TraceeController::SetIsOnEntry(bool setting) noexcept
{
  mOnEntry = setting;
}

bool
TraceeController::IsOnEntry() const noexcept
{
  return mOnEntry;
}

void
TraceeController::EmitStoppedAtBreakpoints(LWP lwp, u32 breakpointId, bool allStopped) noexcept
{
  /* todo(simon): make it possible to determine & set if allThreadsStopped is true or false. For now, we just say
   *  that all get stopped during this event. */
  DBGLOG(core, "[dap event]: stopped at breakpoint {} emitted", breakpointId);
  const bool stopAll = allStopped | mAllStopSession;
  auto evt = new ui::dap::StoppedEvent{
    mTaskLeader, ui::dap::StoppedReason::Breakpoint, "Breakpoint Hit", lwp.tid, {}, "", stopAll
  };
  evt->mBreakpointIds.push_back(breakpointId);
  mDebugAdapterClient->PostDapEvent(evt);
}

void
TraceeController::EmitStepNotification(LWP lwp) noexcept
{
  /* todo(simon): make it possible to determine & set if allThreadsStopped is true or false. For now, we just say
   *  that all get stopped during this event. */
  EmitSteppedStop(lwp, "Stepping finished", false);
}

void
TraceeController::EmitSteppedStop(LWP lwp, std::string_view message, bool allStopped) noexcept
{
  const bool stopAll = allStopped | mAllStopSession;
  mDebugAdapterClient->PostDapEvent(
    new ui::dap::StoppedEvent{ mTaskLeader, ui::dap::StoppedReason::Step, message, lwp.tid, {}, "", stopAll });
}

void
TraceeController::EmitSignalEvent(LWP lwp, int signal) noexcept
{
  /* todo(simon): make it possible to determine & set if allThreadsStopped is true or false. For now, we just say
   *  that all get stopped during this event. */
  const bool stopAll = mAllStopSession;
  mDebugAdapterClient->PostDapEvent(new ui::dap::StoppedEvent{ mTaskLeader,
    ui::dap::StoppedReason::Exception,
    std::format("Signalled {}", signal),
    lwp.tid,
    {},
    "",
    stopAll });
}

void
TraceeController::EmitStopped(Tid tid,
  ui::dap::StoppedReason reason,
  std::string_view message,
  bool allStopped,
  std::vector<int> breakpointsHit) noexcept
{
  const bool stopAll = allStopped | mAllStopSession;
  mDebugAdapterClient->PostDapEvent(
    new ui::dap::StoppedEvent{ mTaskLeader, reason, message, tid, std::move(breakpointsHit), message, stopAll });
}

void
TraceeController::EmitBreakpointEvent(
  std::string_view reason, const UserBreakpoint &bp, std::optional<std::string> message) noexcept
{
  mDebugAdapterClient->PostDapEvent(new ui::dap::BreakpointEvent{ mTaskLeader, reason, std::move(message), &bp });
}

tc::ProcessedStopEvent
TraceeController::ProcessDeferredStopEvent(TaskInfo &, DeferToSupervisor &) noexcept
{
  TODO("implement TraceeController::process_deferred_stopevent(TaskInfo &t, DeferToSupervisor &evt) noexcept");
}

mdb::Expected<Ref<BreakpointLocation>, BreakpointError>
TraceeController::GetOrCreateBreakpointLocation(AddrPtr addr) noexcept
{
  if (auto loc = mUserBreakpoints.GetLocationAt(addr); loc) {
    return loc;
  }

  auto res = InstallSoftwareBreakpointLocation(mTaskLeader, addr);
  if (!res.is_expected()) {
    return mdb::unexpected(res.take_error());
  }
  const auto original_byte = res.take_value();
  return BreakpointLocation::CreateLocation(addr, original_byte);
}

mdb::Expected<Ref<BreakpointLocation>, BreakpointError>
TraceeController::GetOrCreateBreakpointLocation(
  AddrPtr addr, sym::dw::SourceCodeFile &sourceFile, const sym::dw::LineTableEntry &lte) noexcept
{
  auto loc = mUserBreakpoints.GetLocationAt(addr);
  if (loc) {
    return loc;
  }

  auto res = InstallSoftwareBreakpointLocation(mTaskLeader, addr);
  if (!res.is_expected()) {
    return res.take_error();
  }
  auto original_byte = res.take_value();
  return BreakpointLocation::CreateLocationWithSource(addr,
    original_byte,
    std::make_unique<LocationSourceInfo>(sourceFile.mFullPath.StringView(), lte.line, u32{ lte.column }));
}

mdb::Expected<Ref<BreakpointLocation>, BreakpointError>
TraceeController::GetOrCreateBreakpointLocationWithSourceLoc(
  AddrPtr addr, std::optional<LocationSourceInfo> &&sourceLocInfo) noexcept
{
  if (auto loc = mUserBreakpoints.GetLocationAt(addr); loc) {
    return loc;
  }

  auto res = InstallSoftwareBreakpointLocation(mTaskLeader, addr);
  if (!res.is_expected()) {
    return res.take_error();
  }
  auto original_byte = res.take_value();
  if (sourceLocInfo) {
    return BreakpointLocation::CreateLocationWithSource(
      addr, original_byte, std::make_unique<LocationSourceInfo>(std::move(sourceLocInfo.value())));
  } else {
    return BreakpointLocation::CreateLocation(addr, original_byte);
  }
}

bool
TraceeController::CheckBreakpointLocationsForSymbolFile(
  SymbolFile &symbolFile, UserBreakpoint &user, std::vector<Ref<BreakpointLocation>> &locs) noexcept
{
  const auto sz = locs.size();
  if (auto specPtr = user.UserProvidedSpec(); specPtr != nullptr) {
    auto objfile = symbolFile.GetObjectFile();
    switch (specPtr->mKind) {
    case DapBreakpointType::source: {
      const auto &spec = specPtr->uSource;
      const auto predicate = [&srcSpec = spec->mSpec](const sym::dw::LineTableEntry &entry) {
        return srcSpec.line == entry.line && srcSpec.column.value_or(entry.column) == entry.column &&
               !entry.IsEndOfSequence;
      };
      for (auto &sourceCodeFile : objfile->GetSourceCodeFiles(spec->mFilePath)) {
        std::vector<sym::dw::LineTableEntry> entries;
        sourceCodeFile->ReadInSourceCodeLineTable(entries);

        for (const auto &lte : entries | std::views::filter(predicate)) {
          const auto pc = lte.pc + symbolFile.mBaseAddress;
          if (auto res = GetOrCreateBreakpointLocation(pc, *sourceCodeFile, lte); res.is_expected()) {
            locs.push_back(res.take_value());
            if (!spec->mSpec.column.has_value()) {
              break;
            }
          }
        }
      }
    } break;
    case DapBreakpointType::function: {
      auto result = symbolFile.LookupFunctionBreakpointBySpec(*specPtr);

      if (auto it =
            std::find_if(result.begin(), result.end(), [](const auto &it) { return it.loc_src_info.has_value(); });
        it != end(result)) {
        if (auto res =
              GetOrCreateBreakpointLocationWithSourceLoc(it->address, std::move(it->loc_src_info.value()));
          res.is_expected()) {
          locs.push_back(res.take_value());
        }
      } else {
        for (auto &&lookup : result) {
          if (auto res = GetOrCreateBreakpointLocation(lookup.address); res.is_expected()) {
            locs.push_back(res.take_value());
          }
        }
      }
    } break;
    case DapBreakpointType::instruction: {
      const auto &spec = *specPtr->uInstruction;
      auto addr_opt = ToAddress(spec.mInstructionReference);
      MDB_ASSERT(addr_opt.has_value(), "Failed to convert instructionReference to valid address");
      const auto addr = addr_opt.value();
      if (symbolFile.ContainsProgramCounter(addr)) {
        if (auto res = GetOrCreateBreakpointLocation(addr); res.is_expected()) {
          locs.push_back(res.take_value());
        }
      }
      break;
    } break;
    }
  }

  // No new breakpoint location could be found in symbol file.
  return locs.size() != sz;
}

void
TraceeController::DoBreakpointsUpdate(std::vector<std::shared_ptr<SymbolFile>> &&newSymbolFiles) noexcept
{
  auto non_verified = mUserBreakpoints.GetNonVerified();
  DBGLOG(
    core, "[breakpoints]: Updating breakpoints due to new symbol files; non verified={}", non_verified.size());

  // Check all existing breakpoints and those who are verified = false, check if they can be verified against the
  // new object files (and thus actually be set)

  for (auto &user : non_verified) {
    for (auto &symbol_file : newSymbolFiles) {
      // this user breakpoint was verified on previous iteration (i.e in another symbol file)
      if (user->IsVerified()) {
        break;
      }
      std::vector<Ref<BreakpointLocation>> newLocations;
      if (CheckBreakpointLocationsForSymbolFile(*symbol_file, *user, newLocations)) {
        newLocations.back()->AddUser(GetInterface(), *user);
        user->UpdateLocation(std::move(newLocations.back()));
        mUserBreakpoints.AddBreakpointLocation(*user);
        mDebugAdapterClient->PostDapEvent(new ui::dap::BreakpointEvent{ mTaskLeader, "changed", {}, user });
        newLocations.pop_back();

        for (auto &&loc : newLocations) {
          auto newUser = user->CloneBreakpoint(mUserBreakpoints, *this, loc);
          mDebugAdapterClient->PostDapEvent(new ui::dap::BreakpointEvent{ mTaskLeader, "new", {}, newUser });
          MDB_ASSERT(!loc->GetUserIds().empty(), "location has no user!");
        }
        newLocations.clear();
      }
    }
  }

  // Create new breakpoints, based on source specification or fn name spec, if they exist in new object files
  using Entry = sym::dw::LineTableEntry;

  // Do update for "source breakpoints", breakpoints set via a source spec
  for (auto &&sym : newSymbolFiles) {
    auto obj = sym->GetObjectFile();
    for (const auto &source_file : mUserBreakpoints.GetSourceFilesWithBreakpointSpecs()) {
      auto &file_bp_map = mUserBreakpoints.GetBreakpointsFromSourceFile(source_file);
      for (auto &sourceCodeFile : obj->GetSourceCodeFiles(source_file)) {
        std::vector<Entry> entries;
        for (auto &[desc, user_ids] : file_bp_map) {
          entries.clear();
          const auto predicate = [&desc](const Entry &lte) {
            return lte.line == desc.uSource->mSpec.line &&
                   desc.uSource->mSpec.column.value_or(lte.column) == lte.column && !lte.IsEndOfSequence;
          };
          sourceCodeFile->ReadInSourceCodeLineTable(entries);
          for (const auto &e : entries | std::views::filter(predicate)) {
            const auto pc = AddrPtr{ e.pc + sym->mBaseAddress };
            bool sameSourceLocDiffPc = false;
            for (const auto id : user_ids) {
              auto user = mUserBreakpoints.GetUserBreakpoint(id);
              if (user->Address() != pc) {
                sameSourceLocDiffPc = true;
              }
            }
            if (sameSourceLocDiffPc) {
              auto user = mUserBreakpoints.CreateBreakpointLocationUser<Breakpoint>(*this,
                GetOrCreateBreakpointLocation(pc, *sourceCodeFile, e),
                mTaskLeader,
                LocationUserKind::Source,
                desc.Clone());
              mDebugAdapterClient->PostDapEvent(new ui::dap::BreakpointEvent{ mTaskLeader, "new", {}, user });
              user_ids.push_back(user->mId);
              const auto last_slash = source_file.find_last_of('/');
              const std::string_view file_name =
                source_file.substr(last_slash == std::string_view::npos ? 0 : last_slash);
              DBGLOG(core,
                "[{}:bkpt:source:{}]: added bkpt at {}, (unreloc={})",
                mTaskLeader,
                file_name,
                pc,
                sym->UnrelocateAddress(pc));
            }
            // If the breakpoint spec has no column info, pick the first found line table entry with the desired
            // line.
            if (!desc.Column()) {
              break;
            }
          }
        }
      }
    }

    // Do update for "function breakpoints", set via a name or regex of a function name spec.
    for (auto &[fn, ids] : mUserBreakpoints.mFunctionBreakpoints) {
      auto result = sym->LookupFunctionBreakpointBySpec(fn);
      for (auto &&lookup : result) {
        auto user = mUserBreakpoints.CreateBreakpointLocationUser<Breakpoint>(*this,
          GetOrCreateBreakpointLocationWithSourceLoc(lookup.address, std::move(lookup.loc_src_info)),
          mTaskLeader,
          LocationUserKind::Function,
          fn.Clone());
        mDebugAdapterClient->PostDapEvent(new ui::dap::BreakpointEvent{ mTaskLeader, "new", {}, user });
        ids.push_back(user->mId);
      }
    }
  }
}

void
TraceeController::UpdateSourceBreakpoints(const std::filesystem::path &sourceFilePath,
  std::vector<BreakpointSpecification> &&add,
  const std::vector<BreakpointSpecification> &remove) noexcept
{
  UserBreakpoints::SourceFileBreakpointMap &map =
    mUserBreakpoints.GetBreakpointsFromSourceFile(sourceFilePath.string());

  Set<BreakpointSpecification> not_set{ add.begin(), add.end() };

  for (const auto &symbol_file : mSymbolFiles) {
    auto obj = symbol_file->GetObjectFile();
    for (auto &sourceCodeFile : obj->GetSourceCodeFiles(sourceFilePath.c_str())) {
      // TODO(simon): use arena allocator for foundEntries
      std::vector<sym::dw::LineTableEntry> foundEntries;
      for (const auto &sourceSpec : add) {
        foundEntries.clear();
        sourceCodeFile->ReadInSourceCodeLineTable(foundEntries);
        const auto predicate = [&sourceSpec](const sym::dw::LineTableEntry &entry) {
          if (entry.IsEndOfSequence) {
            return false;
          }
          return sourceSpec.Line().value() == entry.line &&
                 sourceSpec.Column().value_or(entry.column) == entry.column;
        };

        for (const auto &e : foundEntries | std::views::filter(predicate)) {
          const auto pc = e.pc + symbol_file->mBaseAddress;
          if (sourceSpec.uSource->mSpec.log_message) {
            auto user = mUserBreakpoints.CreateBreakpointLocationUser<Logpoint>(*this,
              GetOrCreateBreakpointLocation(pc, *sourceCodeFile, e),
              mTaskLeader,
              std::string_view{ sourceSpec.uSource->mSpec.log_message.value() },
              sourceSpec.Clone());
            map[sourceSpec].push_back(user->mId);
            DBGLOG(core,
              "[{}:bkpt:source:{}]: added bkpt {} at 0x{:x}, orig_byte=0x{:x}",
              mTaskLeader,
              sourceCodeFile->mFullPath.FileName(),
              user->mId,
              pc,
              user->GetLocation() != nullptr ? *user->GetLocation()->mOriginalByte : u8{ 0 });
          } else {
            auto user = mUserBreakpoints.CreateBreakpointLocationUser<Breakpoint>(*this,
              GetOrCreateBreakpointLocation(pc, *sourceCodeFile, e),
              mTaskLeader,
              LocationUserKind::Source,
              sourceSpec.Clone());
            map[sourceSpec].push_back(user->mId);
            DBGLOG(core,
              "[{}:bkpt:source:{}]: added bkpt {} at 0x{:x}, orig_byte=0x{:x}",
              mTaskLeader,
              sourceCodeFile->mFullPath.FileName(),
              user->mId,
              pc,
              user->GetLocation() != nullptr ? *user->GetLocation()->mOriginalByte : u8{ 0 });
          }

          if (const auto it = not_set.find(sourceSpec); it != std::end(not_set)) {
            not_set.erase(it);
          }
          if (!sourceSpec.Column()) {
            break;
          }
        }
      }
    }
  }

  // set User Breakpoints without breakpoint location; i.e. "pending" breakpoints, in GDB nomenclature
  for (auto &&srcbp : not_set) {
    auto spec = srcbp.Clone();
    if (spec->uSource->mSpec.log_message) {
      auto user = mUserBreakpoints.CreateBreakpointLocationUser<Logpoint>(*this,
        BreakpointError{ ResolveError{ .mSpecification = spec.get() } },
        mTaskLeader,
        std::string_view{ spec->uSource->mSpec.log_message.value() },
        std::move(spec));
      map[srcbp].push_back(user->mId);
    } else {
      auto user = mUserBreakpoints.CreateBreakpointLocationUser<Breakpoint>(*this,
        BreakpointError{ ResolveError{ .mSpecification = spec.get() } },
        mTaskLeader,
        LocationUserKind::Source,
        std::move(spec));
      map[srcbp].push_back(user->mId);
    }
  }

  for (const auto &bp : remove) {
    auto iter = map.find(bp);
    for (const auto id : iter->second) {
      mUserBreakpoints.RemoveUserBreakpoint(id);
    }
    map.erase(map.find(bp));
  }
}

void
TraceeController::SetSourceBreakpoints(
  const std::filesystem::path &sourceFilePath, const Set<BreakpointSpecification> &breakpoints) noexcept
{
  const UserBreakpoints::SourceFileBreakpointMap &map =
    mUserBreakpoints.GetBreakpointsFromSourceFile(sourceFilePath.string());
  std::vector<BreakpointSpecification> remove{};
  std::vector<BreakpointSpecification> add{};

  for (const auto &[b, id] : map) {
    if (!breakpoints.contains(b)) {
      remove.push_back(b);
    }
  }

  for (const auto &b : breakpoints) {
    if (!map.contains(b)) {
      add.push_back(b);
    }
  }

  UpdateSourceBreakpoints(sourceFilePath, std::move(add), remove);
}

void
TraceeController::SetInstructionBreakpoints(const Set<BreakpointSpecification> &breakpoints) noexcept
{
  MDB_ASSERT(std::ranges::all_of(
               breakpoints, [](const auto &item) { return item.mKind == DapBreakpointType::instruction; }),
    "Require all bps be instruction breakpoints");
  std::vector<BreakpointSpecification> add{};
  std::vector<BreakpointSpecification> remove{};

  for (const auto &bp : breakpoints) {
    if (!mUserBreakpoints.mInstructionBreakpoints.contains(bp)) {
      add.push_back(bp);
    }
  }

  for (const auto &bp : add) {
    auto addr = ToAddress(bp.uInstruction->mInstructionReference).value();
    bool was_not_set = true;
    if (auto symbolFile = FindObjectByPc(addr); symbolFile) {
      auto cus = symbolFile->GetCompilationUnits(addr);
      for (auto cu : cus) {
        auto [src, lte] = cu->GetLineTableEntry(symbolFile->UnrelocateAddress(addr));
        if (src && lte) {
          const auto user = mUserBreakpoints.CreateBreakpointLocationUser<Breakpoint>(*this,
            GetOrCreateBreakpointLocation(addr, *src, *lte),
            mTaskLeader,
            LocationUserKind::Address,
            bp.Clone());
          mUserBreakpoints.mInstructionBreakpoints[bp] = user->mId;
          was_not_set = false;
          break;
        }
      }
    }
    if (was_not_set) {
      const auto user = mUserBreakpoints.CreateBreakpointLocationUser<Breakpoint>(
        *this, GetOrCreateBreakpointLocation(addr), mTaskLeader, LocationUserKind::Address, bp.Clone());
      mUserBreakpoints.mInstructionBreakpoints[bp] = user->mId;
    }
  }

  for (const auto &bp : remove) {
    auto iter = mUserBreakpoints.mInstructionBreakpoints.find(bp);
    MDB_ASSERT(iter != std::end(mUserBreakpoints.mInstructionBreakpoints), "Expected to find breakpoint");
    mUserBreakpoints.RemoveUserBreakpoint(iter->second);
    mUserBreakpoints.mInstructionBreakpoints.erase(iter);
  }
}

void
TraceeController::SetFunctionBreakpoints(const Set<BreakpointSpecification> &breakpoints) noexcept
{
  std::vector<BreakpointSpecification> remove{};
  struct SpecWasSet
  {
    BreakpointSpecification mSpec;
    size_t mSpecHash;
    bool mWasSet;
  };

  std::vector<SpecWasSet> specsToAdd;

  for (const auto &[b, id] : mUserBreakpoints.mFunctionBreakpoints) {
    if (!breakpoints.contains(b)) {
      remove.push_back(b);
    }
  }

  for (const auto &to_remove : remove) {
    auto iter = mUserBreakpoints.mFunctionBreakpoints.find(to_remove);
    MDB_ASSERT(iter != std::end(mUserBreakpoints.mFunctionBreakpoints), "Expected to find fn breakpoint in map");

    for (auto id : iter->second) {
      mUserBreakpoints.RemoveUserBreakpoint(id);
    }
    mUserBreakpoints.mFunctionBreakpoints.erase(iter);
  }

  std::hash<BreakpointSpecification> specHasher{};
  for (const auto &b : breakpoints) {
    if (!mUserBreakpoints.mFunctionBreakpoints.contains(b)) {
      specsToAdd.push_back({ b, specHasher(b), false });
    }
  }

  for (auto &sym : mSymbolFiles) {
    for (auto &fn : specsToAdd) {
      auto result = sym->LookupFunctionBreakpointBySpec(fn.mSpec);
      for (auto &&lookup : result) {
        auto user = mUserBreakpoints.CreateBreakpointLocationUser<Breakpoint>(*this,
          GetOrCreateBreakpointLocationWithSourceLoc(lookup.address, std::move(lookup.loc_src_info)),
          mTaskLeader,
          LocationUserKind::Function,
          fn.mSpec.Clone());
        mUserBreakpoints.mFunctionBreakpoints[fn.mSpec].push_back(user->mId);
        fn.mWasSet = true;
        mDebugAdapterClient->PostDapEvent(
          new ui::dap::BreakpointEvent{ mTaskLeader, "new", "Breakpoint was created", user });
      }
    }
  }

  for (auto &&[spec, specHash, wasSet] : specsToAdd) {
    if (!wasSet) {
      auto spec_ptr = spec.Clone();
      auto user = mUserBreakpoints.CreateBreakpointLocationUser<Breakpoint>(*this,
        BreakpointError{ ResolveError{ .mSpecification = spec_ptr.get() } },
        mTaskLeader,
        LocationUserKind::Function,
        std::move(spec_ptr));
      mUserBreakpoints.mFunctionBreakpoints[spec].push_back(user->mId);
    }
  }
}

void
TraceeController::RemoveBreakpoint(u32 breakpointId) noexcept
{
  mUserBreakpoints.RemoveUserBreakpoint(breakpointId);
}

bool
TraceeController::TryTerminateGracefully() noexcept
{
  DBGLOG(core, "[TraceeController]: terminate gracefully");
  if (IsRunning()) {
    StopAllTasks();
  }

  return ::kill(mTaskLeader, SIGKILL) == 0;
}

static inline void
CreateTraceEventFromStopped(TraceEvent *event, TraceeController &tc, TaskInfo &t) noexcept
{
  MDB_ASSERT(t.mLastWaitStatus.ws != WaitStatusKind::NotKnown,
    "When creating a trace event from a wait status event, we must already know what kind it is.");

  const auto pc = tc.CacheAndGetPcFor(t);
  const auto breakpointAdjustedProgramCounter = offset(pc, -1);
  RefPtr breakpointLocation = tc.GetUserBreakpoints().GetLocationAt(breakpointAdjustedProgramCounter);

  // If there _is_ a breakpointLocation at `breakpointAdjustedProgramCounter`, _and_ event->mPostBreakpointOverStep
  // is set it means we have stepped over a breakpoint, and landed right on the boundary of a new breakpoint - but
  // it's much simpler to just not care about that it's a breakpoint there, and instead just resume the task (as
  // this actually will trigger a breakpoint/SIGTRAP, whereby event->mPostBreakpointOverStep will be false and a
  // breakpoint event created)
  if (breakpointLocation != nullptr && !event->mPostBreakpointOverStep) {
    tc.SetProgramCounterFor(t, breakpointAdjustedProgramCounter);
    return TraceEvent::InitSoftwareBreakpointHit(event,
      { .target = tc.TaskLeaderTid(), .tid = t.mTid, .sig_or_code = {}, .event_time = {} },
      breakpointAdjustedProgramCounter,
      {});
  }

  return TraceEvent::InitDeferToSupervisor(event,
    { .target = tc.TaskLeaderTid(), .tid = t.mTid, .sig_or_code = t.mLastWaitStatus.signal, .event_time = {} },
    {},
    false);
}

static inline void
NativeInitCloneEvent(TraceEvent &evt, TraceeController &control) noexcept
{
  VERIFY(evt.mTask, "Invariant broken: Task requires to be non-null");
  auto &cloningTask = *evt.mTask;
  DBGLOG(core, "Processing CLONE for {}", cloningTask.mTid);
  // we always have to cache these registers, because we need them to pull out some information
  // about the new clone
  control.CacheRegistersFor(*evt.mTask);
  pid_t np = -1;
  // we should only ever hit this when running debugging a native-hosted session
  MDB_ASSERT(
    control.GetInterface().mFormat == TargetFormat::Native, "We somehow ended up heer while debugging a remote");
  auto *regs = cloningTask.NativeRegisters();
  const auto orig_rax = regs->orig_rax;
  if (orig_rax == SYS_clone) {
    const TPtr<void> stack_ptr = sys_arg_n<2>(*regs);
    const TPtr<int> child_tid = sys_arg_n<4>(*regs);
    const u64 tls = sys_arg_n<5>(*regs);
    np = control.ReadType(child_tid);

    MDB_ASSERT(!control.HasTask(np), "Tracee controller already has task {} !", np);
    return TraceEvent::InitCloneEvent(&evt,
      { control.TaskLeaderTid(), cloningTask.mTid, 5, {} },
      TaskVMInfo{ .stack_low = stack_ptr, .stack_size = 0, .tls = tls },
      np,
      {});
  } else if (orig_rax == SYS_clone3) {
    const TraceePointer<clone_args> ptr = sys_arg<SysRegister::RDI>(*regs);
    const auto res = control.ReadType(ptr);
    np = control.ReadType(TPtr<pid_t>{ res.parent_tid });
    return TraceEvent::InitCloneEvent(
      &evt, { control.TaskLeaderTid(), cloningTask.mTid, 5, {} }, TaskVMInfo::from_clone_args(res), np, {});
  } else {
    PANIC("Unknown clone syscall!");
  }
}

TraceEvent *
TraceeController::CreateTraceEventFromWaitStatus(TaskInfo &info) noexcept
{
  info.mHasProcessedStop = true;
  const auto ws = info.PendingWaitStatus();

  TraceEvent *event = new TraceEvent{ info };

  if (info.mBreakpointLocationStatus.mSteppingOverState.mIsSteppingOver) {
    if (!info.mBreakpointLocationStatus.mBreakpointLocation->GetUserIds().empty()) {
      info.mBreakpointLocationStatus.mBreakpointLocation->Enable(info.mTid, GetInterface());
    }
    event->SetSteppedOverBreakpointNeedsResume(
      info.mBreakpointLocationStatus.mSteppingOverState.mResumeActionUponCompletion);
    info.ClearBreakpointLocStatus();
  }

  switch (ws.ws) {
  case WaitStatusKind::Stopped: {
    if (!info.initialized) {
      TraceEvent::InitThreadCreated(
        event, { mTaskLeader, info.mTid, 5, {} }, { tc::RunType::Continue, tc::ResumeTarget::Task, {} }, {});
    } else {
      CreateTraceEventFromStopped(event, *this, info);
    }
    return event;
  }
  case WaitStatusKind::Execed: {
    TraceEvent::InitExecEvent(event,
      { .target = mTaskLeader, .tid = info.mTid, .sig_or_code = 5, .event_time = {} },
      ProcessExecPath(info.mTid),
      {});
    return event;
  }
  case WaitStatusKind::Exited: {
    TraceEvent::InitThreadExited(event, { mTaskLeader, info.mTid, ws.exit_code, {} }, false, {});
    return event;
  }
  case WaitStatusKind::Forked: {
    Tid newChild = 0;
    auto result = ptrace(PTRACE_GETEVENTMSG, info.mTid, nullptr, &newChild);
    MDB_ASSERT(result != -1, "Failed to get new pid for forked child; {}", strerror(errno));
    DBGLOG(core, "[{} forked]: new process after fork {}", info.mTid, newChild);
    TraceEvent::InitForkEvent_(event, { mTaskLeader, info.mTid, 5, {} }, newChild, {});
    return event;
  }
  case WaitStatusKind::VForked: {
    Tid new_child = 0;
    auto result = ptrace(PTRACE_GETEVENTMSG, info.mTid, nullptr, &new_child);
    MDB_ASSERT(result != -1, "Failed to get new pid for forked child; {}", strerror(errno));
    DBGLOG(core, "[vfork]: new process after fork {}", new_child);
    TraceEvent::InitVForkEvent_(event, { mTaskLeader, info.mTid, 5, {} }, new_child, {});
    return event;
  }
  case WaitStatusKind::VForkDone:
    TODO("WaitStatusKind::VForkDone");
    break;
  case WaitStatusKind::Cloned: {
    NativeInitCloneEvent(*event, *this);
    return event;
  } break;
  case WaitStatusKind::Signalled:
    TraceEvent::InitSignal(event, { mTaskLeader, info.mTid, info.mLastWaitStatus.signal, {} }, {});
    return event;
  case WaitStatusKind::SyscallEntry:
    TODO("WaitStatusKind::SyscallEntry");
    break;
  case WaitStatusKind::SyscallExit:
    TODO("WaitStatusKind::SyscallExit");
    break;
  case WaitStatusKind::NotKnown:
    TODO("WaitStatusKind::NotKnown");
    break;
  }
  MDB_ASSERT(false, "Unknown wait status!");
  MIDAS_UNREACHABLE
}

bool
TraceeController::SetAndCallRunAction(Tid tid, std::shared_ptr<ptracestop::ThreadProceedAction> action) noexcept
{
  return mScheduler->SetTaskScheduling(tid, std::move(action), true);
}

bool
TraceeController::ExecutionHasNotEnded() const noexcept
{
  return !mThreads.empty();
}

bool
TraceeController::SomeTaskCanBeResumed() const noexcept
{
  return std::any_of(mThreads.cbegin(), mThreads.cend(), [](const auto &entry) {
    DBGLOG(core, "Thread {} stopped={}", entry.mTid, entry.mTask->IsStopped());
    return entry.mTask->IsStopped();
  });
}

bool
TraceeController::IsRunning() const noexcept
{
  return std::any_of(mThreads.cbegin(), mThreads.cend(), [](const auto &entry) {
    DBGLOG(core, "Thread {} stopped={}", entry.mTid, entry.mTask->IsStopped());
    return !entry.mTask->IsStopped();
  });
}

void
TraceeController::RegisterSymbolFile(std::shared_ptr<SymbolFile> symbolFile, bool isMainExecutable) noexcept
{
  const auto it = std::find_if(mSymbolFiles.begin(), mSymbolFiles.end(), [&symbolFile](auto &s) {
    return symbolFile->GetObjectFilePath() == s->GetObjectFilePath();
  });
  if (it != std::end(mSymbolFiles)) {
    const auto same_bounds = symbolFile->mPcBounds == (*it)->mPcBounds;
    DBGLOG(core,
      "[{}:symbol file]: Already added {} at {} .. {}; new is at {}..{} - Same range?: {}",
      mTaskLeader,
      symbolFile->GetObjectFilePath().c_str(),
      (*it)->LowProgramCounter(),
      (*it)->HighProgramCounter(),
      symbolFile->LowProgramCounter(),
      symbolFile->HighProgramCounter(),
      same_bounds)
    return;
  }
  mSymbolFiles.emplace_back(symbolFile);

  if (isMainExecutable) {
    mMainExecutable = mSymbolFiles.back();
  }

  // todo(simon): optimization possible; insert in a sorted fashion instead.
  std::sort(mSymbolFiles.begin(), mSymbolFiles.end(), [&symbolFile](auto &&a, auto &&b) {
    MDB_ASSERT(a->LowProgramCounter() != b->LowProgramCounter(),
      "[{}]: Added object files with identical address ranges. We screwed something up, for sure\na={}\nb={}",
      symbolFile->GetObjectFilePath().c_str(),
      a->GetObjectFilePath().c_str(),
      b->GetObjectFilePath().c_str());
    return a->LowProgramCounter() < b->LowProgramCounter() && a->HighProgramCounter() < b->HighProgramCounter();
  });
  mNewObjectFilePublisher.Emit(symbolFile.get());
}

// Debug Symbols Related Logic
void
TraceeController::RegisterObjectFile(
  TraceeController *tc, std::shared_ptr<ObjectFile> &&obj, bool isMainExecutable, AddrPtr relocatedBase) noexcept
{
  MDB_ASSERT(obj != nullptr, "Object file is null");
  RegisterSymbolFile(SymbolFile::Create(tc, std::move(obj), relocatedBase), isMainExecutable);
}

void
TraceeController::SetAuxiliaryVector(ParsedAuxiliaryVector data) noexcept
{
  mParsedAuxiliaryVector = data;
}

void
TraceeController::ReadAuxiliaryVector(TaskInfo &task)
{
  MDB_ASSERT(task.mLastWaitStatus.ws == WaitStatusKind::Execed,
    "Reading AUXV using this function does not make sense if's not *right* after an EXEC");
  CacheRegistersFor(task);
  TPtr<i64> stackPointer = task.regs.registers->rsp;
  const i64 argc = ReadType(stackPointer);

  stackPointer += argc + 1;
  MDB_ASSERT(ReadType(stackPointer) == 0, "Expected null terminator after argv at {}", stackPointer);
  stackPointer++;
  auto envp = stackPointer.As<const char *>();
  // we're at the envp now, that pointer list is also terminated by a nullptr
  while (ReadType(envp) != nullptr) {
    envp++;
  }
  // We should now be at Auxilliary Vector Table (see `man getauxval` for info, we're interested in the
  // interpreter base address)

  envp++;
  // cast it to our own type
  auto auxPointer = envp.As<tc::AuxvElement>();
  tc::Auxv result;
  for (;;) {
    auto kvp = ReadType(auxPointer);
    result.mContents.push_back(kvp);
    // terminated by a "null entry"
    if (kvp.mId == 0) {
      break;
    }
    auxPointer++;
  }

  SetAuxiliaryVector(ParsedAuxiliaryVectorData(result, { .requireEntry = true, .requiresInterpreterBase = true }));
}

TargetSession
TraceeController::GetSessionType() const noexcept
{
  return mSessionKind;
}

mdb::Expected<std::unique_ptr<mdb::ByteBuffer>, NonFullRead>
TraceeController::SafeRead(AddrPtr addr, u64 bytes) noexcept
{
  auto buffer = mdb::ByteBuffer::create(bytes);

  auto totalRead = 0ull;
  while (totalRead < bytes) {
    auto res = mTraceeInterface->ReadBytes(addr, bytes - totalRead, buffer->next());
    if (!res.WasSuccessful()) {
      return mdb::unexpected(NonFullRead{ std::move(buffer), static_cast<u32>(bytes - totalRead), errno });
    }
    buffer->wrote_bytes(res.uBytesRead);
    totalRead += res.uBytesRead;
  }
  return mdb::Expected<std::unique_ptr<mdb::ByteBuffer>, NonFullRead>{ std::move(buffer) };
}

mdb::Expected<std::unique_ptr<mdb::ByteBuffer>, NonFullRead>
TraceeController::SafeRead(std::pmr::memory_resource *allocator, AddrPtr addr, u64 bytes) noexcept
{
  auto buffer = mdb::ByteBuffer::create(allocator, bytes);

  auto totalRead = 0ull;
  while (totalRead < bytes) {
    auto res = mTraceeInterface->ReadBytes(addr, bytes - totalRead, buffer->next());
    if (!res.WasSuccessful()) {
      return mdb::unexpected(NonFullRead{ std::move(buffer), static_cast<u32>(bytes - totalRead), errno });
    }
    buffer->wrote_bytes(res.uBytesRead);
    totalRead += res.uBytesRead;
  }
  return mdb::Expected<std::unique_ptr<mdb::ByteBuffer>, NonFullRead>{ std::move(buffer) };
}

std::unique_ptr<mdb::LeakVector<u8>>
TraceeController::ReadToVector(AddrPtr addr, u64 bytes, std::pmr::memory_resource *resource) noexcept
{
  auto data = mdb::LeakVector<u8>::Create(bytes, resource);

  auto totalRead = 0ull;
  while (totalRead < bytes) {
    const auto read_address = addr + totalRead;
    const auto result = mTraceeInterface->ReadBytes(read_address, bytes - totalRead, data->data_ptr() + totalRead);
    if (!result.WasSuccessful()) {
      PANIC(std::format("Failed to proc_fs read from {}", addr));
    }
    totalRead += result.uBytesRead;
  }
  data->set_size(totalRead);
  return data;
}

bool
TraceeController::WriteBytes(AddrPtr address, std::span<u8> bytes) noexcept
{
  const auto result = mTraceeInterface->WriteBytes(address, bytes);
  return result.mWasSuccessful;
}

std::optional<std::string>
TraceeController::ReadString(TraceePointer<char> address) noexcept
{
  std::string result;
  if (address == nullptr) {
    return std::nullopt;
  }
  auto ch = ReadType<char>(address);
  while (ch != 0) {
    result.push_back(ch);
    address += 1;
    ch = ReadType<char>(address);
  }
  if (result.empty()) {
    return std::nullopt;
  }
  return result;
}

sym::Frame
TraceeController::GetCurrentFrame(TaskInfo &task) noexcept
{
  const auto pc = CacheAndGetPcFor(task);
  const auto obj = FindObjectByPc(pc);
  if (obj == nullptr) {
    return sym::Frame{ nullptr, task, 0, 0, pc, nullptr };
  }
  auto matchingCompilationUnits = obj->GetUnitDataFromProgramCounter(pc);

  for (auto src : matchingCompilationUnits) {
    if (auto fn = src->GetFunctionSymbolByProgramCounter(obj->UnrelocateAddress(pc)); fn) {
      return sym::Frame{ obj, task, 0, 0, pc, fn };
    }
  }

  if (auto min_sym = obj->SearchMinimalSymbolFunctionInfo(pc); min_sym != nullptr) {
    return sym::Frame{ obj, task, 0, 0, pc, min_sym };
  } else {
    return sym::Frame{ obj, task, 0, 0, pc, nullptr };
  }
}

sym::UnwinderSymbolFilePair
TraceeController::GetUnwinderUsingPc(AddrPtr pc) noexcept
{
  for (auto &symbolFile : mSymbolFiles) {
    const auto u = symbolFile->GetObjectFile()->GetUnwinder();
    if (pc > symbolFile->mBaseAddress) {
      const auto unrelocated = symbolFile->UnrelocateAddress(pc);
      if (u->mAddressRange.Contains(unrelocated)) {
        return sym::UnwinderSymbolFilePair{ u, symbolFile.get() };
      }
    }
  }
  return sym::UnwinderSymbolFilePair{ mNullUnwinder, nullptr };
}

void
TraceeController::CacheRegistersFor(TaskInfo &t, bool forceRefresh) noexcept
{
  if (t.mRegisterCacheDirty || forceRefresh) {
    const auto result = mTraceeInterface->ReadRegisters(t);
    MDB_ASSERT(result.is_ok(), "Failed to read register file for {}; {}", t.mTid, strerror(result.sys_errno));
    t.mRegisterCacheDirty = false;
    t.mInstructionPointerDirty = false;
  }
}

mdb::tc::TraceeCommandInterface &
TraceeController::GetInterface() noexcept
{
  return *mTraceeInterface;
}

void
TraceeController::ExitAll() noexcept
{
  while (!mThreads.empty()) {
    TaskExit(*mThreads[0].mTask, false);
  }
}

void
TraceeController::TaskExit(TaskInfo &task, bool notify) noexcept
{
  Tid tid = task.mTid;
  auto it = FindByTid(mThreads, tid);
  MDB_ASSERT(it != std::end(mThreads), "{} couldn't be found in this process {}", tid, mTaskLeader);

  task.exited = true;

  mExitedThreads.push_back(std::move(*it));
  mThreads.erase(it);

  if (notify) {
    mDebugAdapterClient->PostDapEvent(new ui::dap::ThreadEvent{ mTaskLeader, ui::dap::ThreadReason::Exited, tid });
  }
}

sym::CallStack &
TraceeController::BuildCallFrameStack(TaskInfo &task, CallStackRequest req) noexcept
{
  PROFILE_SCOPE("TraceeController::BuildCallFrameStack", "stacktrace");
  DBGLOG(core, "stacktrace for {}", task.mTid);
  if (!task.mTaskCallstack->IsDirty() && (req.req == CallStackRequest::Type::Full ||
                                           (req.req == CallStackRequest::Type::Partial &&
                                             task.mTaskCallstack->FramesCount() == static_cast<u32>(req.count)))) {
    return *task.mTaskCallstack;
  }
  CacheRegistersFor(task);
  auto &callStack = *task.mTaskCallstack;
  PROFILE_BEGIN("Unwind return addresses", "stacktrace");
  auto frameProgramCounters = task.UnwindReturnAddresses(this, req);
  PROFILE_END_ARGS("Unwind return addresses", "stacktrace", PEARG("pcs", frameProgramCounters));
  for (const auto &[depth, i] : mdb::EnumerateView{ frameProgramCounters }) {
    auto framePc = i.AsVoid();
    auto result = FindFunctionByPc(framePc);
    if (!result) {
      DBGLOG(core, "No object file related to pc; abort call frame state building.");
      break;
    }
    auto &[symbol, obj] = result.value();
    const auto id = Tracer::Get().NewVariablesReference();
    Tracer::Get().SetVariableContext(std::make_shared<VariableContext>(&task, obj, id, id, ContextType::Frame));
    if (symbol) {
      callStack.PushFrame(obj, task, depth, id, i.AsVoid(), symbol);
    } else {
      auto obj = FindObjectByPc(framePc);
      auto minimalSymbols = obj->SearchMinimalSymbolFunctionInfo(framePc);
      if (minimalSymbols) {
        callStack.PushFrame(obj, task, depth, id, i.AsVoid(), minimalSymbols);
      } else {
        DBGLOG(core, "[stackframe]: WARNING, no frame info for pc {}", i.AsVoid());
        callStack.PushFrame(obj, task, depth, id, i.AsVoid(), nullptr);
      }
    }
  }
  return callStack;
}

SymbolFile *
TraceeController::FindObjectByPc(AddrPtr addr) noexcept
{
  return mdb::find_if(
    mSymbolFiles, [addr](auto &symbol_file) { return symbol_file->ContainsProgramCounter(addr); })
    .transform([](auto iterator) { return iterator->get(); })
    .value_or(nullptr);
}

std::optional<std::pair<sym::FunctionSymbol *, NonNullPtr<SymbolFile>>>
TraceeController::FindFunctionByPc(AddrPtr addr) noexcept
{
  PROFILE_BEGIN("TraceeController::FindFunctionByPc", "supervisor");
  const auto symbolFile = FindObjectByPc(addr);
  if (symbolFile == nullptr) {
    return std::nullopt;
  }

  auto matchingCompilationUnits = symbolFile->GetUnitDataFromProgramCounter(addr);

  // TODO(simon): Massive room for optimization here. Make get_cus_from_pc return source units directly
  //  or, just make them searchable by cu (via some hashed lookup in a map or something.)
  sym::FunctionSymbol *foundFn = nullptr;
  PROFILE_AT_SCOPE_END("TraceeController::FindFunctionByPc",
    "supervisor",
    PEARG("cu_count", matchingCompilationUnits.size()),
    PEARG("unreloc_addr", symbolFile->UnrelocateAddress(addr)),
    PEARG("found_fn", foundFn ? foundFn->name : "not found"));

  using sym::CompilationUnit;

  std::vector<sym::CompilationUnit *> alreadyParse;
  std::vector<sym::CompilationUnit *> sortedCompUnits;

  alreadyParse.reserve(matchingCompilationUnits.size());
  sortedCompUnits.reserve(matchingCompilationUnits.size());
  for (auto src : matchingCompilationUnits) {
    if (src->IsFunctionSymbolsResolved()) {
      if (auto fn = src->GetFunctionSymbolByProgramCounter(symbolFile->UnrelocateAddress(addr)); fn) {
        foundFn = fn;
        return std::make_pair(fn, NonNull(*symbolFile));
      }
    } else {
      sortedCompUnits.push_back(src);
    }
  }

  std::sort(sortedCompUnits.begin(), sortedCompUnits.end(), [](CompilationUnit *a, CompilationUnit *b) {
    return a->GetDwarfUnitData()->UnitSize() > b->GetDwarfUnitData()->UnitSize();
  });

  for (const auto cu : sortedCompUnits) {
    if (auto fn = cu->GetFunctionSymbolByProgramCounter(symbolFile->UnrelocateAddress(addr)); fn) {
      foundFn = fn;
      return std::make_pair(fn, NonNull(*symbolFile));
    }
  }

  return std::make_pair(nullptr, NonNull(*symbolFile));
}

mdb::Expected<u8, BreakpointError>
TraceeController::InstallSoftwareBreakpointLocation(Tid tid, AddrPtr addr) noexcept
{
  const auto res = mTraceeInterface->InstallBreakpoint(tid, addr);
  if (!res.is_ok()) {
    DBGLOG(core, "[{}:bkpt:loc]: error while installing location: {}", mTaskLeader, addr);
    return mdb::unexpected(BreakpointError{ MemoryError{ errno, addr } });
  }
  DBGLOG(core,
    "[{}:bkpt:loc]: installing location: {}, original byte: 0x{:x}",
    mTaskLeader,
    addr,
    static_cast<u8>(res.data));
  return static_cast<u8>(res.data);
}

Publisher<void> &
TraceeController::GetPublisher(ObserverType type) noexcept
{
  switch (type) {
  case ObserverType::AllStop:
    return mAllStopPublisher;
  }
  MIDAS_UNREACHABLE
}

void
TraceeController::EmitAllStopped() noexcept
{
  DBGLOG(core, "[all-stopped]: sending registered notifications");
  // all_stopped_observer.send_notifications();
  mAllStopPublisher.Emit();
}

bool
TraceeController::IsAllStopped() const noexcept
{
  for (const auto &entry : mThreads) {
    if (!entry.mTask->IsStopProcessed()) {
      return false;
    }
  }
  return true;
}

bool
TraceeController::IsSessionAllStopMode() const noexcept
{
  switch (mInterfaceType) {
  case InterfaceType::Ptrace:
    return false;
  case InterfaceType::GdbRemote:
    return !static_cast<tc::GdbRemoteCommander *>(mTraceeInterface.get())->remote_settings().mIsNonStop;
  }
  NEVER("Unknown target interface type");
}

TaskInfo *
TraceeController::SetPendingWaitstatus(WaitPidResult waitResult) noexcept
{
  const auto tid = waitResult.tid;
  auto task = GetTaskByTid(tid);
  MDB_ASSERT(task != nullptr, "couldn't find task {}", tid);
  task->mLastWaitStatus = waitResult.ws;
  task->mTracerVisibleStop = true;
  task->mHasProcessedStop = false;
  return task;
}

tc::ProcessedStopEvent
TraceeController::HandleTerminatedBySignal(const Signal &evt) noexcept
{
  // TODO: Allow signals through / stop process / etc. Allow for configurability here.
  mDebugAdapterClient->PostDapEvent(new ui::dap::ExitedEvent{ mTaskLeader, evt.mTerminatingSignal });
  ShutDownDebugAdapterClient();
  mIsExited = true;
  return tc::ProcessedStopEvent{ false };
}

tc::ProcessedStopEvent
TraceeController::HandleStepped(TaskInfo *task, const Stepped &event) noexcept
{
  if (event.mStop) {
    EmitStepNotification({ .pid = mTaskLeader, .tid = task->mTid });
    return tc::ProcessedStopEvent{ false };
  } else {
    if (task->mBreakpointLocationStatus.mSteppingOverState.mIsSteppingOver) {
      task->mBreakpointLocationStatus.mBreakpointLocation->Enable(task->mTid, GetInterface());
      task->ClearBreakpointLocStatus();
    }
    return tc::ProcessedStopEvent{ true, event.mResumeWhenDone };
  }
}

tc::ProcessedStopEvent
TraceeController::HandleEntry(const EntryEvent &event) noexcept
{
  SetIsOnEntry(false);
  // apply session breakpoints to new process space
  if (event.mShouldStop) {
    // emit stop event
    EmitStopped(event.mThreadId, ui::dap::StoppedReason::Entry, "forked", true, {});
  } else {
    // say "thread created / started"
  }
  return tc::ProcessedStopEvent{ !event.mShouldStop, {} };
}

tc::ProcessedStopEvent
TraceeController::HandleThreadCreated(
  TaskInfo *task, const ThreadCreated &e, const RegisterData &registerData) noexcept
{
  // means this event was produced by a Remote session. Construct the task now
  if (!task) {
    CreateNewTask(e.mThreadId, true);
    task = GetTaskByTid(e.mThreadId);
    if (!registerData.empty()) {
      MDB_ASSERT(*GetInterface().mArchInfo != nullptr,
        "Passing raw register contents with no architecture description doesn't work.");
      task->StoreToRegisterCache(registerData);
      for (const auto &p : registerData) {
        if (p.first == 16) {
          task->mInstructionPointerDirty = false;
        }
      }
    }
  }

  const auto evt = new ui::dap::ThreadEvent{ mTaskLeader, ui::dap::ThreadReason::Started, e.mThreadId };
  mDebugAdapterClient->PostDapEvent(evt);

  return tc::ProcessedStopEvent{ true, e.mResumeAction };
}

bool
TraceeController::OneRemainingTask() noexcept
{
  // TODO: This (potentially) needs to check currently uninitialized tasks, if they belong to this process space
  //  otherwise this may return untrue values. Therefore this simple check is lifted into it's own method.
  return mThreads.size() == 1;
}

tc::ProcessedStopEvent
TraceeController::HandleBreakpointHit(TaskInfo *task, const BreakpointHitEvent &event) noexcept
{
  VERIFY(task, "Task must be non nullptr");
  auto breakpointAddress = event.mAddress
                             ->or_else([&]() {
                               // Remember: A breakpoint (0xcc) is 1 byte. We need to rewind that 1 byte.
                               return std::optional{ CacheAndGetPcFor(*task).GetRaw() };
                             })
                             .value();

  auto breakpointLocation = GetUserBreakpoints().GetLocationAt(breakpointAddress);
  VERIFY(breakpointLocation != nullptr, "Expected breakpoint location at 0x{:x}", breakpointAddress);
  task->AddBreakpointLocationStatus(breakpointLocation);
  const auto users = breakpointLocation->GetUserIds();
  VERIFY(!breakpointLocation->GetUserIds().empty(),
    "[task={}]: A breakpoint location with no user is a rogue/leaked breakpoint at 0x{:x}",
    task->mTid,
    breakpointAddress);

  bool shouldResume = true;
  for (const auto bpId : users) {
    auto user = GetUserBreakpoints().GetUserBreakpoint(bpId);
    auto breakpointResult = user->OnHit(*this, *task);
    shouldResume = shouldResume && !breakpointResult.ShouldStop();
    if (breakpointResult.ShouldRetire()) {
      GetUserBreakpoints().RemoveUserBreakpoint(user->mId);
    }
  }

  return tc::ProcessedStopEvent{ shouldResume, {} };
}

tc::ProcessedStopEvent
TraceeController::HandleThreadExited(TaskInfo *task, const ThreadExited &evt) noexcept
{
  if (OneRemainingTask()) {
    TaskExit(*task, true);
    return HandleProcessExit(ProcessExited{ .mProcessId = mTaskLeader, .mExitCode = evt.mCodeOrSignal });
  }

  TaskExit(*task, true);
  return tc::ProcessedStopEvent{ false, {}, false, true };
}

static void
ScheduleInvalidateThis(TraceeController *t)
{
  EventSystem::Get().PushInternalEvent(InvalidateSupervisor{ t });
}

tc::ProcessedStopEvent
TraceeController::HandleProcessExit(const ProcessExited &evt) noexcept
{
  auto t = GetTaskByTid(evt.mThreadId);
  if (t && !t->exited) {
    mDebugAdapterClient->PostDapEvent(
      new ui::dap::ThreadEvent{ mTaskLeader, ui::dap::ThreadReason::Exited, t->mTid });
    t->exited = true;
    t->reaped = true;
  }

  ScheduleInvalidateThis(this);
  mDebugAdapterClient->PostDapEvent(new ui::dap::ExitedEvent{ mTaskLeader, evt.mExitCode });
  return tc::ProcessedStopEvent::ProcessExited();
}

void
TraceeController::PostExec(const std::string &exe) noexcept
{
  DBGLOG(core, "Processing EXEC for {} - process was vforked: {}", mTaskLeader, bool{ mIsVForking });
  if (mMainExecutable) {
    mMainExecutable = nullptr;
  }
  mSymbolFiles.clear();

  auto t = GetTaskByTid(TaskLeaderTid());
  CacheRegistersFor(*t);
  mUserBreakpoints.OnExec();

  if (mTraceeInterface->mType == tc::TraceeInterfaceType::Ptrace) {
    mTraceeInterface->OnExec();
  }

  auto auxVectorResult = mTraceeInterface->ReadAuxiliaryVector().expected("Failed to read auxv");
  const auto parsedAux = ParsedAuxiliaryVectorData(auxVectorResult);
  SetAuxiliaryVector(parsedAux);

  std::vector<u8> programHeaderContents{};
  programHeaderContents.resize(parsedAux.mProgramHeaderEntrySize * parsedAux.mProgramHeaderCount, 0);
  const auto readResult = mTraceeInterface->ReadBytes(
    parsedAux.mProgramHeaderPointer, programHeaderContents.size(), programHeaderContents.data());
  MDB_ASSERT(readResult.WasSuccessful(), "Failed to read program headers");

  Elf64_Phdr *cast = (Elf64_Phdr *)programHeaderContents.data();
  AddrPtr baseAddress = nullptr;
  for (auto i = 0u; i < parsedAux.mProgramHeaderCount; ++i) {
    if ((cast + i)->p_type == PT_PHDR) {
      baseAddress = parsedAux.mProgramHeaderPointer - (cast + i)->p_offset;
      DBGLOG(core, "Found base address in program header data in loaded binary: {}", baseAddress);
    }
  }

  if (auto symbol_obj = Tracer::Get().LookupSymbolfile(exe); symbol_obj == nullptr) {
    auto obj = ObjectFile::CreateObjectFile(this, exe);
    if (obj->GetElf()->AddressesNeedsRelocation()) {
      RegisterObjectFile(this, std::move(obj), true, baseAddress);
    } else {
      RegisterObjectFile(this, std::move(obj), true, nullptr);
    }
  } else {
    RegisterSymbolFile(symbol_obj, true);
  }

  mTraceeInterface->tracee_r_debug = InstallDynamicLoaderBreakpoints();
  DoBreakpointsUpdate({ mMainExecutable });
  mOnExecOrExitPublisher.Emit();
}

void
TraceeController::DefaultHandler(TraceEvent *evt) noexcept
{
  // todo(simon): I'm more and more leaning into making remote | local debug sessions _completely_ separate,
  // instead of this "unified behind one interface approach". Due to gdb's remote protocol design it just doesn't
  // lend itself well to that, unfortunately. In a better world, with a better protocol (one that actually just
  // mimicks what we have using ptrace) this would be *massively* simpler.

  // todo(simon): open up for design that involves user-subscribed event handlers (once we get scripting up and
  // running) It is in this event handling, where we can (at the very end of each handler) emit additional "user
  // facing events", that we also can collect values from (perhaps the user wants to stop for a reason, as such
  // their subscribed event handlers will return `false`).
  using tc::ProcessedStopEvent;

  MDB_ASSERT(!mIsExited, "Supervisor exited already.");

  const auto arch = GetInterface().mArchInfo;
  auto task = evt->mTask;

  // we _have_ to do this check here, because the event *might* be a ThreadCreated event
  // and *it* happens *slightly* different depending on if it's a Remote or a Native session that sends it.
  // Unfortunately.
  if (!task && !mIsExited) {
    // rr ends up here.
    DBGLOG(core, "task {} created in stop handler because target doesn't support thread events", evt->mTaskId);
    evt->mTask = task = GetOrCreateNewTask(evt->mTaskId, false);
  }
  MDB_ASSERT(task, "no task when handling a task event?");
  task->mLastWaitStatus.signal = evt->uSignal;
  if (!evt->mRegisterData.empty()) {
    MDB_ASSERT(*arch != nullptr, "Passing raw register contents with no architecture description doesn't work.");
    task->StoreToRegisterCache(evt->mRegisterData);
    for (const auto &p : evt->mRegisterData) {
      if (p.first == 16) {
        task->mInstructionPointerDirty = false;
      }
    }
  }
  task->CollectStop();
  task->SetValueLiveness(Tracer::Get().GetCurrentVariableReferenceBoundary());
  if (IsSessionAllStopMode()) {
    for (const auto &entry : GetThreads()) {
      entry.mTask->SetUserVisibleStop();
      entry.mTask->mHasProcessedStop = true;
    }
  }

  ProcessedStopEvent processedStop =
    std::visit(Match{
                 [&](const WatchpointEvent &e) noexcept {
                   (void)e;
                   TODO("WatchpointEvent");
                   return ProcessedStopEvent::ResumeAny();
                 },
                 [&](const SyscallEvent &e) noexcept {
                   (void)e;
                   TODO("SyscallEvent");
                   return ProcessedStopEvent::ResumeAny();
                 },
                 [&](const ThreadCreated &e) noexcept { return HandleThreadCreated(task, e, evt->mRegisterData); },
                 [&](const ThreadExited &e) noexcept { return HandleThreadExited(task, e); },
                 [&](const BreakpointHitEvent &e) noexcept { return HandleBreakpointHit(task, e); },
                 [&](const ForkEvent &e) noexcept { return HandleFork(e); },
                 [&](const Clone &e) noexcept { return HandleClone(e); },
                 [&](const Exec &e) noexcept { return HandleExec(e); },
                 [&](const ProcessExited &e) noexcept { return HandleProcessExit(e); },
                 [&](const LibraryEvent &e) noexcept {
                   (void)e;
                   TODO("LibraryEvent");
                   return ProcessedStopEvent{ true, {} };
                 },
                 [&](const Signal &e) noexcept { return HandleTerminatedBySignal(e); },
                 [&](const Stepped &e) noexcept { return HandleStepped(task, e); },
                 [&](const EntryEvent &e) noexcept { return HandleEntry(e); },
                 [&](const DeferToSupervisor &e) noexcept {
                   // And if there is no Proceed action installed, default action is taken (RESUME)
                   return ProcessedStopEvent{ true && !e.mAttached, {} };
                 },
               },
      evt->mEvent);

  // Now that event has been properly handled, we can check for "global" (process-local) handlers
  // for instance, if we've requested all tasks to stop, or if we've requested a shut down, we will treat all
  // proceeds the same. effectively ignoring the default proceed behaviors from an event.

  DBGLOG(core,
    "[{}.{}]: handle {}, resume:{}, post breakpoint-stepover: {}",
    mTaskLeader,
    task->mTid,
    evt->mEventType,
    processedStop.mShouldResumeAfterProcessing,
    evt->mPostBreakpointOverStep.has_value());

  if (evt->mPostBreakpointOverStep && processedStop.mShouldResumeAfterProcessing) {
    const auto type = evt->mPostBreakpointOverStep.value();
    switch (type) {
    case tc::RunType::Unknown:
      break;
    case tc::RunType::Step:
    case tc::RunType::Continue:
    case tc::RunType::SyscallContinue:
      if (processedStop.mResumeAction) {
        processedStop.mResumeAction->mResumeType = type;
      } else {
        processedStop.mResumeAction = tc::ResumeAction{ type };
      }
    }
  }

  mScheduler->Schedule(*task, processedStop);
}

void
TraceeController::PopHandlerStack(bool consumePotentiallyDeferred) noexcept
{
  mEventHandlerStack.Pop();
  if (consumePotentiallyDeferred) {
    EventSystem::Get().ConsumeDebuggerEvents(mDeferredEvents);
  }
}

void
TraceeController::InvalidateThreads([[maybe_unused]] int eventTime) noexcept
{
  DBGLOG(core, "implement handling of reverse-execution across thread/process births");
}

void
TraceeController::HandleTracerEvent(TraceEvent *evt) noexcept
{
  if (evt->mEventTime != -1 && (evt->mEventTime < mCurrentEventTime)) {
    InvalidateThreads(evt->mEventTime);
  }
  mCurrentEventTime = std::max<int>(0, evt->mEventTime);
  const auto eventState = mEventHandlerStack.ProcessEvent(*evt);
  switch (eventState) {
  case EventState::Unhandled:
    DefaultHandler(evt);
    [[fallthrough]];
  case EventState::Handled:
    DBGLOG(core, "Supervisor event handled");
    delete evt;
    break;
  case EventState::Defer:
    mDeferredEvents.push_back(evt);
    break;
  }
}

void
TraceeController::OnTearDown() noexcept
{
  mUserBreakpoints.OnProcessExit();
  mOnExecOrExitPublisher.Emit();
  GetInterface().PerformShutdown();
  ShutDownDebugAdapterClient();
}

bool
TraceeController::IsReplaySession() const noexcept
{
  return mTraceeInterface->IsReplaySession();
}

tc::ProcessedStopEvent
TraceeController::HandleFork(const ForkEvent &evt) noexcept
{
  auto interface = mTraceeInterface->OnFork(evt.mChildPid);
  auto newSupervisor = Tracer::Get().AddNewSupervisor(Fork(std::move(interface), evt.mIsVFork));
  auto clientName = std::format("forked {}", newSupervisor->TaskLeaderTid());
  mDebugAdapterClient->AddSupervisor(newSupervisor);

  bool resume = true;
  if (!evt.mIsVFork) {
    resume = newSupervisor->GetInterface().PostFork(this);
    mDebugAdapterClient->PostDapEvent(new ui::dap::Process{ mTaskLeader, evt.mChildPid, "forked", true });
  } else {
    mEventHandlerStack.PushEventHandler([](const auto &) { return EventState::Defer; });
    newSupervisor->mIsVForking = true;
    newSupervisor->mOnExecOrExitPublisher.Once(
      [parent = this, self = newSupervisor, resumeTid = evt.mThreadId, newPid = evt.mChildPid]() {
        parent->PopHandlerStack(true);
        self->mIsVForking = false;
        self->mConfigurationIsDone = true;

        auto *traceEvent = new TraceEvent{};
        TraceEvent::InitDeferToSupervisor(traceEvent,
          { .target = parent->TaskLeaderTid(), .tid = resumeTid, .sig_or_code = 0, .event_time = {} },
          {},
          {});
        EventSystem::Get().PushDebuggerEvent(traceEvent);
        parent->mDebugAdapterClient->PostDapEvent(
          new ui::dap::Process{ parent->mTaskLeader, newPid, "forked", true });
      });
  }
  const bool should_resume = !evt.mIsVFork && resume;
  return tc::ProcessedStopEvent{
    .mShouldResumeAfterProcessing = should_resume, .mResumeAction = {}, .mVForked = evt.mIsVFork
  };
}

tc::ProcessedStopEvent
TraceeController::HandleClone(const Clone &evt) noexcept
{
  auto task = Tracer::Get().TakeUninitializedTask(evt.mChildTid);
  DBGLOG(core,
    "Running clone handler for {}: child created = {}. Already created: {}",
    evt.mThreadId,
    evt.mChildTid,
    task != nullptr);
  if (!task) {
    CreateNewTask(evt.mChildTid, true);
    if (evt.mTaskStackMetadata) {
      SetTaskVmInfo(evt.mChildTid, evt.mTaskStackMetadata.value());
    }
  } else {
    task->InitializeThread(GetInterface(), true);
    AddTask(std::move(task));
  }
  mDebugAdapterClient->PostDapEvent(new ui::dap::ThreadEvent{ mTaskLeader, evt });
  return tc::ProcessedStopEvent{ true, {} };
}

tc::ProcessedStopEvent
TraceeController::HandleExec(const Exec &evt) noexcept
{
  // configurationDone will resume us if we're vforking
  PostExec(evt.mExecFile);
  mDebugAdapterClient->PostDapEvent(new ui::dap::CustomEvent{ mTaskLeader,
    "setProcessName",
    std::format(R"({{ "name": "{}", "processId": {} }})", evt.mExecFile, mTaskLeader) });
  return tc::ProcessedStopEvent{ true, {} };
}

ui::dap::DebugAdapterClient *
TraceeController::GetDebugAdapterProtocolClient() const noexcept
{
  return mDebugAdapterClient;
}

void
TraceeController::ShutDownDebugAdapterClient() noexcept
{
  if (mDebugAdapterClient) {
    mDebugAdapterClient->PostDapEvent(new ui::dap::TerminatedEvent{
      mTaskLeader,
    });
    mDebugAdapterClient->RemoveSupervisor(this);
    mDebugAdapterClient = nullptr;
  }
}
} // namespace mdb