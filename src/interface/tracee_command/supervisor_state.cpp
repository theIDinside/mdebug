/** LICENSE TEMPLATE */
#include "supervisor_state.h"
#include "bp.h"
#include "utils/util.h"

// mdb
#include <common.h>
#include <interface/dap/events.h>
#include <interface/dap/interface.h>
#include <link.h>
#include <session_task_map.h>
#include <string>
#include <symbolication/callstack.h>
#include <symbolication/dwarf/die.h>
#include <symbolication/dwarf_binary_reader.h>
#include <symbolication/dwarf_frameunwinder.h>
#include <task.h>
#include <utils/enumerator.h>

// std
#include <algorithm>

namespace mdb {
ParsedAuxiliaryVector
ParsedAuxiliaryVectorData(const Auxv &aux, ParseAuxiliaryOptions options) noexcept
{
  ParsedAuxiliaryVector result;
  ParseAuxiliaryOptions found;
  for (const auto [id, value] : aux.mContents) {
    switch (id) {
    case AT_PHDR:
      result.mProgramHeaderPointer = value;
      break;
    case AT_PHENT:
      result.mProgramHeaderEntrySize = value;
      break;
    case AT_PHNUM:
      result.mProgramHeaderCount = value;
      break;
    case AT_BASE:
      result.mInterpreterBaseAddress = value;
      found.requiresInterpreterBase = true;
      break;
    case AT_ENTRY:
      result.mEntry = value;
      found.requireEntry = true;
      break;
    }
  }

  DBGLOG(core,
    "Auxiliary Vector: {{ interpreter: {}, program entry: {}, program headers: {} }}",
    result.mInterpreterBaseAddress,
    result.mEntry,
    result.mProgramHeaderPointer);

  if (options.requiresInterpreterBase) {
    VERIFY(found.requiresInterpreterBase, "Could not find interpreter base in aux vector");
  }

  if (options.requireEntry) {
    VERIFY(found.requireEntry, "Could not find entry address in aux vector");
  }

  return result;
}
} // namespace mdb

namespace mdb::tc {

/// Creates a `SymbolFile` using either an existing `ObjectFile` as storage or constructing a new one.
/// When debugging 2 processes with the same binaries, we don't want duplicate storage.
static auto
CreateSymbolFile(SupervisorState &supervisorState, const Path &path, AddrPtr addr) noexcept
  -> std::shared_ptr<SymbolFile>
{
  auto existingObjFile = Tracer::Get().LookupSymbolfile(path);
  if (existingObjFile) {
    // This process already registered this symbol object.
    if (existingObjFile->GetSupervisor() == &supervisorState) {
      return nullptr;
    }
    // if baseAddr == addr; unique = false, return null, because we've already registered it
    return existingObjFile->Copy(supervisorState, addr);
  } else {
    auto obj = ObjectFile::CreateObjectFile(&supervisorState, path);
    if (obj != nullptr) {
      return SymbolFile::Create(&supervisorState, std::move(obj), addr);
    }
  }
  return nullptr;
}

static Path
InterpreterPath(const Elf *elf, const ElfSection *interp) noexcept
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

SupervisorState::SupervisorState(
  SupervisorType type, Tid taskLeader, ui::dap::DebugAdapterManager *client) noexcept
    : mSessionId(-1), mTaskLeader(taskLeader), mDebugAdapterClient(client), mUserBreakpoints(*this),
      mScheduler{ std::make_unique<TaskScheduler>(this) }, mNullUnwinder{ new sym::Unwinder{ nullptr } },
      mSupervisorType(type)
{
  mNewObjectFilePublisher.Subscribe(SubscriberIdentity::Of(this), [this](const SymbolFile *sf) {
    mDebugAdapterClient->PostDapEvent(new ui::dap::ModuleEvent{ mSessionId, "new", *sf });
  });
}

sym::Unwinder *
SupervisorState::GetNullUnwinder() const noexcept
{
  return mNullUnwinder;
}

void
SupervisorState::OnForkFrom(const SupervisorState &parent) noexcept
{
  mParentPid = parent.mTaskLeader;
  CopyTo(parent.mSymbolFiles, mSymbolFiles);
  std::string threadName = "forked";
  CreateNewTask(mTaskLeader, threadName, false);
}

void
SupervisorState::SetParent(Pid parentPid) noexcept
{
  mParentPid = parentPid;
}

void
SupervisorState::SetTaskLeader(Tid taskLeaderTid) noexcept
{
  mTaskLeader = taskLeaderTid;
}

void
SupervisorState::SetSessionId(SessionId sessionId) noexcept
{
  MDB_ASSERT(mSessionId == -1, "Expected sessionId to not be set!");
  mSessionId = sessionId;
}

Publisher<void> &
SupervisorState::GetOnExecOrExitPublisher() noexcept
{
  return mOnExecOrExitPublisher;
}

std::span<std::shared_ptr<SymbolFile>>
SupervisorState::GetSymbolFiles() noexcept
{
  return mSymbolFiles;
}

std::shared_ptr<SymbolFile>
SupervisorState::LookupSymbolFile(const Path &path) noexcept
{
  for (const auto &s : mSymbolFiles) {
    if (s->GetObjectFile()->IsFile(path)) {
      return s;
    }
  }
  return nullptr;
}

AddrPtr
SupervisorState::EntryAddress() const noexcept
{
  return mParsedAuxiliaryVector.mEntry;
}

void
SupervisorState::InstallDynamicLoaderBreakpoints(AddrPtr mappedDynamicSectionAddress) noexcept
{
  MDB_ASSERT(mMainExecutable != nullptr, "No main executable for this target");
  const auto mainExecutableElf = mMainExecutable->GetObjectFile()->GetElf();
  const Path interpreterPath = InterpreterPath(mainExecutableElf, mainExecutableElf->GetSection(".interp"));
  const std::shared_ptr tempObjectFile = ObjectFile::CreateObjectFile(this, interpreterPath);
  MDB_ASSERT(tempObjectFile != nullptr, "Failed to mmap the loader binary");

  const auto interpreterBase = mParsedAuxiliaryVector.mInterpreterBaseAddress;

  auto dlDebugStateSymbol = tempObjectFile->FindMinimalFunctionSymbol("_dl_debug_state", true);
  MDB_ASSERT(dlDebugStateSymbol.has_value(), "Did not find _dl_debug_state");
  AddrPtr dlDebugState = dlDebugStateSymbol->address + interpreterBase;

  auto user = UserBreakpoint::Create<InternalBreakpoint>(
    RequiredUserParameters{ .mTaskId = mTaskLeader,
      .mBreakpointId = mUserBreakpoints.NewBreakpointId(),
      .mBreakpointLocationResult = GetOrCreateBreakpointLocation(dlDebugState),
      .mTimesToHit = {},
      .mControl = *this },
    std::string_view{ "Initialize debug state" },
    [this, mappedDynamicSectionAddress]() {
      auto sect = mMainExecutable->GetObjectFile()->GetElf()->GetSection(ElfSec::Dynamic);
      MDB_ASSERT(sect, "Could not find .dynamic section");
      // TODO: Start supporting 32 bits
      auto count = sect->GetDataAs<Elf64_Dyn>().size();
      std::vector<Elf64_Dyn> mappedEntries{ count };
      // slow read. who cares. but change to something better when there's literally nothing else to do.
      const auto bytesRead = ReadIntoVector(mappedDynamicSectionAddress, count, mappedEntries);
      for (const auto &entry : mappedEntries) {
        if (entry.d_tag == DT_DEBUG) {
          auto rDebug = ReadType(TPtr<r_debug>{ entry.d_un.d_val });
          SetLinkerDebugData(rDebug.r_version, entry.d_un.d_val);
          mUserBreakpoints.CreateBreakpointLocationUser<SOLoadingBreakpoint>(
            *this, GetOrCreateBreakpointLocation(rDebug.r_brk), mTaskLeader);

          break;
        }
      }
      // Let's run a check to see if we can parse any symbols right now. Normally we shouldn't, but let's not miss
      // if that ever changes.
      OnSharedObjectEvent();
      return BreakpointHitEventResult{ .mRetireBreakpoint = BreakpointOp::Retire };
    });
  mUserBreakpoints.AddUser(user);
}

void
SupervisorState::ConfigureBreakpointBehavior(BreakpointBehavior behavior) noexcept
{
  mBreakpointBehavior = behavior;
}

void
SupervisorState::SetLinkerDebugData(int version, AddrPtr rDebugAddr)
{
  mLinkerDebugData = LinkerLoaderDebug{ .mVersion = version, .mRDebug = rDebugAddr.As<r_debug>() };
}

void
SupervisorState::TearDown(bool killProcess) noexcept
{
  DBGLOG(core,
    "Tear down traced process space {} - unclear if this method is needed. Kill={}",
    mTaskLeader,
    killProcess);
  mIsExited = true;
  mUserBreakpoints.OnProcessExit();
}

bool
SupervisorState::IsExited() const noexcept
{
  return mIsExited;
}

bool
SupervisorState::IsDisconnected() const noexcept
{
  return mIsDisconnected;
}

void
SupervisorState::ConfigureDapClient(ui::dap::DebugAdapterManager *client) noexcept
{
  mDebugAdapterClient = client;
}

void
SupervisorState::Disconnect(bool terminate) noexcept
{
  StopAllTasks();

  if (terminate) {
    DoDisconnect(true);
    return;
  }

  for (auto &user : mUserBreakpoints.AllUserBreakpoints()) {
    mUserBreakpoints.RemoveUserBreakpoint(user->mId);
  }

  auto ok = DoDisconnect(false);
  mIsExited = terminate;
  mIsDisconnected = true;

  Tracer::Get().OnDisconnectOrExit(this);

  VERIFY(ok.is_ok(), "Failed to disconnect: {}", strerror(ok.sys_errno));
}

void
SupervisorState::OnTearDown() noexcept
{
  mUserBreakpoints.OnProcessExit();
  mOnExecOrExitPublisher.Emit();
  PerformShutdown();
  ShutDownDebugAdapterClient();
}

TaskInfo *
SupervisorState::GetTaskByTid(pid_t pid) noexcept
{
  const auto findTask = [tid = pid](const auto &threads) -> TaskInfo * {
    for (const TaskInfoEntry &taskEntry : threads) {
      if (taskEntry.mTid == tid) {
        return taskEntry.mTask;
      }
    }
    return nullptr;
  };

  if (auto task = findTask(mThreads)) {
    return task;
  }

  return findTask(mExitedThreads);
}

void
SupervisorState::CreateNewTask(Tid tid, std::optional<std::string_view> name, bool running) noexcept
{
  MDB_ASSERT(tid != 0 && !HasTask(tid), "Task {} has already been created!", tid);
  auto task = TaskInfo::CreateTask(*this, tid);
  task->SetName(name.value_or(std::to_string(tid)));
  InitRegisterCacheFor(*task);
  mThreads.push_back({ task->mTid, task });
  Tracer::GetSessionTaskMap().Add(tid, task);
}

bool
SupervisorState::HasTask(Tid tid) noexcept
{
  for (const auto &taskEntry : mThreads) {
    if (taskEntry.mTid == tid) {
      return true;
    }
  }

  for (const auto &taskEntry : mExitedThreads) {
    if (taskEntry.mTid == tid) {
      return true;
    }
  }

  return false;
}

bool
SupervisorState::ResumeTarget(tc::RunType resumeType, std::vector<Tid> *resumedThreads) noexcept
{
  DBGLOG(core, "[supervisor]: resume tracee {}", resumeType);
  mScheduler->SetNormalScheduling();
  return DoResumeTarget(resumeType);
}

void
SupervisorState::ResumeTask(TaskInfo &task, tc::RunType type) noexcept
{
  task.mHasStarted = true;

  mScheduler->SetNormalScheduling();
  task.SetResumeType(type);

  if (task.mBreakpointLocationStatus.IsValid()) {
    task.StepOverBreakpoint();
  } else {
    DoResumeTask(task, type);
  }
}

void
SupervisorState::StopAllTasks(std::function<void()> &&callback) noexcept
{
  mAllStopPublisher.Once(std::move(callback));
  StopAllTasks();
}

void
SupervisorState::ScheduleResume(TaskInfo &task, tc::RunType type) noexcept
{
  mScheduler->Schedule(task, { true, type });
}

void
SupervisorState::StopAllTasks() noexcept
{
  DBGBUFLOG(control, "Stopping all threads")
  // If all threads were at a signal-delivery stop, then we will not receive new wait status events
  // and we will never report to the user that everyone has stopped. We need to track that, and possibly emit a
  // stopped event immediately.
  mScheduler->SetStopAllScheduling();
  for (auto &entry : mThreads) {
    auto &t = *entry.mTask;
    if (t.mTraceeState == TraceeState::Running) {
      DBGBUFLOG(control, "thread {} is init={}", t.mTid, bool{ t.mHasStarted });
      const auto response = StopTask(t);
    }
    t.RequestedStop();
  }

  if (IsAllStopped()) {
    mAllStopPublisher.Emit();
  }
}

AddrPtr
SupervisorState::CacheAndGetPcFor(TaskInfo &t) noexcept
{
  if (t.mRegisterCacheDirty) {
    CacheRegistersFor(t);
  }
  return t.GetPc();
}

bool
SupervisorState::SetAndCallRunAction(Tid tid, std::shared_ptr<ptracestop::ThreadProceedAction> action) noexcept
{
  return mScheduler->SetTaskScheduling(tid, std::move(action), true);
}

bool
SupervisorState::IsRunning() const noexcept
{
  return std::any_of(mThreads.cbegin(), mThreads.cend(), [](const auto &entry) {
    DBGLOG(core, "Thread {} stopped={}", entry.mTid, entry.mTask->IsStopped());
    return !entry.mTask->IsStopped();
  });
}

void
SupervisorState::OnConfigurationDone(std::function<bool(SupervisorState *supervisor)> &&done) noexcept
{
  mOnConfigurationDoneCallback = std::move(done);
}

bool
SupervisorState::ConfigurationDone() noexcept
{
  if (mIsConfigured) {
    return true;
  }
  mIsConfigured = true;
  return mOnConfigurationDoneCallback(this);
}

void
SupervisorState::EmitStoppedAtBreakpoints(LWP lwp, u32 breakpointId, bool allStopped) noexcept
{
  /* todo(simon): make it possible to determine & set if allThreadsStopped is true or false. For now, we just say
   *  that all get stopped during this event. */
  auto evt = new ui::dap::StoppedEvent{ mSessionId,
    ui::dap::StoppedReason::Breakpoint,
    "Breakpoint Hit",
    lwp.tid,
    { static_cast<int>(breakpointId) },
    "",
    allStopped };
  mDebugAdapterClient->PostDapEvent(evt);
}

void
SupervisorState::EmitStepNotification(LWP lwp) noexcept
{
  /* todo(simon): make it possible to determine & set if allThreadsStopped is true or false. For now, we just say
   *  that all get stopped during this event. */
  DBGLOG(core, "Emit stepped notification for {}", lwp.tid);
  EmitSteppedStop(lwp, "Stepping finished", false);
}

void
SupervisorState::EmitSteppedStop(LWP lwp, std::string_view message, bool allStopped) noexcept
{
  mDebugAdapterClient->PostDapEvent(
    new ui::dap::StoppedEvent{ mSessionId, ui::dap::StoppedReason::Step, message, lwp.tid, {}, "", allStopped });
}

void
SupervisorState::EmitSignalEvent(LWP lwp, int signal) noexcept
{
  /* todo(simon): make it possible to determine & set if allThreadsStopped is true or false. For now, we just say
   *  that all get stopped during this event. */
  mDebugAdapterClient->PostDapEvent(new ui::dap::StoppedEvent{
    mSessionId, ui::dap::StoppedReason::Exception, std::format("Signalled {}", signal), lwp.tid, {}, "", false });
}

void
SupervisorState::EmitStopped(Tid tid,
  ui::dap::StoppedReason reason,
  std::string_view message,
  bool allStopped,
  std::vector<int> breakpointsHit) noexcept
{
  mDebugAdapterClient->PostDapEvent(
    new ui::dap::StoppedEvent{ mSessionId, reason, message, tid, std::move(breakpointsHit), message, allStopped });
}

void
SupervisorState::EmitBreakpointEvent(
  std::string_view reason, const UserBreakpoint &bp, std::optional<std::string> message) noexcept
{
  mDebugAdapterClient->PostDapEvent(new ui::dap::BreakpointEvent{ mSessionId, reason, std::move(message), &bp });
}

void
SupervisorState::EmitAllStopped() noexcept
{
  DBGLOG(core, "[all-stopped]: sending registered notifications");
  // all_stopped_observer.send_notifications();
  mAllStopPublisher.Emit();
}

u32
SupervisorState::ThreadsCount() const noexcept
{
  return mThreads.size();
}

mdb::Expected<Ref<BreakpointLocation>, BreakpointError>
SupervisorState::GetOrCreateBreakpointLocation(AddrPtr addr) noexcept
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
SupervisorState::GetOrCreateBreakpointLocation(
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
SupervisorState::GetOrCreateBreakpointLocationWithSourceLoc(
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
SupervisorState::CheckBreakpointLocationsForSymbolFile(
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
SupervisorState::DoBreakpointsUpdate(std::vector<std::shared_ptr<SymbolFile>> &&newSymbolFiles) noexcept
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
        newLocations.back()->AddUser(*this, *user);
        user->UpdateLocation(std::move(newLocations.back()));
        mUserBreakpoints.AddBreakpointLocation(*user);
        mDebugAdapterClient->PostDapEvent(new ui::dap::BreakpointEvent{ mSessionId, "changed", {}, user });
        newLocations.pop_back();

        for (auto &&loc : newLocations) {
          auto newUser = user->CloneBreakpoint(mUserBreakpoints, *this, loc);
          mDebugAdapterClient->PostDapEvent(new ui::dap::BreakpointEvent{ mSessionId, "new", {}, newUser });
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
              mDebugAdapterClient->PostDapEvent(new ui::dap::BreakpointEvent{ mSessionId, "new", {}, user });
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
        mDebugAdapterClient->PostDapEvent(new ui::dap::BreakpointEvent{ mSessionId, "new", {}, user });
        ids.push_back(user->mId);
      }
    }
  }
}

void
SupervisorState::UpdateSourceBreakpoints(const std::filesystem::path &sourceFilePath,
  std::vector<BreakpointSpecification> &&add,
  const std::vector<BreakpointSpecification> &remove) noexcept
{
  SourceFileBreakpointMap &map = mUserBreakpoints.GetBreakpointsFromSourceFile(sourceFilePath.string());

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
SupervisorState::SetSourceBreakpoints(
  const std::filesystem::path &sourceFilePath, const Set<BreakpointSpecification> &breakpoints) noexcept
{
  const SourceFileBreakpointMap &map = mUserBreakpoints.GetBreakpointsFromSourceFile(sourceFilePath.string());
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
SupervisorState::SetInstructionBreakpoints(const Set<BreakpointSpecification> &breakpoints) noexcept
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
SupervisorState::SetFunctionBreakpoints(const Set<BreakpointSpecification> &breakpoints) noexcept
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
          new ui::dap::BreakpointEvent{ mSessionId, "new", "Breakpoint was created", user });
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
SupervisorState::RemoveBreakpoint(u32 breakpointId) noexcept
{
  mUserBreakpoints.RemoveUserBreakpoint(breakpointId);
}

std::optional<std::string>
SupervisorState::ReadString(TraceePointer<char> address) noexcept
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

sym::UnwinderSymbolFilePair
SupervisorState::GetUnwinderUsingPc(AddrPtr pc) noexcept
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
SupervisorState::CacheRegistersFor(TaskInfo &t, bool forceRefresh) noexcept
{
  if (t.mRegisterCacheDirty || forceRefresh) {
    const auto result = ReadRegisters(t);
    MDB_ASSERT(result.is_ok(), "Failed to read register file for {}; {}", t.mTid, strerror(result.sys_errno));
    t.mRegisterCacheDirty = false;
  }
}

void
SupervisorState::OnSharedObjectEvent() noexcept
{
  DBGLOG(core, "[{}:so] shared object event triggered", mTaskLeader);
  if (const auto readLibrariesResult = ReadLibraries(); readLibrariesResult) {
    std::vector<std::shared_ptr<SymbolFile>> objectFiles{};
    const auto &libraries = readLibrariesResult.value();
    DBGLOG(core, "Object File Descriptors read: {}", libraries.size());
    for (const auto &[path, l_addr] : libraries) {
      auto symbolFile = CreateSymbolFile(*this, path, l_addr);
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
SupervisorState::IsAllStopped() const noexcept
{
  for (const auto &t : mThreads) {
    if (!t.mTask->IsStopped()) {
      return false;
    }
  }
  return true;
}

void
SupervisorState::RegisterSymbolFile(std::shared_ptr<SymbolFile> symbolFile, bool isMainExecutable) noexcept
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
SupervisorState::RegisterObjectFile(
  SupervisorState *tc, std::shared_ptr<ObjectFile> &&obj, bool isMainExecutable, AddrPtr relocatedBase) noexcept
{
  MDB_ASSERT(obj != nullptr, "Object file is null");
  RegisterSymbolFile(SymbolFile::Create(tc, std::move(obj), relocatedBase), isMainExecutable);
}

void
SupervisorState::SetAuxiliaryVector(ParsedAuxiliaryVector data) noexcept
{
  mParsedAuxiliaryVector = data;
}

void
SupervisorState::PostTaskExit(TaskInfo &task, bool notify) noexcept
{
  task.mExited = true;

  mExitedThreads.push_back({ task.mTid, RefPtr{ &task } });
  auto it = std::find_if(mThreads.begin(), mThreads.end(), [tid = task.mTid](auto &t) { return t.mTid == tid; });
  mThreads.erase(it);

  if (notify) {
    mDebugAdapterClient->PostDapEvent(
      new ui::dap::ThreadEvent{ mSessionId, ui::dap::ThreadReason::Exited, task.mTid });
  }
}

std::span<TaskInfoEntry>
SupervisorState::GetThreads() noexcept
{
  return mThreads;
}

ui::dap::DebugAdapterManager *
SupervisorState::GetDebugAdapterProtocolClient() const noexcept
{
  return mDebugAdapterClient;
}

void
SupervisorState::HandleBreakpointHit(TaskInfo &task, const RefPtr<BreakpointLocation> &breakpointLocation) noexcept
{
  task.AddBreakpointLocationStatus(breakpointLocation);
  const auto users = breakpointLocation->GetUserIds();
  VERIFY(!breakpointLocation->GetUserIds().empty(),
    "[task={}]: A breakpoint location with no user is a rogue/leaked breakpoint at {}",
    task.mTid,
    breakpointLocation->Address());

  bool shouldResume = true;
  for (const auto bpId : users) {
    auto user = mUserBreakpoints.GetUserBreakpoint(bpId);
    auto breakpointResult = user->OnHit(*this, task);
    shouldResume = shouldResume && !breakpointResult.ShouldStop();
    if (breakpointResult.ShouldRetire()) {
      mUserBreakpoints.RemoveUserBreakpoint(user->mId);
    }
  }

  mScheduler->Schedule(task, { shouldResume, task.mResumeRequest.mType });
}

void
SupervisorState::HandleExec(TaskInfo &task, const std::string &execFile) noexcept
{
  // stop at entry & install ld.so breakpoints
  PostExec(execFile, true, true);
  mDebugAdapterClient->PostDapEvent(new ui::dap::CustomEvent{
    mSessionId, "setProcessName", std::format(R"({{ "name": "{}", "processId": {} }})", execFile, mTaskLeader) });
  mScheduler->Schedule(task, { true, task.mResumeRequest.mType });
}

sym::CallStack &
SupervisorState::BuildCallFrameStack(TaskInfo &task, const CallStackRequest &req) noexcept
{
  PROFILE_SCOPE("SupervisorState::BuildCallFrameStack", "stacktrace");
  DBGLOG(core, "stacktrace for {}", task.mTid);
  if (!task.mTaskCallstack->IsDirty() && (req.req == CallStackRequest::Type::Full ||
                                           (req.req == CallStackRequest::Type::Partial &&
                                             task.mTaskCallstack->FramesCount() == static_cast<u32>(req.count)))) {
    DBGLOG(core, "activation record cache not dirty");
    return *task.mTaskCallstack;
  }
  CacheRegistersFor(task, true);
  auto &callStack = *task.mTaskCallstack;
  PROFILE_BEGIN("Unwind return addresses", "stacktrace");
  auto frameProgramCounters = task.UnwindReturnAddresses(req);
  PROFILE_END_ARGS("Unwind return addresses", "stacktrace", PEARG("pcs", frameProgramCounters));
  for (const auto &[depth, i] : Enumerate<u32>(frameProgramCounters)) {
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
SupervisorState::FindObjectByPc(AddrPtr addr) noexcept
{
  return mdb::find_if(
    mSymbolFiles, [addr](auto &symbol_file) { return symbol_file->ContainsProgramCounter(addr); })
    .transform([](auto iterator) { return iterator->get(); })
    .value_or(nullptr);
}

sym::Frame
SupervisorState::GetCurrentFrame(TaskInfo &task) noexcept
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

std::optional<std::pair<sym::FunctionSymbol *, NonNullPtr<SymbolFile>>>
SupervisorState::FindFunctionByPc(AddrPtr addr) noexcept
{
  PROFILE_BEGIN("SupervisorState::FindFunctionByPc", "supervisor");
  const auto symbolFile = FindObjectByPc(addr);
  if (symbolFile == nullptr) {
    return std::nullopt;
  }

  auto matchingCompilationUnits = symbolFile->GetUnitDataFromProgramCounter(addr);

  // TODO(simon): Massive room for optimization here. Make get_cus_from_pc return source units directly
  //  or, just make them searchable by cu (via some hashed lookup in a map or something.)
  sym::FunctionSymbol *foundFn = nullptr;
  PROFILE_AT_SCOPE_END("SupervisorState::FindFunctionByPc",
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

void
SupervisorState::PostExec(const std::string &exe, bool stopAtEntry, bool installDynamicLoaderBreakpoints) noexcept
{
  DBGLOG(core, "Processing EXEC for {}", mTaskLeader);
  if (mMainExecutable) {
    mMainExecutable = nullptr;
  }
  mSymbolFiles.clear();

  auto t = GetTaskByTid(TaskLeaderTid());
  CacheRegistersFor(*t);
  mUserBreakpoints.OnExec();

  Auxv auxVectorResult = DoReadAuxiliaryVector().expected("Failed to read auxv");
  mParsedAuxiliaryVector = ParsedAuxiliaryVectorData(auxVectorResult);

  std::vector<u8> programHeaderContents{};
  programHeaderContents.resize(
    mParsedAuxiliaryVector.mProgramHeaderEntrySize * mParsedAuxiliaryVector.mProgramHeaderCount, 0);
  const auto readResult = DoReadBytes(
    mParsedAuxiliaryVector.mProgramHeaderPointer, programHeaderContents.size(), programHeaderContents.data());
  MDB_ASSERT(readResult.WasSuccessful(), "Failed to read program headers");

  Elf64_Phdr *cast = (Elf64_Phdr *)programHeaderContents.data();
  AddrPtr baseAddress = nullptr;
  const Elf64_Phdr *pt_dynamic = nullptr;
  for (auto i = 0u; i < mParsedAuxiliaryVector.mProgramHeaderCount; ++i) {
    if ((cast + i)->p_type == PT_PHDR) {
      baseAddress = mParsedAuxiliaryVector.mProgramHeaderPointer - (cast + i)->p_offset;
      DBGLOG(core, "Found base address in program header data in loaded binary: {}", baseAddress);
    }
    if ((cast + i)->p_type == PT_DYNAMIC) {
      pt_dynamic = (cast + i);
    }
  }

  MDB_ASSERT(pt_dynamic != nullptr, "No dynamic section found.");
  const auto dynamicSegment = baseAddress + pt_dynamic->p_vaddr;
  DBGLOG(core, "Dynamic segment mapped in at {}", dynamicSegment);

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

  if (installDynamicLoaderBreakpoints) {
    InstallDynamicLoaderBreakpoints(dynamicSegment);
  }

  DoBreakpointsUpdate({ mMainExecutable });
  mOnExecOrExitPublisher.Emit();

  if (stopAtEntry) {
    Set<BreakpointSpecification> fns{ BreakpointSpecification::Create<FunctionBreakpointSpec>(
      {}, {}, "main", false) };
    SetFunctionBreakpoints(fns);
  }
}

mdb::Expected<std::unique_ptr<mdb::ByteBuffer>, NonFullRead>
SupervisorState::SafeRead(AddrPtr addr, u64 bytes) noexcept
{
  auto buffer = mdb::ByteBuffer::create(bytes);

  auto totalRead = 0ull;
  while (totalRead < bytes) {
    auto res = DoReadBytes(addr, bytes - totalRead, buffer->next());
    if (!res.WasSuccessful()) {
      return mdb::unexpected(NonFullRead{ std::move(buffer), static_cast<u32>(bytes - totalRead), errno });
    }
    buffer->wrote_bytes(res.uBytesRead);
    totalRead += res.uBytesRead;
  }
  return mdb::Expected<std::unique_ptr<mdb::ByteBuffer>, NonFullRead>{ std::move(buffer) };
}

mdb::Expected<std::unique_ptr<mdb::ByteBuffer>, NonFullRead>
SupervisorState::SafeRead(std::pmr::memory_resource *allocator, AddrPtr addr, u64 bytes) noexcept
{
  auto buffer = mdb::ByteBuffer::create(allocator, bytes);

  auto totalRead = 0ull;
  while (totalRead < bytes) {
    auto res = DoReadBytes(addr, bytes - totalRead, buffer->next());
    if (!res.WasSuccessful()) {
      return mdb::unexpected(NonFullRead{ std::move(buffer), static_cast<u32>(bytes - totalRead), errno });
    }
    buffer->wrote_bytes(res.uBytesRead);
    totalRead += res.uBytesRead;
  }
  return mdb::Expected<std::unique_ptr<mdb::ByteBuffer>, NonFullRead>{ std::move(buffer) };
}

std::optional<std::string>
SupervisorState::ReadNullTerminatedString(TraceePointer<char> address) noexcept
{
  std::string result{};
  if (address == nullptr) {
    return std::nullopt;
  }
  u8 buf[256];
  auto res = DoReadBytes(address.As<void>(), std::size(buf), buf);
  while (res.WasSuccessful()) {
    for (auto i = 0u; i < res.uBytesRead; ++i) {
      if (buf[i] == 0) {
        return result;
      }
      result.push_back(buf[i]);
    }
    res = DoReadBytes(address.As<void>(), 128, buf);
  }

  if (result.empty()) {
    return std::nullopt;
  }
  return result;
}

std::unique_ptr<mdb::LeakVector<u8>>
SupervisorState::ReadToVector(AddrPtr addr, u64 bytes, std::pmr::memory_resource *resource) noexcept
{
  auto data = mdb::LeakVector<u8>::Create(bytes, resource);

  auto totalRead = 0ull;
  while (totalRead < bytes) {
    const auto read_address = addr + totalRead;
    const auto result = DoReadBytes(read_address, bytes - totalRead, data->data_ptr() + totalRead);
    if (!result.WasSuccessful()) {
      PANIC(std::format("Failed to proc_fs read from {}", addr));
    }
    totalRead += result.uBytesRead;
  }
  data->set_size(totalRead);
  return data;
}

bool
SupervisorState::WriteBytes(AddrPtr address, std::span<u8> bytes) noexcept
{
  const auto result = DoWriteBytes(address, bytes.data(), bytes.size_bytes());
  return result.mWasSuccessful;
}

mdb::Expected<u8, BreakpointError>
SupervisorState::InstallSoftwareBreakpointLocation(Tid tid, AddrPtr addr) noexcept
{
  const auto res = InstallBreakpoint(tid, addr);
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

void
SupervisorState::ShutDownDebugAdapterClient() noexcept
{
  if (mDebugAdapterClient) {
    mDebugAdapterClient->PostDapEvent(new ui::dap::TerminatedEvent{
      mSessionId,
    });
    mDebugAdapterClient = nullptr;
  }
}

SupervisorState::LinkerReadResult
SupervisorState::ReadLinkerInformation(const r_debug &dbg, std::vector<ObjectFileDescriptor> &objects) noexcept
{
  if (dbg.r_state != dbg.RT_CONSISTENT) {
    DBGLOG(core, "Debug state not consistent: no information about obj files read");
    return LinkerReadResult::InconsistentState;
  }
  auto linkmap = TPtr<link_map>{ dbg.r_map };
  while (linkmap != nullptr) {
    auto map_res = SafeReadType(linkmap);
    if (!map_res.has_value()) {
      DBGLOG(core, "Failed to read linkmap");
      return LinkerReadResult::Error;
    }
    auto map = map_res.value();
    auto namePointer = TPtr<char>{ map.l_name };
    const auto path = ReadNullTerminatedString(namePointer);
    if (!path) {
      DBGLOG(core, "Failed to read null-terminated string from tracee at {}", namePointer);
      return LinkerReadResult::Error;
    }
    objects.emplace_back(path.value(), map.l_addr);
    linkmap = TPtr<link_map>{ map.l_next };
  }
  return LinkerReadResult::Ok;
}

bool
SupervisorState::ReverseResumeTarget(tc::RunType resumeType) noexcept
{
  // Normal debug sessions do not support reverse execution.
  return false;
}

std::optional<std::vector<ObjectFileDescriptor>>
SupervisorState::ReadLibraries() noexcept
{
  // tracee_r_debug: TPtr<r_debug> points to tracee memory where r_debug lives
  MDB_ASSERT(mLinkerDebugData.mVersion > 0, "Linker data version has not been set");
  std::vector<ObjectFileDescriptor> objectFiles{};
  if (mLinkerDebugData.mVersion == 1) {
    auto rdebug_result = SafeReadType(mLinkerDebugData.mRDebug);
    if (!rdebug_result.has_value()) {
      DBGLOG(core, "Could not read rdebug_extended");
      return {};
    }
    ReadLinkerInformation(*rdebug_result, objectFiles);
  } else {
    auto rdebug_extended = SafeReadType(mLinkerDebugData.mRDebug.As<r_debug_extended>());
    for (;;) {
      if (!rdebug_extended.has_value() || rdebug_extended->base.r_state != rdebug_extended->base.RT_CONSISTENT) {
        break;
      }

      if (ReadLinkerInformation(rdebug_extended->base, objectFiles) != LinkerReadResult::Ok) {
        break;
      }
      const auto next = TPtr<r_debug_extended>{ rdebug_extended->r_next };

      if (next == nullptr) {
        break;
      }
      rdebug_extended = SafeReadType(next);
    }
  }
  return std::make_optional(std::move(objectFiles));
}

} // namespace mdb::tc