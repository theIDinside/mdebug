/** LICENSE TEMPLATE */

#include "rr_session.h"

// rr
#include <ReplayTask.h>
#include <kernel_abi.h>

// mdb
#include <interface/dap/events.h>
#include <interface/tracee_command/rr/rr_supervisor.h>
#include <session_task_map.h>
#include <symbolication/dwarf_binary_reader.h>
#include <task.h>
#include <tracer.h>
#include <utils/todo.h>

namespace mdb::tc::replay {

Session::Session(ReplaySupervisor *replaySupervisor,
  Tid taskLeader,
  uint64_t frameTime,
  ui::dap::DebugAdapterManager *dap) noexcept
    : SupervisorState(SupervisorType::RR, taskLeader, dap), mReplaySupervisor(replaySupervisor),
      mGenesisFrame(frameTime)
{
}

rr::ReplayTask *
Session::GetReplayTask(Tid recTid) noexcept
{
  return mReplaySupervisor->GetTask(recTid);
}

std::optional<std::string>
Session::GetThreadName(Tid tid) noexcept
{
  auto task = mReplaySupervisor->GetTask(tid);
  if (task) {
    return task->name();
  }
  return {};
}

TaskInfo *
Session::CreateNewTask(Tid tid, std::optional<std::string_view> name, bool running) noexcept
{
  DBGLOG(core, "Create new task {}", tid);
  if (auto t = Tracer::GetSessionTaskMap().Get(tid)) {
    if (!t->IsValid()) {
      t->SetName(name.value_or(std::to_string(tid)));
      t->ReInit();
    }
    return t;
  }
  RefPtr<TaskInfo> task = TaskInfo::CreateTask(*this, tid);
  task->SetTimestampCreated(mReplaySupervisor->CurrentFrameTime());
  task->SetName(name.value_or(std::to_string(tid)));

#ifdef MDB_DEBUG
  MDB_ASSERT(mdb::none_of(mThreads, [&tid](const auto &t) { return t.mTid == tid; }), "Duplicate thread added");
#endif

  mThreads.push_back({ task->mTid, task });
  Tracer::GetSessionTaskMap().Add(tid, task);
  return task;
}

/* static */
Session *
Session::Create(ReplaySupervisor *replaySupervisor,
  Tid taskLeader,
  ui::dap::DebugAdapterManager *dap,
  bool hasReplayedStep) noexcept
{
  replaySupervisor->RegisterStopsForProcess(taskLeader);

  auto supervisor = Tracer::Get().PossiblyReviveSupervisor<Session>(taskLeader, [&]() {
    return UniquePtr<Session>(
      new Session{ replaySupervisor, taskLeader, replaySupervisor->CurrentFrameTime(), dap });
  });

  supervisor->mHasFirstExecuted = hasReplayedStep;

  auto *ptr = Tracer::AddSupervisor(std::move(supervisor));
  replaySupervisor->AddSupervisor({ ptr });

  auto t = ptr->CreateNewTask(taskLeader, replaySupervisor->ExecedFile(taskLeader), false);
  t->SetTimestampCreated(replaySupervisor->CurrentFrameTime());

  return ptr;
}

ReplaySupervisor *
Session::GetReplaySupervisor() const noexcept
{
  return mReplaySupervisor;
}

void
Session::StoppedDuringReverse() noexcept
{
  const auto time = mReplaySupervisor->CurrentFrameTime();
  auto i = 0;
  for (auto &entry : mThreads) {
    if (entry.mTask->StartTime() > time) {
      entry.mTask->Invalidate();
    }
  }
}

void
Session::DisconnectDueToReverse()
{
  ShutDownDebugAdapterClient();
}

void
Session::Revive() noexcept
{
  DBGLOG(core, "Reviving supervisor {}", mTaskLeader);
  mRevived = true;
}

bool
Session::HandleBreakpointHitInReverse(
  TaskInfo &task, const RefPtr<BreakpointLocation> &breakpointLocation) noexcept
{
  VERIFY(!breakpointLocation->GetUserIds().empty(),
    "[task={}]: A breakpoint location with no user is a rogue/leaked breakpoint at {}",
    task.mTid,
    breakpointLocation->Address());

  const auto &users = breakpointLocation->GetUserIds();

  bool shouldResume = true;
  for (const auto bpId : users) {
    auto locationUser = mUserBreakpoints.GetUserBreakpoint(bpId);
    if (locationUser->IsUserBreakpoint()) {
      auto breakpointResult = locationUser->OnHit(*this, task);
      shouldResume = shouldResume && !breakpointResult.ShouldStop();
      if (breakpointResult.ShouldRetire()) {
        mUserBreakpoints.RemoveUserBreakpoint(locationUser->mId);
      }
    }
  }

  if (!shouldResume) {
    task.AddBreakpointLocationStatus(breakpointLocation);
  }

  return shouldResume;
}

void
Session::HandleEventInReverse(const ReplayEvent &evt) noexcept
{
  auto task = GetTaskByTid(evt.mTaskInfo.mRecTid);
  // Special case reverse. Reverse should *only* ever stop on breakpoints (non-system bps, so no shared object bps
  // for instance, only user bps) and watchpoints being hit
  bool shouldKeepReversing = true;
  if (evt.mStopKind == StopKind::Stopped) {
    if (evt.mHitBreakpoint) {
      RefPtr loc = mUserBreakpoints.GetLocationAt(evt.mTaskInfo.mRIP);
      TaskInfo *task = GetTaskByTid(evt.mTaskInfo.mRecTid);
      shouldKeepReversing = HandleBreakpointHitInReverse(*task, loc);
    }
  }

  if (shouldKeepReversing) {
    ReverseResumeTarget(tc::RunType::Continue);
  } else {
    mScheduler->Schedule(*task, { false, task->mResumeRequest.mType });
  }
}

void
Session::HandleEvent(const ReplayEvent &evt) noexcept
{
  DBGBUFLOG(core,
    "Handle event {} ({}), recorded tid={}, breakpoint={}, stepping complete={}",
    evt.mStopKind,
    std::to_underlying(evt.mStopKind),
    evt.mTaskInfo.mRecTid,
    evt.mHitBreakpoint,
    evt.mSteppingCompleted);

  // Special case reverse. Reverse should *only* ever stop on breakpoints (non-system bps, so no shared object bps
  // for instance, only user bps) and watchpoints being hit
  if (mReplaySupervisor->IsReversing()) {
    return HandleEventInReverse(evt);
  }

  auto task = GetTaskByTid(evt.mTaskInfo.mRecTid);

  bool steppedOverBreakpoint = false;

  if (task->mBreakpointLocationStatus.mBreakpointLocation && task->mBreakpointLocationStatus.mIsSteppingOver) {
    steppedOverBreakpoint = true;
    task->mBreakpointLocationStatus.mBreakpointLocation->Enable(task->mTid, *this);
    // Clear breakpoint location status. The existence of this value, means the task needs to step over a
    // breakpoint. Since we've established that we've stepped over one here, we need to clear the loc status, so
    // that the next resume doesn't think it needs stepping over a breakpoint.
    task->ClearBreakpointLocStatus();
  }

  MDB_ASSERT(evt.mStopKind >= StopKind::Stopped && evt.mStopKind <= StopKind::NotKnown, "Invalid stop kind value");

  switch (evt.mStopKind) {
  case StopKind::Stopped: {
    if (!task->mHasStarted) {
      task->mHasStarted = true;
    }
    if (evt.mHitBreakpoint) {
      RefPtr loc = mUserBreakpoints.GetLocationAt(evt.mTaskInfo.mRIP);
      TaskInfo *task = GetTaskByTid(evt.mTaskInfo.mRecTid);
      HandleBreakpointHit(*task, loc);
    } else {
      mScheduler->ReplaySchedule(*task, { true, task->mResumeRequest.mType });
    }
  } break;
  case StopKind::Execed: {
    mReplaySupervisor->GetSessionBreakpoints()->UserExeced(task->mTid);
    HandleExec(*task, mReplaySupervisor->ExecedFile(task->mTid));
  } break;
  case StopKind::Exited: {
    // this is... ugly. But tell the scheduler to resume first, because otherwise it'll just not do anything
    // if it sees the task as exited. This only happens for rr sessions, since a resume resumes the replay, not an
    // individual task.
    DBGLOG(core, "Schedule for exited...");
    mScheduler->ReplaySchedule(*task, { true, task->mResumeRequest.mType });
    task->SetExited();
  } break;
  case StopKind::Forked:
    [[fallthrough]];
  case StopKind::VForked: {
    if (!mReplaySupervisor->IsIgnoring(evt.mTaskInfo.mNewTaskIfAny)) {
      HandleFork(*task, evt.mTaskInfo.mNewTaskIfAny, evt.mStopKind == StopKind::VForked);
    } else {
      mScheduler->ReplaySchedule(*task, { true, task->mResumeRequest.mType });
    }
  } break;
  case StopKind::VForkDone: {
  } break;
  case StopKind::Cloned: {
    auto threadName = GetThreadName(evt.mTaskInfo.mNewTaskIfAny);
    CreateNewTask(evt.mTaskInfo.mNewTaskIfAny, threadName.value_or("thread"), false);
    mScheduler->ReplaySchedule(*task, { true, task->mResumeRequest.mType });
  } break;
  case StopKind::Signalled: {
    DBGLOG(core, "Signalled with signal {}", evt.mTaskInfo.mSignal);
    switch (evt.mTaskInfo.mSignal) {
    case SIGTRAP:
      [[fallthrough]];
    case SIGSTOP:
      this->mDebugAdapterClient->PostDapEvent(
        CreateStoppedEvent(ui::dap::StoppedReason::Exception, "Signal stop", task->mTid, "Signal received", true));
      break;
    default:
      mScheduler->ReplaySchedule(*task, { true, task->mResumeRequest.mType });
    }
  } break;
  case StopKind::SyscallEntry: {
    TODO("StopKind::SyscallEntry");
  } break;
  case StopKind::SyscallExit: {
    TODO("StopKind::SyscallExit");
  } break;
  case StopKind::NotKnown: {
  } break;
  }
}

void
Session::AdjustSymbols() noexcept
{
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

  auto exe = mReplaySupervisor->ExecedFile(mTaskLeader);

  DBGLOG(core, "exe for forked process={}", exe);

  if (auto symbol_obj = Tracer::LookupSymbolfile(exe); symbol_obj == nullptr) {
    auto obj = ObjectFile::CreateObjectFile(TaskLeaderTid(), exe);
    if (obj->GetElf()->AddressesNeedsRelocation()) {
      RegisterObjectFile(this, std::move(obj), true, baseAddress);
    } else {
      RegisterObjectFile(this, std::move(obj), true, nullptr);
    }
  } else {
    RegisterSymbolFile(symbol_obj, true);
  }

  constexpr auto InterpreterPath = [](const Elf *elf, const ElfSection *interp) noexcept {
    MDB_ASSERT(interp->mName == ".interp", "Section is not .interp: {}", interp->mName);
    DwarfBinaryReader reader{ elf, interp->mSectionData };
    const auto path = reader.ReadString();
    DBGLOG(core, "Path to system interpreter: {}", path);
    return path;
  };

  const auto mainExecutableElf = mMainExecutable->GetObjectFile()->GetElf();
  const Path interpreterPath = InterpreterPath(mainExecutableElf, mainExecutableElf->GetSection(".interp"));
  const std::shared_ptr tempObjectFile = ObjectFile::CreateObjectFile(TaskLeaderTid(), interpreterPath);
  MDB_ASSERT(tempObjectFile != nullptr, "Failed to mmap the loader binary");

  const auto interpreterBase = mParsedAuxiliaryVector.mInterpreterBaseAddress;

  auto dlDebugStateSymbol = tempObjectFile->FindMinimalFunctionSymbol("_dl_debug_state", true);
  MDB_ASSERT(dlDebugStateSymbol.has_value(), "Did not find _dl_debug_state");
  AddrPtr dlDebugState = dlDebugStateSymbol->address + interpreterBase;

  auto sect = mMainExecutable->GetObjectFile()->GetElf()->GetSection(ElfSec::Dynamic);
  MDB_ASSERT(sect, "Could not find .dynamic section");
  // TODO: Start supporting 32 bits
  auto count = sect->GetDataAs<Elf64_Dyn>().size();
  std::vector<Elf64_Dyn> mappedEntries{ count };
  // slow read. who cares. but change to something better when there's literally nothing else to do.
  const auto bytesRead = ReadIntoVector(dynamicSegment, count, mappedEntries);
  for (const auto &entry : mappedEntries) {
    if (entry.d_tag == DT_DEBUG) {
      auto rDebug = ReadType(TPtr<r_debug>{ entry.d_un.d_val });
      SetLinkerDebugData(rDebug.r_version, entry.d_un.d_val);
      mUserBreakpoints.CreateBreakpointLocationUser<SOLoadingBreakpoint>(
        *this, GetOrCreateBreakpointLocation(rDebug.r_brk), mTaskLeader);
      break;
    }
  }

  auto libs = ReadLibraries();
  MDB_ASSERT(libs.has_value(), "Failed to read libs");

  if (!libs) {
    DBGLOG(core, "{} could not read libraries", mTaskLeader);
    return;
  }

  MDB_ASSERT(!libs->empty(), "No libraries could be read!");

  DBGLOG(core, "Read {} libraries", libs->size());

  for (const auto &lib : *libs) {
    auto symbolFile = CreateSymbolFile(*this, lib.mPath, lib.mAddress);
    if (symbolFile) {
      DBGLOG(core, "{}: registring symbol file {}", mTaskLeader, symbolFile->mSymbolObjectFileId);
      RegisterSymbolFile(symbolFile, false);
    }
  }
}

void
Session::HandleFork(TaskInfo &parentTask, pid_t child, bool vFork) noexcept
{
  const bool hasReplayedStep = false;
  auto newSupervisor = Session::Create(mReplaySupervisor, child, mDebugAdapterClient, hasReplayedStep);
  newSupervisor->mParenPid = mTaskLeader;

  // When a replay session forks, we can't actually notify the debugger client that the process exists yet
  // because, doing so, it would try to actually do stuff with it. The process is not safe to be touched by the
  // client until it's first execution step Therefore, defer any notifications of a new process existing, *until*
  // it has first started (it's first replay event in the trace).
  // So where we for native/ptrace sessions inform the client of a new session to be instantiated here, we wait
  // until first replay step for replay sessions.
  if (!newSupervisor->mRevived) {
    newSupervisor->OnForkCopySymbols(*this, vFork);
  }

  newSupervisor->AdjustSymbols();

  mHasFirstExecuted = true;
  auto &sessionBreakpoints = *mReplaySupervisor->GetSessionBreakpoints();

  {
    std::vector<BreakpointSpecification> add{};
    CopyMapKeysTo(sessionBreakpoints.mFunctionBreakpoints, add);
    DBGLOG(core, "{}: update fn bps of {}", mTaskLeader, add.size());
    UpdateFunctionBreakpoints(add, {});
    add.clear();

    CopyMapKeysTo(sessionBreakpoints.mInstructionBreakpoints, add);
    DBGLOG(core, "{}: update addr bps of {}", mTaskLeader, add.size());
    UpdateInstructionBreakpoints(add, {});
    add.clear();

    for (const auto &[source, specs] : sessionBreakpoints.mSourceCodeBreakpoints) {
      CopyMapKeysTo(specs, add);
      DBGLOG(core, "{}: update source {} bps of {}", mTaskLeader, source, add.size());
      UpdateSourceBreakpoints(source, add, {});
    }
  }

  newSupervisor->CreateNewTask(child, "forked", false);
  if (vFork) {
    TODO("Implement vFork for rr replay sessions");
  }
  mScheduler->ReplaySchedule(parentTask, { true, parentTask.mResumeRequest.mType });
}

mdb::Expected<Auxv, Error>
Session::DoReadAuxiliaryVector() noexcept
{
  auto auxv = mReplaySupervisor->GetAuxv(mTaskLeader);
  Auxv result{};
  result.mContents.reserve(auxv.size() / (8 * 2));
  for (auto i = 0; i < auxv.size(); i += 16) {
    uint64_t value{};
    uint64_t key{};
    std::memcpy(&key, auxv.data() + i, 8);
    std::memcpy(&value, auxv.data() + i + 8, 8);
    result.mContents.emplace_back(key, value);
  }
  return result;
}

TaskExecuteResponse
Session::InstallBreakpoint(Tid tid, AddrPtr addr) noexcept
{
  bool res = mReplaySupervisor->SetBreakpoint(tid, BreakpointRequest{ .is_hardware = false, .address = addr });
  if (res) {
    return TaskExecuteResponse::Ok();
  }
  return TaskExecuteResponse::Error(-1);
}

void
Session::SetSourceBreakpoints(
  const std::filesystem::path &sourceFilePath, const Set<BreakpointSpecification> &breakpoints) noexcept
{
  auto sessionBreakpoints = mReplaySupervisor->GetSessionBreakpoints();
  auto &specsForSource = sessionBreakpoints->mSourceCodeBreakpoints[sourceFilePath];

  std::vector<BreakpointSpecification> add{};
  std::vector<BreakpointSpecification> remove{};

  for (const auto &[spec, bpInfo] : specsForSource) {
    if (!breakpoints.contains(spec)) {
      remove.push_back(spec);
    }
  }

  sessionBreakpoints->RemoveSourceCodeSpec(sourceFilePath, remove);

  for (const auto &b : breakpoints) {
    if (!specsForSource.contains(b)) {
      add.push_back(b);
      DBGLOG(core, "adding spec for source {}", sourceFilePath.c_str());
      specsForSource.emplace(b, sessionBreakpoints->CreateBreakpointInfo());
    }
  }

  // Actually apply breakpoint specs
  mReplaySupervisor->IterateSupervisors([&sourceFilePath, &add, &remove](Session *session) {
    session->UpdateSourceBreakpoints(sourceFilePath, add, remove);
  });
}

void
Session::UpdateInstructionBreakpoints(
  std::span<const BreakpointSpecification> add, std::span<const BreakpointSpecification> remove)
{
  auto &sessionBreakpoints = *mReplaySupervisor->GetSessionBreakpoints();
  for (const auto &bp : add) {
    AddrPtr addr = ToAddress(bp.uInstruction->mInstructionReference).value();
    if (auto symbolFile = FindObjectByPc(addr); symbolFile) {
      const std::vector<sym::CompilationUnit *> cus = symbolFile->GetCompilationUnits(addr);
      for (sym::CompilationUnit *cu : cus) {
        const auto [src, lte] = cu->GetLineTableEntry(symbolFile->UnrelocateAddress(addr));
        if (src && lte) {
          const auto user = mUserBreakpoints.CreateBreakpointLocationUser<Breakpoint>(*this,
            GetOrCreateBreakpointLocation(addr, *src, *lte),
            mTaskLeader,
            LocationUserKind::Address,
            bp.Clone());
          mUserBreakpoints.mInstructionBreakpoints[bp] = user->mId;
          sessionBreakpoints.mInstructionBreakpoints[bp]->AddUser(mTaskLeader);
          break;
        }
      }
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
Session::UpdateFunctionBreakpoints(
  std::span<const BreakpointSpecification> add, std::span<const BreakpointSpecification> remove)
{
  for (const BreakpointSpecification &spec : remove) {
    auto iter = mUserBreakpoints.mFunctionBreakpoints.find(spec);
    MDB_ASSERT(iter != std::end(mUserBreakpoints.mFunctionBreakpoints), "Expected to find fn breakpoint in map");

    for (auto id : iter->second) {
      mUserBreakpoints.RemoveUserBreakpoint(id);
    }
    mUserBreakpoints.mFunctionBreakpoints.erase(iter);
  }

  for (auto &sym : mSymbolFiles) {
    for (auto &spec : add) {
      auto result = sym->LookupFunctionBreakpointBySpec(spec);
      for (auto &&lookup : result) {
        auto user = mUserBreakpoints.CreateBreakpointLocationUser<Breakpoint>(*this,
          GetOrCreateBreakpointLocationWithSourceLoc(lookup.address, std::move(lookup.loc_src_info)),
          mTaskLeader,
          LocationUserKind::Function,
          spec.Clone());
        mUserBreakpoints.mFunctionBreakpoints[spec].push_back(user->mId);
      }
    }
  }
}

// rr session override some DAP commands, as they're supposed to (possibly) affect multiple supervisor via one
// shared interface.
void
Session::UpdateSourceBreakpoints(const std::filesystem::path &sourceFilePath,
  std::span<const BreakpointSpecification> add,
  std::span<const BreakpointSpecification> remove) noexcept
{
  SourceFileBreakpointMap &map = mUserBreakpoints.GetBreakpointsFromSourceFile(sourceFilePath.string());

#define LOGBPADD()                                                                                                \
  DBGLOG(core,                                                                                                    \
    "[{}:bkpt:source:{}]: added bkpt {} at 0x{:x}, orig_byte=0x{:x}",                                             \
    mTaskLeader,                                                                                                  \
    sourceCodeFile->mFullPath.FileName(),                                                                         \
    user->mId,                                                                                                    \
    pc,                                                                                                           \
    user->GetLocation() != nullptr ? *user->GetLocation()->mOriginalByte : u8{ 0 });                              \
  addIdToSpec(user->mId);

  auto sessionBreakpoints = mReplaySupervisor->GetSessionBreakpoints();
  auto &specsForSource = sessionBreakpoints->mSourceCodeBreakpoints[sourceFilePath];

  for (const auto &sourceSpec : add) {
    if (!specsForSource.contains(sourceSpec)) {
      specsForSource.emplace(sourceSpec, sessionBreakpoints->CreateBreakpointInfo());
    }
  }

  for (const auto &symbol_file : mSymbolFiles) {
    auto obj = symbol_file->GetObjectFile();
    for (auto &sourceCodeFile : obj->GetSourceCodeFiles(sourceFilePath.c_str())) {
      // TODO(simon): use arena allocator for foundEntries
      std::vector<sym::dw::LineTableEntry> foundEntries;
      for (const auto &sourceSpec : add) {

        bool appliedSpecAndAdded = false;

        const auto addIdToSpec = [&](u32 id) {
          map[sourceSpec].push_back(id);

          appliedSpecAndAdded = true;
        };

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
            LOGBPADD()
          } else {
            auto user = mUserBreakpoints.CreateBreakpointLocationUser<Breakpoint>(*this,
              GetOrCreateBreakpointLocation(pc, *sourceCodeFile, e),
              mTaskLeader,
              LocationUserKind::Source,
              sourceSpec.Clone());
            LOGBPADD()
          }

          if (!sourceSpec.Column()) {
            break;
          }
        }

        if (appliedSpecAndAdded) {
          specsForSource[sourceSpec]->AddUser(mTaskLeader);
        }
      }
    }
  }

#undef LOGBPADD

  // Remove the breakpoints whose specs got removed
  for (const auto &bp : remove) {
    auto iter = map.find(bp);
    for (const auto id : iter->second) {
      mUserBreakpoints.RemoveUserBreakpoint(id);
    }
    map.erase(map.find(bp));
  }
}

void
Session::SetInstructionBreakpoints(const Set<BreakpointSpecification> &breakpoints) noexcept
{
  MDB_ASSERT(std::ranges::all_of(
               breakpoints, [](const auto &item) { return item.mKind == DapBreakpointType::instruction; }),
    "Require all bps be instruction breakpoints");
  SessionBreakpointSpecs &sessionBreakpoints = *mReplaySupervisor->GetSessionBreakpoints();

  std::vector<BreakpointSpecification> add{};
  std::vector<BreakpointSpecification> remove{};

  for (const auto &bp : breakpoints) {
    if (sessionBreakpoints.TryInitNewInstructionSpec(bp)) {
      add.push_back(bp);
    }
  }

  for (const auto &[bpSpec, bpInfo] : sessionBreakpoints.mInstructionBreakpoints) {
    if (!breakpoints.contains(bpSpec)) {
      remove.push_back(bpSpec);
      sessionBreakpoints.RemoveInstructionSpec(bpSpec);
    }
  }

  // Actually apply breakpoint specs
  mReplaySupervisor->IterateSupervisors([&add, &remove, &sessionBreakpoints](Session *session) {
    session->UpdateInstructionBreakpoints(add, remove);
  });
}

void
Session::SetFunctionBreakpoints(const Set<BreakpointSpecification> &breakpoints) noexcept
{
  std::vector<BreakpointSpecification> remove{};
  std::vector<BreakpointSpecification> add{};

  SessionBreakpointSpecs &sessionBreakpoints = *mReplaySupervisor->GetSessionBreakpoints();

  for (const auto &[b, id] : sessionBreakpoints.mFunctionBreakpoints) {
    if (!breakpoints.contains(b)) {
      remove.push_back(b);
      sessionBreakpoints.RemoveFunctionSpec(b);
    }
  }

  std::hash<BreakpointSpecification> specHasher{};
  for (const auto &b : breakpoints) {
    if (sessionBreakpoints.TryInitNewFunctionSpec(b)) {
      add.push_back(b);
    }
  }

  // Actually apply breakpoint specs
  mReplaySupervisor->IterateSupervisors(
    [&add, &remove](Session *session) { session->UpdateFunctionBreakpoints(add, remove); });
}

void
Session::DoBreakpointsUpdate(const SymbolFile &newSymbolFile) noexcept
{
  auto sessionBreakpoints = mReplaySupervisor->GetSessionBreakpoints();

  // Create new breakpoints, based on source specification or fn name spec, if they exist in new object files
  using Entry = sym::dw::LineTableEntry;

  // Do update for "source breakpoints", breakpoints set via a source spec
  auto obj = newSymbolFile.GetObjectFile();

  // Apply source code breakpoint specs to new symbol file
  for (const auto &[sourceFile, specs] : sessionBreakpoints->mSourceCodeBreakpoints) {
    for (auto &sourceCodeFile : obj->GetSourceCodeFiles(sourceFile)) {
      std::vector<Entry> entries;
      for (auto &[desc, bpInfo] : specs) {
        entries.clear();
        const auto predicate = [&desc](const Entry &lte) {
          return lte.line == desc.uSource->mSpec.line &&
                 desc.uSource->mSpec.column.value_or(lte.column) == lte.column && !lte.IsEndOfSequence;
        };
        sourceCodeFile->ReadInSourceCodeLineTable(entries);
        for (const auto &e : entries | std::views::filter(predicate)) {
          const auto pc = AddrPtr{ e.pc + newSymbolFile.mBaseAddress };
          bool sameSourceLocDiffPc = false;
          if (sameSourceLocDiffPc) {
            auto user = mUserBreakpoints.CreateBreakpointLocationUser<Breakpoint>(*this,
              GetOrCreateBreakpointLocation(pc, *sourceCodeFile, e),
              mTaskLeader,
              LocationUserKind::Source,
              desc.Clone());
            bpInfo->AddUser(mTaskLeader);
            const auto lastSlash = sourceFile.find_last_of('/');
            const std::string_view fileName =
              std::string_view{ sourceFile }.substr(lastSlash == std::string_view::npos ? 0 : lastSlash);
            DBGLOG(core,
              "[{}:bkpt:source:{}]: added bkpt at {}, (unreloc={})",
              mTaskLeader,
              fileName,
              pc,
              newSymbolFile.UnrelocateAddress(pc));
          }
        }
      }
    }
  }

  // Apply function breakpoint specs to new symbol file
  for (auto &[spec, bpInfo] : sessionBreakpoints->mFunctionBreakpoints) {
    auto result = newSymbolFile.LookupFunctionBreakpointBySpec(spec);
    for (auto &&lookup : result) {
      auto user = mUserBreakpoints.CreateBreakpointLocationUser<Breakpoint>(*this,
        GetOrCreateBreakpointLocationWithSourceLoc(lookup.address, std::move(lookup.loc_src_info)),
        mTaskLeader,
        LocationUserKind::Function,
        spec.Clone());
      bpInfo->AddUser(mTaskLeader);
    }
  }

  // Apply address breakpoint specs to new symbol file
  for (auto &[spec, bpInfo] : sessionBreakpoints->mInstructionBreakpoints) {
    auto addr_opt = ToAddress(spec.uInstruction->mInstructionReference);
    MDB_ASSERT(addr_opt.has_value(), "Failed to convert instructionReference to valid address");
    const auto addr = addr_opt.value();
    if (newSymbolFile.ContainsProgramCounter(addr)) {
      if (auto res = GetOrCreateBreakpointLocation(addr); res.is_expected()) {
        bpInfo->AddUser(mTaskLeader);
        (void)mUserBreakpoints.CreateBreakpointLocationUser<Breakpoint>(
          *this, *res, mTaskLeader, LocationUserKind::Address, spec.Clone());
      }
    }
  }
}

void
Session::DoBreakpointsUpdate(std::span<std::shared_ptr<SymbolFile>> newSymbolFiles) noexcept
{
  for (const auto &symbolFile : newSymbolFiles) {
    DoBreakpointsUpdate(*symbolFile);
  }
}

void
Session::OnErase() noexcept
{
  mReplaySupervisor->Erase(this);
  mDebugAdapterClient->RemoveSupervisor(this);
}

TaskExecuteResponse
Session::ReadRegisters(TaskInfo &t) noexcept
{
  // We don't need to read registers here at all (I believe). Because RR will have fetched this for us.
  auto task = mReplaySupervisor->GetTask(t.mTid);
  MDB_ASSERT(task, "No task by that id: {}", t.mTid);
  auto userRegs = task->regs().get_ptrace();
  DBGBUFLOG(core,
    "read registers for {}: [rip:0x{:x}, rsp:0x{:x}, rax:0x{:x}]",
    t.mTid,
    userRegs.rip,
    userRegs.rsp,
    userRegs.rax);
  return TaskExecuteResponse::Ok();
}

TaskExecuteResponse
Session::WriteRegisters(TaskInfo &t, void *data, size_t length) noexcept
{
  // Diversion sessions not supported (and may never be supported.)
  return TaskExecuteResponse::Error(-1);
}

TaskExecuteResponse
Session::SetRegister(TaskInfo &t, size_t registerNumber, void *data, size_t length) noexcept
{
  return TaskExecuteResponse::Error(-1);
}

u64
Session::GetUserRegister(const TaskInfo &t, size_t registerNumber) noexcept
{
  // this should be safe rr::NativeArch::user_regs_struct -> user_regs_struct
  const auto internalData = mReplaySupervisor->GetTask(t.mTid)->regs().get_regs_for_trace();
  const auto index = GetDwarfRegisterIndex(registerNumber);
  auto *ptr = reinterpret_cast<const u64 *>(internalData.data);
  return *(ptr + index);
}

TaskExecuteResponse
Session::DoDisconnect(bool terminate) noexcept
{
  mReplaySupervisor->Shutdown();
  return TaskExecuteResponse::Ok();
}

ReadResult
Session::DoReadBytes(AddrPtr address, u32 size, u8 *readBuffer) noexcept
{
  const auto result = mReplaySupervisor->ReadMemory(mTaskLeader, address, size, readBuffer);
  if (result == -1) {
    DBGLOG(core, "Reading from target failed, target is running");
    return ReadResult::AppError(ApplicationError::TargetIsRunning);
  }

  return ReadResult::Ok((u32)result);
}

TraceeWriteResult
Session::DoWriteBytes(AddrPtr addr, const u8 *buf, u32 size) noexcept
{
  TODO("Session::DoWriteBytes(AddrPtr addr, const u8 *buf, u32 size) noexcept");
}

TaskExecuteResponse
Session::EnableBreakpoint(Tid tid, BreakpointLocation &location) noexcept
{
  bool res = mReplaySupervisor->SetBreakpoint(
    tid, BreakpointRequest{ .is_hardware = false, .address = location.Address() });
  if (res) {
    return TaskExecuteResponse::Ok();
  }
  return TaskExecuteResponse::Error(-1);
}

TaskExecuteResponse
Session::DisableBreakpoint(Tid tid, BreakpointLocation &location) noexcept
{
  bool res = mReplaySupervisor->RemoveBreakpoint(
    tid, BreakpointRequest{ .is_hardware = false, .address = location.Address() });
  if (res) {
    return TaskExecuteResponse::Ok();
  }
  return TaskExecuteResponse::Error(-1);
}

TaskExecuteResponse
Session::StopTask(TaskInfo &t) noexcept
{
  // Supervisor does single threaded execution, interrupting all is interrupting `t`
  mReplaySupervisor->RequestInterrupt(mTaskLeader);
  return TaskExecuteResponse::Ok();
}

void
Session::DoResumeTask(TaskInfo &t, RunType runType) noexcept
{
  DBGLOG(core, "Attempting to resume task {}, type=", t.mTid, runType);
  mdbrr::ResumeReplay resumeReplay{ .resume_type = mdbrr::ResumeType::RR_RESUME,
    .direction = mdbrr::ReplayDirection::RR_DIR_FORWARD };
  if (runType == RunType::Step) [[unlikely]] {
    resumeReplay.resume_type = mdbrr::ResumeType::RR_STEP;
    resumeReplay.steps = 1;
  }

  mReplaySupervisor->RequestResume(resumeReplay);
}

bool
Session::DoResumeTarget(RunType runType) noexcept
{
  mdbrr::ResumeReplay resumeReplay{ .resume_type = mdbrr::ResumeType::RR_RESUME,
    .direction = mdbrr::ReplayDirection::RR_DIR_FORWARD };
  if (runType == RunType::Step) [[unlikely]] {
    resumeReplay.resume_type = mdbrr::ResumeType::RR_STEP;
  }

  // The task to resume may not belong to the session where the user requested resume in.
  // Therefore pull it out of the global "world map".

  TaskInfo *task = Tracer::GetSessionTaskMap().Get(mReplaySupervisor->GetTaskToResume());
  MDB_ASSERT(task, "task not found {}", mReplaySupervisor->GetTaskToResume());

  if (task->mBreakpointLocationStatus.IsValid()) {
    task->StepOverBreakpoint();
    return true;
  }

  return mReplaySupervisor->RequestResume(resumeReplay);
}

bool
Session::ReverseResumeTarget(tc::RunType runType) noexcept
{
  mdbrr::ResumeReplay resumeReplay{ .resume_type = mdbrr::ResumeType::RR_RESUME,
    .direction = mdbrr::ReplayDirection::RR_DIR_REVERSE };

  if (runType == RunType::Step) [[unlikely]] {
    resumeReplay.resume_type = mdbrr::ResumeType::RR_STEP;
  }

  bool ok = mReplaySupervisor->RequestResume(resumeReplay);
  if (!ok) {
    return false;
  }
  return true;
}

void
Session::AttachSession() noexcept
{
  // no-op. an rr replay is controllable through 1 session only, using specialized/supported only by midas DAP
  // extensions
}

bool
Session::Pause(Tid tid) noexcept
{
  if (!mReplaySupervisor->IsReplaying()) {
    auto pid = mReplaySupervisor->GetTaskToResume();
    mDebugAdapterClient->PostDapEvent(
      CreateStoppedEvent(ui::dap::StoppedReason::Pause, "Paused", tid, "Paused all", true, {}));
    return true;
  }
  auto task = GetTaskByTid(tid);
  if (task->IsStopped()) {
    return false;
  }
  const bool success = SetAndCallRunAction(
    task->mTid, std::make_shared<ptracestop::StopImmediately>(*this, *task, ui::dap::StoppedReason::Pause));
  return success;
}

/* virtual */
mdb::ui::dap::StoppedEvent *
Session::CreateStoppedEvent(ui::dap::StoppedReason reason,
  std::string_view description,
  Tid tid,
  std::string_view text,
  bool allStopped,
  std::vector<int> breakpointsHit) noexcept
{
  auto event =
    SupervisorState::CreateStoppedEvent(reason, description, tid, text, allStopped, std::move(breakpointsHit));

  event->SetExistingProcesses(mReplaySupervisor->CurrentLiveProcesses());
  return event;
}

static TaskInfo *
GetCachedTask(Tid tid, std::vector<TaskInfoEntry> &entries)
{
  for (const auto &entry : entries) {
    if (entry.mTid == tid) {
      return entry.mTask;
    }
  }
  return nullptr;
}

} // namespace mdb::tc::replay