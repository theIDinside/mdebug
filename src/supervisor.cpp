/** LICENSE TEMPLATE */
#include "supervisor.h"
#include "bp.h"
#include "fmt/core.h"
#include "interface/dap/events.h"
#include "interface/dap/interface.h"
#include "interface/dap/types.h"
#include "interface/tracee_command/ptrace_commander.h"
#include "interface/tracee_command/tracee_command_interface.h"
#include "symbolication/dwarf/name_index.h"
#include "symbolication/dwarf_binary_reader.h"
#include "symbolication/dwarf_expressions.h"
#include "symbolication/dwarf_frameunwinder.h"
#include "symbolication/elf_symbols.h"
#include "symbolication/objfile.h"
#include "task.h"
#include "tasks/dwarf_unit_data.h"
#include "tasks/index_die_names.h"
#include "tracer.h"
#include "utils/byte_buffer.h"
#include "utils/enumerator.h"
#include "utils/expected.h"
#include "utils/immutable.h"
#include "utils/logger.h"
#include "utils/macros.h"
#include "utils/scope_defer.h"
#include <algorithm>
#include <chrono>
#include <elf.h>
#include <fcntl.h>
#include <filesystem>
#include <iterator>
#include <link.h>
#include <mdbsys/ptrace.h>
#include <ranges>
#include <set>
#include <span>
#include <string_view>
#include <sys/mman.h>
#include <unistd.h>
#include <utility>

namespace mdb {

using sym::dw::SourceCodeFile;

template <typename TaskPointerType>
constexpr auto
FindByTid(std::vector<TaskPointerType> &container, Tid tid) noexcept
{
  return std::find_if(container.begin(), container.end(), [tid](const auto &task) { return task.mTid == tid; });
}

// FORK constructor
TraceeController::TraceeController(TraceeController &parent, tc::Interface &&interface, bool isVFork) noexcept
    : mParentPid(parent.mTaskLeader), mTaskLeader{interface->TaskLeaderTid()}, mSymbolFiles(parent.mSymbolFiles),
      mMainExecutable{parent.mMainExecutable}, mThreads{}, mThreadInfos{}, mUserBreakpoints{*this},
      mSharedObjects{parent.mSharedObjects.clone()}, mInterfaceType{parent.mInterfaceType},
      mInterpreterBase{parent.mInterpreterBase}, mEntry{parent.mEntry}, mSessionKind{parent.mSessionKind},
      mScheduler{std::make_unique<TaskScheduler>(this)}, mNullUnwinder{parent.mNullUnwinder},
      mTraceeInterface{std::move(interface)}
{
  mIsVForking = isVFork;
  // Must be set first.
  mTraceeInterface->SetTarget(this);
  mThreads.reserve(64);

  // Out of order events may have already created the task.
  if (auto t = Tracer::Get().TakeUninitializedTask(mTraceeInterface->TaskLeaderTid()); t) {
    ASSERT(t->mSupervisor == nullptr, "This task {} already has a supervisor.", t->mTid);
    t->InitializeThread(*mTraceeInterface, false);
    AddTask(std::move(t));
  } else {
    auto task = TaskInfo::CreateTask(*mTraceeInterface, mTraceeInterface->TaskLeaderTid(), false);
    Tracer::Get().RegisterTracedTask(task);
    AddTask(std::move(task));
  }

  mNewObjectFilePublisher.Subscribe(SubscriberIdentity::Of(this), [this](const SymbolFile *sf) {
    mDebugAdapterClient->PostDapEvent(new ui::dap::ModuleEvent{"new", *sf});
  });
  mBreakpointBehavior = parent.mBreakpointBehavior;
}

TraceeController::TraceeController(TargetSession targetSession, tc::Interface &&interface,
                                   InterfaceType type) noexcept
    : mParentPid(0), mTaskLeader{interface != nullptr ? interface->TaskLeaderTid() : 0}, mMainExecutable{nullptr},
      mThreads{}, mThreadInfos{}, mUserBreakpoints{*this}, mSharedObjects{}, mInterfaceType(type),
      mInterpreterBase{}, mEntry{}, mSessionKind{targetSession}, mScheduler{std::make_unique<TaskScheduler>(this)},
      mNullUnwinder{new sym::Unwinder{nullptr}}, mTraceeInterface(std::move(interface))
{
  // Must be set first.
  mTraceeInterface->SetTarget(this);
  mThreads.reserve(64);
  auto task = TaskInfo::CreateTask(*mTraceeInterface, mTraceeInterface->TaskLeaderTid(), true);
  Tracer::Get().RegisterTracedTask(task);
  AddTask(std::move(task));

  mNewObjectFilePublisher.Subscribe(SubscriberIdentity::Of(this), [this](const SymbolFile *sf) {
    mDebugAdapterClient->PostDapEvent(new ui::dap::ModuleEvent{"new", *sf});
  });
}

/*static*/
std::unique_ptr<TraceeController>
TraceeController::create(TargetSession session, tc::Interface &&interface, InterfaceType type)
{
  return std::unique_ptr<TraceeController>(new TraceeController{session, std::move(interface), type});
}

void
TraceeController::ConfigureBreakpointBehavior(BreakpointBehavior behavior) noexcept
{
  mBreakpointBehavior = behavior;
}

void
TraceeController::TearDown(bool killProcess) noexcept
{
  DBGLOG(core, "Tear down traced process space {} - unclear if this method is needed. Kill={}", mTaskLeader,
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
  StopAllTasks(nullptr);
  const auto ok = GetInterface().DoDisconnect(false);
  VERIFY(ok.is_ok(), "Failed to disconnect: {}", strerror(ok.sys_errno));
}

std::unique_ptr<TraceeController>
TraceeController::Fork(tc::Interface &&interface, bool isVFork) noexcept
{
  auto child = std::unique_ptr<TraceeController>(new TraceeController{*this, std::move(interface), isVFork});
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
  return mEntry.value_or(nullptr);
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

std::vector<ProbeInfo>
parse_stapsdt_note(const Elf *elf, const ElfSection *section) noexcept
{
  std::vector<ProbeInfo> probes;
  DwarfBinaryReader reader{elf, section->mSectionData};
  std::set<std::string_view> required_probes{{"map_complete", "reloc_complete", "unmap_complete"}};
  // stapsdt, location 8 bytes, base 8 bytes, semaphore 8 bytes, desc=string of N bytes, then more bytes we don't
  // care for

  while (reader.has_more() && required_probes.size() > 0) {
    reader.read_value<u32>();
    reader.read_value<u32>();
    reader.read_value<u32>();
    // const auto stapsdt = reader.read_string();
    // ASSERT(stapsdt == "stapsdt", "Failed to see 'stapsdt' deliminator; saw {}", stapsdt);
    // instead just skip:
    reader.skip_string();

    const auto ptr = reader.read_value<u64>();
    // base =
    reader.skip_value<u64>();
    // semaphore =
    reader.skip_value<u64>();

    // same here
    // const auto provider = reader.read_string();
    // ASSERT(provider == "rtld", "Supported provider is rtld, got {}", provider);
    reader.skip_string();
    const auto probe_name = reader.read_string();
    reader.skip_string();
    if (reader.bytes_read() % 4 != 0) {
      reader.skip(4 - reader.bytes_read() % 4);
    }
    if (required_probes.contains(probe_name)) {
      probes.push_back(ProbeInfo{.address = ptr, .name = std::string{probe_name}});
      required_probes.erase(required_probes.find(probe_name));
    }
  }
  return probes;
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
get_rdebug_state(ObjectFile *obj_file)
{
  const auto rdebug_state = obj_file->FindMinimalObjectSymbol(LOADER_STATE);
  ASSERT(rdebug_state.has_value(), "Could not find _r_debug!");
  return rdebug_state->address.as<r_debug_extended>();
}

TPtr<r_debug_extended>
TraceeController::InstallDynamicLoaderBreakpoints() noexcept
{
  ASSERT(mMainExecutable != nullptr, "No main executable for this target");
  const auto mainExecutableElf = mMainExecutable->GetObjectFile()->GetElf();
  auto int_path = interpreter_path(mainExecutableElf, mainExecutableElf->GetSection(".interp"));
  auto tmp_objfile = ObjectFile::CreateObjectFile(this, int_path);
  ASSERT(tmp_objfile != nullptr, "Failed to mmap the loader binary");
  const auto system_tap_sec = tmp_objfile->GetElf()->GetSection(".note.stapsdt");
  const auto probes = parse_stapsdt_note(tmp_objfile->GetElf(), system_tap_sec);

  mTraceeInterface->tracee_r_debug = *mInterpreterBase + get_rdebug_state(tmp_objfile.get());
  DBGLOG(core, "_r_debug found at {}", mTraceeInterface->tracee_r_debug);
  for (const auto symbol_name : LOADER_SYMBOL_NAMES) {
    if (auto symbol = tmp_objfile->FindMinimalFunctionSymbol(symbol_name); symbol) {
      const auto addr = *mInterpreterBase + symbol->address;
      DBGLOG(core, "Setting ld breakpoint at 0x{:x}", addr);
      mUserBreakpoints.create_loc_user<SOLoadingBreakpoint>(*this, GetOrCreateBreakpointLocation(addr),
                                                            mTaskLeader);
    }
  }

  return mTraceeInterface->tracee_r_debug;
}

void
TraceeController::OnSharedObjectEvent() noexcept
{
  DBGLOG(core, "[{}:so] shared object event triggered", mTaskLeader);
  if (const auto libs_result = mTraceeInterface->ReadLibraries(); libs_result) {
    std::vector<std::shared_ptr<SymbolFile>> obj_files{};
    const auto &libs = libs_result.value();
    DBGLOG(core, "Object File Descriptors read: {}", libs.size());
    for (const auto &[path, l_addr] : libs) {
      auto symbolFile = createSymbolFile(*this, path, l_addr);
      if (symbolFile) {
        obj_files.push_back(symbolFile);
        RegisterSymbolFile(symbolFile, false);
      }
    }
    DoBreakpointsUpdate(std::move(obj_files));
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
  mThreads.push_back({.mTid = t, .mTask = std::move(task)});
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

std::span<TaskInfo::TaskInfoEntry>
TraceeController::GetThreads() noexcept
{
  return mThreads;
}

std::span<TaskInfo::TaskInfoEntry>
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

void
TraceeController::CreateNewTask(Tid tid, bool running) noexcept
{
  ASSERT(tid != 0 && !HasTask(tid), "Task {} has already been created!", tid);
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
TraceeController::ResumeTarget(tc::ResumeAction action) noexcept
{
  DBGLOG(core, "[supervisor]: resume tracee {}", to_str(action.type));
  mScheduler->SetNormalScheduling();
  bool resumedAtLeastOne = false;
  for (auto &entry : mThreads) {
    resumedAtLeastOne |= entry.mTask->mUserVisibleStop;
  }
  return mTraceeInterface->ResumeTarget(this, action).is_ok() && resumedAtLeastOne;
}

void
TraceeController::ResumeTask(TaskInfo &task, tc::ResumeAction type) noexcept
{
  mScheduler->SetNormalScheduling();
  bool resume_task = !(task.mBreakpointLocationStatus);
  // The breakpoint location which loc_stat refers to, may have been deleted; as such we don't need to step over
  // that breakpoint any more but we will need to remove the loc stat on this task.
  if (task.mBreakpointLocationStatus) {
    auto location = mUserBreakpoints.location_at(task.mBreakpointLocationStatus->loc);
    if (location) {
      task.step_over_breakpoint(this, type);
    } else {
      task.clear_bpstat();
      resume_task = true;
    }
  }

  // we do it like this, to not have to say tc->resume_task(...) in multiple places.
  if (resume_task) {
    const auto res = mTraceeInterface->ResumeTask(task, type);
    CDLOG(!res.is_ok(), core, "Unable to resume task {}: {}", task.mTid, strerror(res.sys_errno));
  }
  task.mLastWaitStatus = WaitStatus{WaitStatusKind::NotKnown, {}};
  task.clear_stop_state();
  task.SetCurrentResumeAction(type);
}

void
TraceeController::StopAllTasks(TaskInfo *requestingTask, std::function<void()> &&callback) noexcept
{
  mAllStopPublisher.Once(std::move(callback));
  StopAllTasks(requestingTask);
}

void
TraceeController::StopAllTasks(TaskInfo *requestingTask) noexcept
{
  DBGLOG(core, "Stopping all threads")
  // If all threads were at a signal-delivery stop, then we will not receive new wait status events
  // and we will never report to the user that everyone has stopped. We need to track that, and possibly emit a
  // stopped event immediately.
  bool actuallyStoppedChild = false;
  mScheduler->SetStopAllScheduling();
  for (auto &entry : mThreads) {
    auto &t = *entry.mTask;
    if (!t.mUserVisibleStop && !t.mTracerVisibleStop) {
      actuallyStoppedChild = true;
      DBGLOG(core, "Halting {}", t.mTid);
      const auto response = mTraceeInterface->StopTask(t);
      ASSERT(response.is_ok(), "Failed to stop {}: {}", t.mTid, strerror(response.sys_errno));
      t.set_stop();
    } else if (t.mTracerVisibleStop) {
      // we're in a tracer-stop, not in a user-stop, so we need no stopping, we only need to inform ourselves that
      // we upgraded our tracer-stop to a user-stop
      t.set_stop();
    }
  }

  if (!actuallyStoppedChild) {
    mAllStopPublisher.Emit();
  }
}

TaskInfo *
TraceeController::RegisterTaskWaited(TaskWaitResult wait) noexcept
{
  ASSERT(HasTask(wait.tid), "Target did not contain task {}", wait.tid);
  auto task = GetTaskByTid(wait.tid);
  task->set_taskwait(wait);
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
  ASSERT(res.is_ok(), "Failed to set PC for {}; {}", task.mTid, strerror(res.sys_errno));
  task.mInstructionPointerDirty = false;
}

void
TraceeController::SetTaskVmInfo(Tid tid, TaskVMInfo vmInfo) noexcept
{
  ASSERT(HasTask(tid), "Unknown task {}", tid);
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
TraceeController::EmitStoppedAtBreakpoints(LWP lwp, u32 bp_id, bool allStopped) noexcept
{
  /* todo(simon): make it possible to determine & set if allThreadsStopped is true or false. For now, we just say
   *  that all get stopped during this event. */
  DBGLOG(core, "[dap event]: stopped at breakpoint {} emitted", bp_id);
  auto evt =
    new ui::dap::StoppedEvent{ui::dap::StoppedReason::Breakpoint, "Breakpoint Hit", lwp.tid, {}, "", allStopped};
  evt->bp_ids.push_back(bp_id);
  mDebugAdapterClient->PostDapEvent(evt);
}

void
TraceeController::EmitSteppedStop(LWP lwp) noexcept
{
  /* todo(simon): make it possible to determine & set if allThreadsStopped is true or false. For now, we just say
   *  that all get stopped during this event. */
  EmitSteppedStop(lwp, "Stepping finished", false);
}

void
TraceeController::EmitSteppedStop(LWP lwp, std::string_view message, bool allStopped) noexcept
{
  mDebugAdapterClient->PostDapEvent(
    new ui::dap::StoppedEvent{ui::dap::StoppedReason::Step, message, lwp.tid, {}, "", allStopped});
}

void
TraceeController::EmitSignalEvent(LWP lwp, int signal) noexcept
{
  /* todo(simon): make it possible to determine & set if allThreadsStopped is true or false. For now, we just say
   *  that all get stopped during this event. */
  mDebugAdapterClient->PostDapEvent(new ui::dap::StoppedEvent{
    ui::dap::StoppedReason::Exception, fmt::format("Signalled {}", signal), lwp.tid, {}, "", true});
}

void
TraceeController::EmitStopped(Tid tid, ui::dap::StoppedReason reason, std::string_view message, bool allStopped,
                              std::vector<int> bps_hit) noexcept
{
  mDebugAdapterClient->PostDapEvent(
    new ui::dap::StoppedEvent{reason, message, tid, std::move(bps_hit), message, allStopped});
}

void
TraceeController::EmitBreakpointEvent(std::string_view reason, const UserBreakpoint &bp,
                                      std::optional<std::string> message) noexcept
{
  mDebugAdapterClient->PostDapEvent(new ui::dap::BreakpointEvent{reason, std::move(message), &bp});
}

tc::ProcessedStopEvent
TraceeController::ProcessDeferredStopEvent(TaskInfo &, DeferToSupervisor &) noexcept
{
  TODO("implement TraceeController::process_deferred_stopevent(TaskInfo &t, DeferToSupervisor &evt) noexcept");
}

mdb::Expected<Ref<BreakpointLocation>, BpErr>
TraceeController::GetOrCreateBreakpointLocation(AddrPtr addr) noexcept
{
  if (auto loc = mUserBreakpoints.location_at(addr); loc) {
    return loc;
  }

  auto res = InstallSoftwareBreakpointLocation(mTaskLeader, addr);
  if (!res.is_expected()) {
    return mdb::unexpected(res.take_error());
  }
  const auto original_byte = res.take_value();
  return BreakpointLocation::CreateLocation(addr, original_byte);
}

mdb::Expected<Ref<BreakpointLocation>, BpErr>
TraceeController::GetOrCreateBreakpointLocation(AddrPtr addr, sym::dw::SourceCodeFile &sourceFile,
                                                const sym::dw::LineTableEntry &lte) noexcept
{
  auto loc = mUserBreakpoints.location_at(addr);
  if (loc) {
    return loc;
  }

  auto res = InstallSoftwareBreakpointLocation(mTaskLeader, addr);
  if (!res.is_expected()) {
    return res.take_error();
  }
  auto original_byte = res.take_value();
  return BreakpointLocation::CreateLocationWithSource(
    addr, original_byte,
    std::make_unique<LocationSourceInfo>(sourceFile.mFullPath.StringView(), lte.line, u32{lte.column}));
}

mdb::Expected<Ref<BreakpointLocation>, BpErr>
TraceeController::GetOrCreateBreakpointLocationWithSourceLoc(
  AddrPtr addr, std::optional<LocationSourceInfo> &&sourceLocInfo) noexcept
{
  if (auto loc = mUserBreakpoints.location_at(addr); loc) {
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
TraceeController::CheckBreakpointLocationsForSymbolFile(SymbolFile &symbolFile, UserBreakpoint &user,
                                                        std::vector<Ref<BreakpointLocation>> &locs) noexcept
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
      auto addr_opt = to_addr(spec.mInstructionReference);
      ASSERT(addr_opt.has_value(), "Failed to convert instructionReference to valid address");
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
  auto non_verified = mUserBreakpoints.non_verified();
  DBGLOG(core, "[breakpoints]: Updating breakpoints due to new symbol files; non verified={}",
         non_verified.size());

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
        newLocations.back()->add_user(GetInterface(), *user);
        user->UpdateLocation(std::move(newLocations.back()));
        mUserBreakpoints.add_bp_location(*user);
        mDebugAdapterClient->PostDapEvent(new ui::dap::BreakpointEvent{"changed", {}, user});
        newLocations.pop_back();

        for (auto &&loc : newLocations) {
          auto newUser = user->CloneBreakpoint(mUserBreakpoints, *this, loc);
          mDebugAdapterClient->PostDapEvent(new ui::dap::BreakpointEvent{"new", {}, newUser});
          ASSERT(!loc->loc_users().empty(), "location has no user!");
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
    for (const auto &source_file : mUserBreakpoints.sources_with_bpspecs()) {
      auto &file_bp_map = mUserBreakpoints.bps_for_source(source_file);
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
            const auto pc = AddrPtr{e.pc + sym->mBaseAddress};
            bool sameSourceLocDiffPc = false;
            for (const auto id : user_ids) {
              auto user = mUserBreakpoints.GetUserBreakpoint(id);
              if (user->Address() != pc) {
                sameSourceLocDiffPc = true;
              }
            }
            if (sameSourceLocDiffPc) {
              auto user = mUserBreakpoints.create_loc_user<Breakpoint>(
                *this, GetOrCreateBreakpointLocation(pc, *sourceCodeFile, e), mTaskLeader,
                LocationUserKind::Source, desc.Clone());
              mDebugAdapterClient->PostDapEvent(new ui::dap::BreakpointEvent{"new", {}, user});
              user_ids.push_back(user->mId);
              const auto last_slash = source_file.find_last_of('/');
              const std::string_view file_name =
                source_file.substr(last_slash == std::string_view::npos ? 0 : last_slash);
              DBGLOG(core, "[{}:bkpt:source:{}]: added bkpt at {}, (unreloc={})", mTaskLeader, file_name, pc,
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
    for (auto &[fn, ids] : mUserBreakpoints.fn_breakpoints) {
      auto result = sym->LookupFunctionBreakpointBySpec(fn);
      for (auto &&lookup : result) {
        auto user = mUserBreakpoints.create_loc_user<Breakpoint>(
          *this, GetOrCreateBreakpointLocationWithSourceLoc(lookup.address, std::move(lookup.loc_src_info)),
          mTaskLeader, LocationUserKind::Function, fn.Clone());
        mDebugAdapterClient->PostDapEvent(new ui::dap::BreakpointEvent{"new", {}, user});
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
  UserBreakpoints::SourceFileBreakpointMap &map = mUserBreakpoints.bps_for_source(sourceFilePath.string());

  Set<BreakpointSpecification> not_set{add.begin(), add.end()};

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

          auto user = mUserBreakpoints.create_loc_user<Breakpoint>(
            *this, GetOrCreateBreakpointLocation(pc, *sourceCodeFile, e), mTaskLeader, LocationUserKind::Source,
            sourceSpec.Clone());
          map[sourceSpec].push_back(user->mId);
          DBGLOG(core, "[{}:bkpt:source:{}]: added bkpt {} at 0x{:x}, orig_byte=0x{:x}", mTaskLeader,
                 sourceCodeFile->mFullPath.FileName(), user->mId, pc,
                 user->GetLocation() != nullptr ? *user->GetLocation()->original_byte : u8{0});
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
    auto user = mUserBreakpoints.create_loc_user<Breakpoint>(
      *this, BpErr{ResolveError{.spec = spec.get()}}, mTaskLeader, LocationUserKind::Source, std::move(spec));
    map[srcbp].push_back(user->mId);
  }

  for (const auto &bp : remove) {
    auto iter = map.find(bp);
    for (const auto id : iter->second) {
      mUserBreakpoints.remove_bp(id);
    }
    map.erase(map.find(bp));
  }
}

void
TraceeController::SetSourceBreakpoints(const std::filesystem::path &sourceFilePath,
                                       const Set<BreakpointSpecification> &bps) noexcept
{
  const UserBreakpoints::SourceFileBreakpointMap &map = mUserBreakpoints.bps_for_source(sourceFilePath.string());
  std::vector<BreakpointSpecification> remove{};
  std::vector<BreakpointSpecification> add{};

  for (const auto &[b, id] : map) {
    if (!bps.contains(b)) {
      remove.push_back(b);
    }
  }

  for (const auto &b : bps) {
    if (!map.contains(b)) {
      add.push_back(b);
    }
  }

  UpdateSourceBreakpoints(sourceFilePath, std::move(add), remove);
}

void
TraceeController::SetInstructionBreakpoints(const Set<BreakpointSpecification> &bps) noexcept
{
  ASSERT(std::ranges::all_of(bps, [](const auto &item) { return item.mKind == DapBreakpointType::instruction; }),
         "Require all bps be instruction breakpoints");
  std::vector<BreakpointSpecification> add{};
  std::vector<BreakpointSpecification> remove{};

  for (const auto &[bp, id] : mUserBreakpoints.instruction_breakpoints) {
    bool search = false;
    if (!bps.contains(bp)) {
    }
  }

  for (const auto &bp : bps) {
    if (!mUserBreakpoints.instruction_breakpoints.contains(bp)) {
      add.push_back(bp);
    }
  }

  for (const auto &bp : add) {
    auto addr = to_addr(bp.uInstruction->mInstructionReference).value();
    bool was_not_set = true;
    if (auto symbolFile = FindObjectByPc(addr); symbolFile) {
      auto cus = symbolFile->GetCompilationUnits(addr);
      for (auto cu : cus) {
        auto [src, lte] = cu->GetLineTableEntry(symbolFile->UnrelocateAddress(addr));
        if (src && lte) {
          const auto user =
            mUserBreakpoints.create_loc_user<Breakpoint>(*this, GetOrCreateBreakpointLocation(addr, *src, *lte),
                                                         mTaskLeader, LocationUserKind::Address, bp.Clone());
          mUserBreakpoints.instruction_breakpoints[bp] = user->mId;
          was_not_set = false;
          break;
        }
      }
    }
    if (was_not_set) {
      const auto user = mUserBreakpoints.create_loc_user<Breakpoint>(
        *this, GetOrCreateBreakpointLocation(addr), mTaskLeader, LocationUserKind::Address, bp.Clone());
      mUserBreakpoints.instruction_breakpoints[bp] = user->mId;
    }
  }

  for (const auto &bp : remove) {
    auto iter = mUserBreakpoints.instruction_breakpoints.find(bp);
    ASSERT(iter != std::end(mUserBreakpoints.instruction_breakpoints), "Expected to find breakpoint");
    mUserBreakpoints.remove_bp(iter->second);
    mUserBreakpoints.instruction_breakpoints.erase(iter);
  }
}

void
TraceeController::SetFunctionBreakpoints(const Set<BreakpointSpecification> &bps) noexcept
{
  std::vector<BreakpointSpecification> remove{};
  struct SpecWasSet
  {
    BreakpointSpecification mSpec;
    size_t mSpecHash;
    bool mWasSet;
  };

  std::vector<SpecWasSet> specsToAdd;

  for (const auto &[b, id] : mUserBreakpoints.fn_breakpoints) {
    if (!bps.contains(b)) {
      remove.push_back(b);
    }
  }
  std::hash<BreakpointSpecification> specHasher{};
  for (const auto &b : bps) {
    if (!mUserBreakpoints.fn_breakpoints.contains(b)) {
      specsToAdd.push_back({b, specHasher(b), false});
    }
  }

  for (auto &sym : mSymbolFiles) {
    for (auto &fn : specsToAdd) {
      auto result = sym->LookupFunctionBreakpointBySpec(fn.mSpec);
      for (auto &&lookup : result) {
        auto user = mUserBreakpoints.create_loc_user<Breakpoint>(
          *this, GetOrCreateBreakpointLocationWithSourceLoc(lookup.address, std::move(lookup.loc_src_info)),
          mTaskLeader, LocationUserKind::Function, fn.mSpec.Clone());
        mUserBreakpoints.fn_breakpoints[fn.mSpec].push_back(user->mId);
        fn.mWasSet = true;
        mDebugAdapterClient->PostDapEvent(new ui::dap::BreakpointEvent{"new", "Breakpoint was created", user});
      }
    }
  }

  for (auto &&[spec, specHash, wasSet] : specsToAdd) {
    if (!wasSet) {
      auto spec_ptr = spec.Clone();
      auto user =
        mUserBreakpoints.create_loc_user<Breakpoint>(*this, BpErr{ResolveError{.spec = spec_ptr.get()}},
                                                     mTaskLeader, LocationUserKind::Function, std::move(spec_ptr));
    }
  }

  for (const auto &to_remove : remove) {
    auto iter = mUserBreakpoints.fn_breakpoints.find(to_remove);
    ASSERT(iter != std::end(mUserBreakpoints.fn_breakpoints), "Expected to find fn breakpoint in map");

    for (auto id : iter->second) {
      mUserBreakpoints.remove_bp(id);
    }
    mUserBreakpoints.fn_breakpoints.erase(iter);
  }
}

void
TraceeController::RemoveBreakpoint(u32 breakpointId) noexcept
{
  mUserBreakpoints.remove_bp(breakpointId);
}

bool
TraceeController::TryTerminateGracefully() noexcept
{
  DBGLOG(core, "[TraceeController]: terminate gracefully");
  if (IsRunning()) {
    StopAllTasks(nullptr);
  }

  return ::kill(mTaskLeader, SIGKILL) == 0;
}

static inline TraceEvent *
CreateTraceEventFromStopped(TraceeController &tc, TaskInfo &t) noexcept
{
  ASSERT(t.mLastWaitStatus.ws != WaitStatusKind::NotKnown,
         "When creating a trace event from a wait status event, we must already know what kind it is.");
  AddrPtr stepped_over_bp_id{nullptr};
  if (t.mBreakpointLocationStatus) {
    const auto locstat = t.clear_bpstat();
    return TraceEvent::CreateStepped({tc.TaskLeaderTid(), t.mTid, {}}, !locstat->should_resume, locstat,
                                     t.mNextResumeAction, {});
  }
  const auto pc = tc.CacheAndGetPcFor(t);
  const auto prev_pc_byte = offset(pc, -1);
  auto bp_loc = tc.GetUserBreakpoints().location_at(prev_pc_byte);
  if (bp_loc != nullptr && bp_loc->address() != stepped_over_bp_id) {
    tc.SetProgramCounterFor(t, prev_pc_byte);
    return TraceEvent::CreateSoftwareBreakpointHit(
      {.target = tc.TaskLeaderTid(), .tid = t.mTid, .sig_or_code = {}}, prev_pc_byte, {});
  }

  return TraceEvent::CreateDeferToSupervisor(
    {.target = tc.TaskLeaderTid(), .tid = t.mTid, .sig_or_code = t.mLastWaitStatus.signal}, {}, false);
}

static inline TraceEvent *
native_create_clone_event(TraceeController &tc, TaskInfo &cloning_task) noexcept
{
  DBGLOG(core, "Processing CLONE for {}", cloning_task.mTid);
  // we always have to cache these registers, because we need them to pull out some information
  // about the new clone
  tc.CacheRegistersFor(cloning_task);
  pid_t np = -1;
  // we should only ever hit this when running debugging a native-hosted session
  ASSERT(tc.GetInterface().mFormat == TargetFormat::Native, "We somehow ended up heer while debugging a remote");
  auto regs = cloning_task.native_registers();
  const auto orig_rax = regs->orig_rax;
  if (orig_rax == SYS_clone) {
    const TPtr<void> stack_ptr = sys_arg_n<2>(*regs);
    const TPtr<int> child_tid = sys_arg_n<4>(*regs);
    const u64 tls = sys_arg_n<5>(*regs);
    np = tc.ReadType(child_tid);

    ASSERT(!tc.HasTask(np), "Tracee controller already has task {} !", np);
    return TraceEvent::CreateCloneEvent({tc.TaskLeaderTid(), cloning_task.mTid, 5},
                                        TaskVMInfo{.stack_low = stack_ptr, .stack_size = 0, .tls = tls}, np, {});
  } else if (orig_rax == SYS_clone3) {
    const TraceePointer<clone_args> ptr = sys_arg<SysRegister::RDI>(*regs);
    const auto res = tc.ReadType(ptr);
    np = tc.ReadType(TPtr<pid_t>{res.parent_tid});
    return TraceEvent::CreateCloneEvent({tc.TaskLeaderTid(), cloning_task.mTid, 5},
                                        TaskVMInfo::from_clone_args(res), np, {});
  } else {
    PANIC("Unknown clone syscall!");
  }
}

TraceEvent *
TraceeController::CreateTraceEventFromWaitStatus(TaskInfo &info) noexcept
{
  info.set_dirty();
  info.mHasProcessedStop = true;
  const auto ws = info.pending_wait_status();

  switch (ws.ws) {
  case WaitStatusKind::Stopped: {
    if (!info.initialized) {
      return TraceEvent::CreateThreadCreated({mTaskLeader, info.mTid, 5},
                                             {tc::RunType::Continue, tc::ResumeTarget::Task}, {});
    }
    return CreateTraceEventFromStopped(*this, info);
  }
  case WaitStatusKind::Execed: {
    return TraceEvent::CreateExecEvent({.target = mTaskLeader, .tid = info.mTid, .sig_or_code = 5},
                                       ProcessExecPath(info.mTid), {});
  }
  case WaitStatusKind::Exited: {
    return TraceEvent::CreateThreadExited({mTaskLeader, info.mTid, ws.exit_code}, false, {});
  }
  case WaitStatusKind::Forked: {
    Tid new_child = 0;
    auto result = ptrace(PTRACE_GETEVENTMSG, info.mTid, nullptr, &new_child);
    ASSERT(result != -1, "Failed to get new pid for forked child; {}", strerror(errno));
    DBGLOG(core, "[{} forked]: new process after fork {}", info.mTid, new_child);
    return TraceEvent::CreateForkEvent_({mTaskLeader, info.mTid, 5}, new_child, {});
  }
  case WaitStatusKind::VForked: {
    Tid new_child = 0;
    auto result = ptrace(PTRACE_GETEVENTMSG, info.mTid, nullptr, &new_child);
    ASSERT(result != -1, "Failed to get new pid for forked child; {}", strerror(errno));
    DBGLOG(core, "[vfork]: new process after fork {}", new_child);
    return TraceEvent::CreateVForkEvent_({mTaskLeader, info.mTid, 5}, new_child, {});
  }
  case WaitStatusKind::VForkDone:
    TODO("WaitStatusKind::VForkDone");
    break;
  case WaitStatusKind::Cloned: {
    return native_create_clone_event(*this, info);
  } break;
  case WaitStatusKind::Signalled:
    return TraceEvent::CreateSignal({mTaskLeader, info.mTid, info.mLastWaitStatus.signal}, {});
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
  ASSERT(false, "Unknown wait status!");
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
    DBGLOG(core, "Thread {} stopped={}", entry.mTid, entry.mTask->is_stopped());
    return entry.mTask->is_stopped();
  });
}

bool
TraceeController::IsRunning() const noexcept
{
  return std::any_of(mThreads.cbegin(), mThreads.cend(), [](const auto &entry) {
    DBGLOG(core, "Thread {} stopped={}", entry.mTid, entry.mTask->is_stopped());
    return !entry.mTask->is_stopped();
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
    DBGLOG(core, "[{}:symbol file]: Already added {} at {} .. {}; new is at {}..{} - Same range?: {}", mTaskLeader,
           symbolFile->GetObjectFilePath().c_str(), (*it)->LowProgramCounter(), (*it)->HighProgramCounter(),
           symbolFile->LowProgramCounter(), symbolFile->HighProgramCounter(), same_bounds)
    return;
  }
  mSymbolFiles.emplace_back(symbolFile);

  if (isMainExecutable) {
    mMainExecutable = mSymbolFiles.back();
  }

  // todo(simon): optimization possible; insert in a sorted fashion instead.
  std::sort(mSymbolFiles.begin(), mSymbolFiles.end(), [&symbolFile](auto &&a, auto &&b) {
    ASSERT(a->LowProgramCounter() != b->LowProgramCounter(),
           "[{}]: Added object files with identical address ranges. We screwed something up, for sure\na={}\nb={}",
           symbolFile->GetObjectFilePath().c_str(), a->GetObjectFilePath().c_str(),
           b->GetObjectFilePath().c_str());
    return a->LowProgramCounter() < b->LowProgramCounter() && a->HighProgramCounter() < b->HighProgramCounter();
  });
  mNewObjectFilePublisher.Emit(symbolFile.get());
}

// Debug Symbols Related Logic
void
TraceeController::RegisterObjectFile(TraceeController *tc, std::shared_ptr<ObjectFile> &&obj,
                                     bool isMainExecutable, AddrPtr relocatedBase) noexcept
{
  ASSERT(obj != nullptr, "Object file is null");
  RegisterSymbolFile(SymbolFile::Create(tc, std::move(obj), relocatedBase), isMainExecutable);
}

struct AuxvPair
{
  u64 key, value;
};

void
TraceeController::ParseAuxiliaryVectorInfo(tc::Auxv &&aux) noexcept
{
  mAuxiliaryVector = std::move(aux);

  for (const auto [id, value] : mAuxiliaryVector.vector) {
    if (id == AT_BASE) {
      DBGLOG(core, "interpreter base found: 0x{:x}", value);
      mInterpreterBase = value;
    }
    if (id == AT_ENTRY) {
      DBGLOG(core, "Entry found: 0x{:x}", value);
      mEntry = value;
    }
  }
}

void
TraceeController::ReadAuxiliaryVector(TaskInfo &task)
{
  ASSERT(task.mLastWaitStatus.ws == WaitStatusKind::Execed,
         "Reading AUXV using this function does not make sense if's not *right* after an EXEC");
  CacheRegistersFor(task);
  TPtr<i64> stack_ptr = task.regs.registers->rsp;
  i64 argc = ReadType(stack_ptr);

  stack_ptr += argc + 1;
  ASSERT(ReadType(stack_ptr) == 0, "Expected null terminator after argv at {}", stack_ptr);
  stack_ptr++;
  auto envp = stack_ptr.as<const char *>();
  // we're at the envp now, that pointer list is also terminated by a nullptr
  while (ReadType(envp) != nullptr) {
    envp++;
  }
  // We should now be at Auxilliary Vector Table (see `man getauxval` for info, we're interested in the
  // interpreter base address)

  envp++;
  // cast it to our own type
  auto aux_ptr = envp.as<AuxvPair>();
  std::vector<AuxvPair> auxv{};
  for (;;) {
    auto kvp = ReadType(aux_ptr);
    auxv.push_back(kvp);
    // terminated by a "null entry"
    if (kvp.key == 0) {
      break;
    }
    aux_ptr++;
  }

  for (const auto &kvp : auxv) {
    if (kvp.key == AT_BASE) {
      mInterpreterBase = kvp.value;
    }
    if (kvp.key == AT_ENTRY) {
      mEntry = kvp.value;
    }
  }

  ASSERT(mEntry.has_value() && mInterpreterBase.has_value(), "Expected ENTRY and INTERPRETER_BASE to be found");
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

  auto total_read = 0ull;
  while (total_read < bytes) {
    auto res = mTraceeInterface->ReadBytes(addr, bytes - total_read, buffer->next());
    if (!res.success()) {
      return mdb::unexpected(NonFullRead{std::move(buffer), static_cast<u32>(bytes - total_read), errno});
    }
    buffer->wrote_bytes(res.bytes_read);
    total_read += res.bytes_read;
  }
  return mdb::Expected<std::unique_ptr<mdb::ByteBuffer>, NonFullRead>{std::move(buffer)};
}

mdb::Expected<std::unique_ptr<mdb::ByteBuffer>, NonFullRead>
TraceeController::SafeRead(std::pmr::memory_resource *allocator, AddrPtr addr, u64 bytes) noexcept
{
  auto buffer = mdb::ByteBuffer::create(allocator, bytes);

  auto total_read = 0ull;
  while (total_read < bytes) {
    auto res = mTraceeInterface->ReadBytes(addr, bytes - total_read, buffer->next());
    if (!res.success()) {
      return mdb::unexpected(NonFullRead{std::move(buffer), static_cast<u32>(bytes - total_read), errno});
    }
    buffer->wrote_bytes(res.bytes_read);
    total_read += res.bytes_read;
  }
  return mdb::Expected<std::unique_ptr<mdb::ByteBuffer>, NonFullRead>{std::move(buffer)};
}

mdb::StaticVector<u8>::OwnPtr
TraceeController::ReadToVector(AddrPtr addr, u64 bytes) noexcept
{
  auto data = std::make_unique<mdb::StaticVector<u8>>(bytes);

  auto total_read = 0ull;
  while (total_read < bytes) {
    const auto read_address = addr + total_read;
    const auto result =
      mTraceeInterface->ReadBytes(read_address, bytes - total_read, data->data_ptr() + total_read);
    if (!result.success()) {
      PANIC(fmt::format("Failed to proc_fs read from {}", addr));
    }
    total_read += result.bytes_read;
  }
  data->set_size(total_read);
  return data;
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
    return sym::Frame{nullptr, task, 0, 0, pc, nullptr};
  }
  auto cus_matching_addr = obj->GetUnitDataFromProgramCounter(pc);

  for (auto src : cus_matching_addr) {
    if (auto fn = src->GetFunctionSymbolByProgramCounter(obj->UnrelocateAddress(pc)); fn) {
      return sym::Frame{obj, task, 0, 0, pc, fn};
    }
  }

  if (auto min_sym = obj->SearchMinimalSymbolFunctionInfo(pc); min_sym != nullptr) {
    return sym::Frame{obj, task, 0, 0, pc, min_sym};
  } else {
    return sym::Frame{obj, task, 0, 0, pc, nullptr};
  }
}

sym::UnwinderSymbolFilePair
TraceeController::GetUnwinderUsingPc(AddrPtr pc) noexcept
{
  for (auto &symbol_file : mSymbolFiles) {
    const auto u = symbol_file->GetObjectFile()->GetUnwinder();
    const auto addr_range = u->mAddressRange;
    if (pc > symbol_file->mBaseAddress) {
      const auto unrelocated = symbol_file->UnrelocateAddress(pc);
      if (addr_range.Contains(unrelocated)) {
        return sym::UnwinderSymbolFilePair{u, symbol_file.get()};
      }
    }
  }
  return sym::UnwinderSymbolFilePair{mNullUnwinder, nullptr};
}

void
TraceeController::CacheRegistersFor(TaskInfo &t) noexcept
{
  if (t.mRegisterCacheDirty) {
    const auto result = mTraceeInterface->ReadRegisters(t);
    ASSERT(result.is_ok(), "Failed to read register file for {}; {}", t.mTid, strerror(result.sys_errno));
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
TraceeController::ExitAll(TaskInfo::SupervisorState state) noexcept
{
  while (!mThreads.empty()) {
    TaskExit(*mThreads[0].mTask, state, false);
  }
}

void
TraceeController::TaskExit(TaskInfo &task, TaskInfo::SupervisorState state, bool notify) noexcept
{
  Tid tid = task.mTid;
  auto it = FindByTid(mThreads, tid);
  ASSERT(it != std::end(mThreads), "{} couldn't be found in this process {}", tid, mTaskLeader);

  task.exited = true;
  task.SetTracerState(state);

  mExitedThreads.push_back(std::move(*it));
  mThreads.erase(it);

  if (notify) {
    mDebugAdapterClient->PostDapEvent(new ui::dap::ThreadEvent{ui::dap::ThreadReason::Exited, tid});
  }
}

sym::CallStack &
TraceeController::BuildCallFrameStack(TaskInfo &task, CallStackRequest req) noexcept
{
  DBGLOG(core, "stacktrace for {}", task.mTid);
  if (!task.mTaskCallstack->IsDirty()) {
    return *task.mTaskCallstack;
  }
  CacheRegistersFor(task);
  auto &cs_ref = *task.mTaskCallstack;

  auto frame_pcs = task.return_addresses(this, req);
  for (const auto &[depth, i] : mdb::EnumerateView{frame_pcs}) {
    auto frame_pc = i.as_void();
    auto result = FindFunctionByPc(frame_pc);
    if (!result) {
      DBGLOG(core, "No object file related to pc; abort call frame state building.");
      break;
    }
    auto &[symbol, obj] = result.value();
    const auto id = Tracer::Get().NewVariablesReference();
    Tracer::Get().SetVariableContext(VariableContext{.tc = this,
                                                     .t = &task,
                                                     .symbol_file = obj,
                                                     .frame_id = id,
                                                     .id = static_cast<u16>(id),
                                                     .type = ContextType::Frame});
    if (symbol) {
      cs_ref.PushFrame(obj, task, depth, id, i.as_void(), symbol);
    } else {
      auto obj = FindObjectByPc(frame_pc);
      auto min_sym = obj->SearchMinimalSymbolFunctionInfo(frame_pc);
      if (min_sym) {
        cs_ref.PushFrame(obj, task, depth, id, i.as_void(), min_sym);
      } else {
        DBGLOG(core, "[stackframe]: WARNING, no frame info for pc {}", i.as_void());
        cs_ref.PushFrame(obj, task, depth, id, i.as_void(), nullptr);
      }
    }
  }
  return cs_ref;
}

SymbolFile *
TraceeController::FindObjectByPc(AddrPtr addr) noexcept
{
  return mdb::find_if(mSymbolFiles,
                      [addr](auto &symbol_file) { return symbol_file->ContainsProgramCounter(addr); })
    .transform([](auto iterator) { return iterator->get(); })
    .value_or(nullptr);
}

std::optional<std::pair<sym::FunctionSymbol *, NonNullPtr<SymbolFile>>>
TraceeController::FindFunctionByPc(AddrPtr addr) noexcept
{
  const auto symbolFile = FindObjectByPc(addr);
  if (symbolFile == nullptr) {
    return std::nullopt;
  }

  auto cus_matching_addr = symbolFile->GetUnitDataFromProgramCounter(addr);

  // TODO(simon): Massive room for optimization here. Make get_cus_from_pc return source units directly
  //  or, just make them searchable by cu (via some hashed lookup in a map or something.)
  DBGLOG(perf, "Start fn symbol resolving in {} compilation units in {} for unreloc addr: {}",
         cus_matching_addr.size(), symbolFile->GetObjectFilePath().filename().c_str(),
         symbolFile->UnrelocateAddress(addr));
  const auto start = std::chrono::high_resolution_clock::now();
  sym::FunctionSymbol *foundFn = nullptr;
  ScopedDefer defer{[start, symbolFile = symbolFile, &foundFn, addr]() {
    auto us =
      std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start)
        .count();
    DBGLOG(perf, "Parsed symbols & found function symbol {} in {} us ({}), unreloc addr={}",
           foundFn ? foundFn->name : "<no known name>", us, symbolFile->GetObjectFilePath().filename().c_str(),
           symbolFile->UnrelocateAddress(addr));
  }};

  using sym::CompilationUnit;

  std::vector<sym::CompilationUnit *> alreadyParse;
  std::vector<sym::CompilationUnit *> sortedCompUnits;

  alreadyParse.reserve(cus_matching_addr.size());
  sortedCompUnits.reserve(cus_matching_addr.size());
  u64 totalSize = 0;
  for (auto src : cus_matching_addr) {
    if (src->IsFunctionSymbolsResolved()) {
      if (auto fn = src->GetFunctionSymbolByProgramCounter(symbolFile->UnrelocateAddress(addr)); fn) {
        foundFn = fn;
        return std::make_pair(fn, NonNull(*symbolFile));
      }
    } else {
      totalSize += src->get_dwarf_unit()->UnitSize();
      sortedCompUnits.push_back(src);
    }
  }

  std::sort(sortedCompUnits.begin(), sortedCompUnits.end(), [](CompilationUnit *a, CompilationUnit *b) {
    return a->get_dwarf_unit()->UnitSize() > b->get_dwarf_unit()->UnitSize();
  });

  for (const auto cu : sortedCompUnits) {
    if (auto fn = cu->GetFunctionSymbolByProgramCounter(symbolFile->UnrelocateAddress(addr)); fn) {
      foundFn = fn;
      return std::make_pair(fn, NonNull(*symbolFile));
    }
  }

  return std::make_pair(nullptr, NonNull(*symbolFile));
}

mdb::Expected<u8, BpErr>
TraceeController::InstallSoftwareBreakpointLocation(Tid tid, AddrPtr addr) noexcept
{
  const auto res = mTraceeInterface->InstallBreakpoint(tid, addr);
  if (!res.is_ok()) {
    DBGLOG(core, "[{}:bkpt:loc]: error while installing location: {}", mTaskLeader, addr);
    return mdb::unexpected(BpErr{MemoryError{errno, addr}});
  }
  DBGLOG(core, "[{}:bkpt:loc]: installing location: {}, original byte: 0x{:x}", mTaskLeader, addr,
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
    if (!entry.mTask->stop_processed()) {
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
    return !static_cast<tc::GdbRemoteCommander *>(mTraceeInterface.get())->remote_settings().is_non_stop;
  }
  NEVER("Unknown target interface type");
}

TaskInfo *
TraceeController::SetPendingWaitstatus(TaskWaitResult wait_result) noexcept
{
  const auto tid = wait_result.tid;
  auto task = GetTaskByTid(tid);
  ASSERT(task != nullptr, "couldn't find task {}", tid);
  task->mLastWaitStatus = wait_result.ws;
  task->mTracerVisibleStop = true;
  task->mHasProcessedStop = false;
  return task;
}

tc::ProcessedStopEvent
TraceeController::HandleTerminatedBySignal(const Signal &evt) noexcept
{
  // TODO: Allow signals through / stop process / etc. Allow for configurability here.
  mDebugAdapterClient->PostDapEvent(new ui::dap::ExitedEvent{evt.mTerminatingSignal});
  ShutDownDebugAdapterClient();
  mIsExited = true;
  return tc::ProcessedStopEvent{false, {}};
}

tc::ProcessedStopEvent
TraceeController::HandleStepped(TaskInfo *task, const Stepped &event) noexcept
{
  if (event.loc_stat) {
    ASSERT(event.loc_stat->stepped_over, "how did we end up here if we did not step over a breakpoint?");
    auto bp_loc = GetUserBreakpoints().location_at(event.loc_stat->loc);
    if (event.loc_stat->re_enable_bp) {
      bp_loc->enable(task->mTid, GetInterface());
    }
  }

  if (event.stop) {
    task->mUserVisibleStop = true;
    EmitSteppedStop({.pid = mTaskLeader, .tid = task->mTid});
    return tc::ProcessedStopEvent{false, {}};
  } else {
    const auto resume =
      event.loc_stat.transform([](const auto &loc) { return loc.should_resume; }).value_or(false);
    return tc::ProcessedStopEvent{resume, event.resume_when_done};
  }
}

tc::ProcessedStopEvent
TraceeController::HandleEntry(TaskInfo *task, const EntryEvent &event) noexcept
{
  SetIsOnEntry(false);
  // apply session breakpoints to new process space
  if (event.should_stop) {
    // emit stop event
    EmitStopped(event.thread_id, ui::dap::StoppedReason::Entry, "forked", true, {});
  } else {
    // say "thread created / started"
  }
  return tc::ProcessedStopEvent{!event.should_stop, {}};
}

tc::ProcessedStopEvent
TraceeController::HandleThreadCreated(TaskInfo *task, const ThreadCreated &e,
                                      const RegisterData &register_data) noexcept
{
  // means this event was produced by a Remote session. Construct the task now
  if (!task) {
    CreateNewTask(e.thread_id, true);
    task = GetTaskByTid(e.thread_id);
    if (!register_data.empty()) {
      ASSERT(*GetInterface().mArchInfo != nullptr,
             "Passing raw register contents with no architecture description doesn't work.");
      task->StoreToRegisterCache(register_data);
      for (const auto &p : register_data) {
        if (p.first == 16) {
          task->mInstructionPointerDirty = false;
        }
      }
    }
  }

  const auto evt = new ui::dap::ThreadEvent{ui::dap::ThreadReason::Started, e.thread_id};
  mDebugAdapterClient->PostDapEvent(evt);

  return tc::ProcessedStopEvent{true, e.resume_action};
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
  // todo(simon): here we should start building upon global event system, like in gdb, where the user can
  // hook into specific events. in this particular case, we could emit a
  // BreakpointEvent{user_ids_that_were_hit} and let the user look up the bps, and use them instead of
  // passing the data along; that way we get to make it asynchronous - because user code or core code
  // might want to delete the breakpoint _before_ a user wants to use it. Adding this lookup by key
  // feature makes that possible, it also makes the implementation and reasoning about life times
  // *SUBSTANTIALLY* easier.
  auto t = GetTaskByTid(event.thread_id);

  auto bp_addy = event.address_val
                   ->or_else([&]() {
                     // Remember: A breakpoint (0xcc) is 1 byte. We need to rewind that 1 byte.
                     return std::optional{CacheAndGetPcFor(*t).get()};
                   })
                   .value();

  auto bp_loc = GetUserBreakpoints().location_at(bp_addy);
  ASSERT(bp_loc != nullptr, "Expected breakpoint location at 0x{:x}", bp_addy);
  const auto users = bp_loc->loc_users();
  ASSERT(!bp_loc->loc_users().empty(),
         "[task={}]: A breakpoint location with no user is a rogue/leaked breakpoint at 0x{:x}", t->mTid, bp_addy);

  bool should_resume = true;
  u32 aliveBreakpoints = users.size();
  for (const auto user_id : users) {
    auto user = GetUserBreakpoints().GetUserBreakpoint(user_id);
    auto breakpointResult = user->OnHit(*this, *t);
    should_resume = should_resume && !breakpointResult.ShouldStop();
    if (breakpointResult.ShouldRetire()) {
      --aliveBreakpoints;
      GetUserBreakpoints().remove_bp(user->mId);
    }
  }
  // If all breakpoints at @ has retired, don't add a breakpoint location status, because the next operation we can
  // simply resume however we like from, there's no breakpoint to disable-then-enable.
  if (aliveBreakpoints > 0) {
    t->AddBreakpointLocationStatus(bp_addy);
  }
  return tc::ProcessedStopEvent{should_resume, {}};
}

tc::ProcessedStopEvent
TraceeController::HandleThreadExited(TaskInfo *task, const ThreadExited &evt) noexcept
{
  if (OneRemainingTask()) {
    TaskExit(*task, TaskInfo::SupervisorState::Exited, true);
    return HandleProcessExit(ProcessExited{.pid = mTaskLeader, .exit_code = evt.code_or_signal});
  }

  TaskExit(*task, TaskInfo::SupervisorState::Exited, true);
  return tc::ProcessedStopEvent{false, {}, false, true};
}

static void
ScheduleInvalidateThis(TraceeController *t)
{
  EventSystem::Get().PushInternalEvent(InvalidateSupervisor{t});
}

tc::ProcessedStopEvent
TraceeController::HandleProcessExit(const ProcessExited &evt) noexcept
{
  auto t = GetTaskByTid(evt.thread_id);
  if (t && !t->exited) {
    mDebugAdapterClient->PostDapEvent(new ui::dap::ThreadEvent{ui::dap::ThreadReason::Exited, t->mTid});
    t->exited = true;
    t->reaped = true;
  }

  ScheduleInvalidateThis(this);
  mDebugAdapterClient->PostDapEvent(new ui::dap::ExitedEvent{evt.exit_code});
  return tc::ProcessedStopEvent::ProcessExited();
}

void
TraceeController::PostExec(const std::string &exe) noexcept
{
  DBGLOG(core, "Processing EXEC for {} - process was vforked: {}", mTaskLeader, mIsVForking);
  if (mMainExecutable) {
    mMainExecutable = nullptr;
  }
  mSymbolFiles.clear();

  auto t = GetTaskByTid(TaskLeaderTid());
  CacheRegistersFor(*t);
  mUserBreakpoints.on_exec();

  if (mTraceeInterface->mType == tc::TraceeInterfaceType::Ptrace) {
    mTraceeInterface->OnExec();
  }

  auto auxv_result = mTraceeInterface->ReadAuxiliaryVector().expected("Failed to read auxv");
  const auto parsedAux = ParsedAuxiliaryVectorData(auxv_result);
  mAuxiliaryVector = std::move(auxv_result);
  mInterpreterBase = parsedAux.mInterpreterBaseAddress;
  mEntry = parsedAux.mEntry;

  std::vector<u8> programHeaderContents{};
  programHeaderContents.resize(parsedAux.mProgramHeaderEntrySize * parsedAux.mProgramHeaderCount, 0);
  const auto readResult = mTraceeInterface->ReadBytes(parsedAux.mProgramHeaderPointer,
                                                      programHeaderContents.size(), programHeaderContents.data());
  ASSERT(readResult.success(), "Failed to read program headers");

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
  DoBreakpointsUpdate({mMainExecutable});
  mOnExecOrExitPublisher.Emit();
}

void
TraceeController::DefaultHandler(TraceEvent *evt) noexcept
{
  // todo(simon): open up for design that involves user-subscribed event handlers (once we get scripting up and
  // running) It is in this event handling, where we can (at the very end of each handler) emit additional "user
  // facing events", that we also can collect values from (perhaps the user wants to stop for a reason, as such
  // their subscribed event handlers will return `false`).
  using tc::ProcessedStopEvent;
  using MatchResult = ProcessedStopEvent;

  ASSERT(!mIsExited, "Supervisor exited already.");

  const auto arch = GetInterface().mArchInfo;
  auto task = GetTaskByTid(evt->tid);
  // we _have_ to do this check here, because the event *might* be a ThreadCreated event
  // and *it* happens *slightly* different depending on if it's a Remote or a Native session that sends it.
  // Unfortunately.
  if (!task && !mIsExited) {
    // rr ends up here.
    DBGLOG(core, "task {} created in stop handler because target doesn't support thread events", evt->tid);
    CreateNewTask(evt->tid, false);
    task = GetTaskByTid(evt->tid);
  }
  if (task) {
    task->mLastWaitStatus.signal = evt->signal;
    if (!evt->registers->empty()) {
      ASSERT(*arch != nullptr, "Passing raw register contents with no architecture description doesn't work.");
      task->StoreToRegisterCache(evt->registers);
      for (const auto &p : evt->registers) {
        if (p.first == 16) {
          task->mInstructionPointerDirty = false;
        }
      }
    }
    task->collect_stop();
  }
  if (IsSessionAllStopMode()) {
    for (const auto &entry : GetThreads()) {
      entry.mTask->set_stop();
      entry.mTask->mHasProcessedStop = true;
    }
  }
  const TraceEvent &r = *evt;

  auto processedStop = std::visit(
    Match{
      [&](const WatchpointEvent &e) -> MatchResult {
        (void)e;
        TODO("WatchpointEvent");
        return ProcessedStopEvent::ResumeAny();
      },
      [&](const SyscallEvent &e) -> MatchResult {
        (void)e;
        TODO("SyscallEvent");
        return ProcessedStopEvent::ResumeAny();
      },
      [&](const ThreadCreated &e) -> MatchResult { return HandleThreadCreated(task, e, evt->registers); },
      [&](const ThreadExited &e) -> MatchResult { return HandleThreadExited(task, e); },
      [&](const BreakpointHitEvent &e) -> MatchResult { return HandleBreakpointHit(task, e); },
      [&](const ForkEvent &e) -> MatchResult { return HandleFork(e); },
      [&](const Clone &e) -> MatchResult { return HandleClone(e); },
      [&](const Exec &e) -> MatchResult { return HandleExec(e); },
      [&](const ProcessExited &e) -> MatchResult { return HandleProcessExit(e); },
      [&](const LibraryEvent &e) -> MatchResult {
        (void)e;
        TODO("LibraryEvent");
        return ProcessedStopEvent{true, {}};
      },
      [&](const Signal &e) -> MatchResult { return HandleTerminatedBySignal(e); },
      [&](const Stepped &e) -> MatchResult { return HandleStepped(task, e); },
      [&](const EntryEvent &e) noexcept -> MatchResult { return HandleEntry(task, e); },
      [&](const DeferToSupervisor &e) -> MatchResult {
        // And if there is no Proceed action installed, default action is taken (RESUME)
        return ProcessedStopEvent{true && !e.attached, {}};
      },
    },
    *evt->event);

  // Now that event has been properly handled, we can check for "global" (process-local) handlers
  // for instance, if we've requested all tasks to stop, or if we've requested a shut down, we will treat all
  // proceeds the same. effectively ignoring the default proceed behaviors from an event.

  DBGLOG(core, "[{}.{}]: handle {}, resume:{}", mTaskLeader, task->mTid, evt->event_type,
         processedStop.should_resume);

  mScheduler->Schedule(*task, processedStop);
}

void
TraceeController::ResumeEventHandling() noexcept
{
  mAction = SupervisorEventHandlerAction::Default;
  EventSystem::Get().ConsumeDebuggerEvents(mDeferredEvents);
}

void
TraceeController::SetDeferEventHandler() noexcept
{
  mAction = SupervisorEventHandlerAction::Defer;
}

void
TraceeController::HandleTracerEvent(TraceEvent *evt) noexcept
{
  switch (mAction) {
  case SupervisorEventHandlerAction::Default:
    DefaultHandler(evt);
    delete evt;
    break;
  case SupervisorEventHandlerAction::Defer:
    // vfork parents should not resume until child unblocks it.
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

tc::ProcessedStopEvent
TraceeController::HandleFork(const ForkEvent &evt) noexcept
{
  auto interface = mTraceeInterface->OnFork(evt.child_pid);
  auto new_supervisor = Tracer::Get().AddNewSupervisor(Fork(std::move(interface), evt.mIsVFork));
  auto client = ui::dap::DebugAdapterClient::CreateSocketConnection(*mDebugAdapterClient);
  client->ClientConfigured(new_supervisor);

  if (!evt.mIsVFork) {
    DBGLOG(core, "event was not vfork; disabling breakpoints in new address space.");
    // the new process space copies the old one; which contains breakpoints.
    // we restore the newly forked process space to the real contents. New breakpoints will be set
    // by the initialize -> configDone sequence
    auto &supervisor = new_supervisor->GetInterface();
    for (auto &user : mUserBreakpoints.all_users()) {
      if (auto loc = user->GetLocation(); loc) {
        supervisor.DisableBreakpoint(evt.child_pid, *loc);
      }
    }
  } else {
    SetDeferEventHandler();
    new_supervisor->mIsVForking = true;
    new_supervisor->mOnExecOrExitPublisher.Once(
      [parent = this, self = new_supervisor, resumeTid = evt.thread_id]() {
        parent->ResumeEventHandling();
        self->mIsVForking = false;
        self->mConfigurationIsDone = true;
        EventSystem::Get().PushDebuggerEvent(
          TraceEvent::CreateDeferToSupervisor({.target = parent->TaskLeaderTid(), .tid = resumeTid}, {}, {}));
      });
  }

  return tc::ProcessedStopEvent{.should_resume = !evt.mIsVFork, .res = {}, .mVForked = evt.mIsVFork};
}

tc::ProcessedStopEvent
TraceeController::HandleClone(const Clone &evt) noexcept
{
  auto task = Tracer::Get().TakeUninitializedTask(evt.child_tid);
  DBGLOG(core, "Running clone handler for {}: child created = {}. Already created: {}", evt.thread_id,
         evt.child_tid, task != nullptr);
  if (!task) {
    CreateNewTask(evt.child_tid, true);
    if (evt.vm_info) {
      SetTaskVmInfo(evt.child_tid, evt.vm_info.value());
    }
  } else {
    task->InitializeThread(GetInterface(), true);
    AddTask(std::move(task));
  }
  mDebugAdapterClient->PostDapEvent(new ui::dap::ThreadEvent{evt});
  return tc::ProcessedStopEvent{true, {}};
}

tc::ProcessedStopEvent
TraceeController::HandleExec(const Exec &evt) noexcept
{
  // configurationDone will resume us if we're vforking
  const bool resumeFromExec = !mIsVForking;
  PostExec(evt.exec_file);
  mDebugAdapterClient->PostDapEvent(new ui::dap::Process{evt.exec_file, true});
  return tc::ProcessedStopEvent{resumeFromExec, {}};
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
    mDebugAdapterClient->PostDapEvent(new ui::dap::TerminatedEvent{});
    mDebugAdapterClient->ShutDown();
    mDebugAdapterClient = nullptr;
  }
}
} // namespace mdb